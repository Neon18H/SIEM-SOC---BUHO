import io
import tarfile
import zipfile
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.http import FileResponse, HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from soc.auth import user_org
from soc.models import EnrollmentToken

from .forms import AgentReleaseForm
from .models import AgentRelease, DownloadAudit

SUPPORTED_PLATFORMS = {
    AgentRelease.PLATFORM_LINUX: {'title': 'Linux (x86_64)', 'installer_name': 'install.sh'},
    AgentRelease.PLATFORM_WINDOWS: {'title': 'Windows (x64)', 'installer_name': 'install.ps1'},
}


def _is_admin(user):
    profile = getattr(user, 'userprofile', None)
    return bool(user.is_superuser or (profile and profile.role == 'admin'))


def get_client_ip(request):
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def is_rate_limited(request, platform, action, max_requests=15, window_seconds=60):
    cache_key = f'agent_dl:{request.user.id}:{platform}:{action}'
    current = cache.get(cache_key, 0)
    if current >= max_requests:
        return True
    if current == 0:
        cache.set(cache_key, 1, timeout=window_seconds)
    else:
        cache.incr(cache_key)
    return False


def get_active_release(platform):
    return AgentRelease.objects.filter(platform=platform, is_active=True).first()


def _linux_install_script():
    return """#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/agent-nocturno"
CONF_DIR="/etc/agent-nocturno"
SECRET_FILE="${CONF_DIR}/agent-secret.json"

sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin agentnocturno 2>/dev/null || true
sudo mkdir -p "${INSTALL_DIR}" "${CONF_DIR}"
sudo cp "${BASE_DIR}/config.yml" "${CONF_DIR}/config.yml"

if [ -f "${BASE_DIR}/secret.json" ]; then
  sudo cp "${BASE_DIR}/secret.json" "${SECRET_FILE}"
fi

sudo rsync -a --delete "${BASE_DIR}/agent/" "${INSTALL_DIR}/"
sudo python3 -m venv "${INSTALL_DIR}/venv"
sudo "${INSTALL_DIR}/venv/bin/pip" install --upgrade pip
sudo "${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"

sudo tee /etc/systemd/system/agent-nocturno.service >/dev/null <<'UNIT'
[Unit]
Description=Agent Nocturno
After=network-online.target

[Service]
Type=simple
User=agentnocturno
Group=agentnocturno
WorkingDirectory=/opt/agent-nocturno
ExecStart=/opt/agent-nocturno/venv/bin/python /opt/agent-nocturno/main.py --config /etc/agent-nocturno/config.yml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

sudo chown -R agentnocturno:agentnocturno "${INSTALL_DIR}" "${CONF_DIR}"
sudo chmod 600 "${CONF_DIR}/config.yml" || true
sudo chmod 600 "${SECRET_FILE}" || true
sudo systemctl daemon-reload
sudo systemctl enable --now agent-nocturno
sudo systemctl --no-pager --full status agent-nocturno
"""


def _windows_install_script():
    return r"""$ErrorActionPreference = 'Stop'
$BaseDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallDir = 'C:\ProgramData\AgentNocturno'
$AgentDir = Join-Path $InstallDir 'agent'
$ConfigFile = Join-Path $InstallDir 'config.yml'

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $AgentDir -Force | Out-Null
Copy-Item (Join-Path $BaseDir 'config.yml') $ConfigFile -Force
if (Test-Path (Join-Path $BaseDir 'secret.json')) {
  Copy-Item (Join-Path $BaseDir 'secret.json') (Join-Path $InstallDir 'secret.json') -Force
}
Copy-Item (Join-Path $BaseDir 'agent\*') $AgentDir -Recurse -Force

py -3 -m venv (Join-Path $InstallDir 'venv')
& (Join-Path $InstallDir 'venv\Scripts\pip.exe') install --upgrade pip
& (Join-Path $InstallDir 'venv\Scripts\pip.exe') install -r (Join-Path $AgentDir 'requirements.txt')

$nssm = Join-Path $BaseDir 'nssm.exe'
if (!(Test-Path $nssm)) {
  throw 'nssm.exe no encontrado dentro del bundle.'
}

$pythonExe = Join-Path $InstallDir 'venv\Scripts\python.exe'
$appArgs = "`"$AgentDir\main.py`" --config `"$ConfigFile`""
& $nssm install agent-nocturno $pythonExe $appArgs
& $nssm set agent-nocturno AppDirectory $AgentDir
& $nssm start agent-nocturno
Get-Service agent-nocturno
"""


def _readme(platform, org, enrollment):
    installer = SUPPORTED_PLATFORMS[platform]['installer_name']
    return (
        'Agente Nocturno - Quickstart\n'
        '============================\n\n'
        f'Organización: {org.name}\n'
        f'Token expira: {enrollment.expires_at.isoformat()}\n\n'
        f'1. Descomprime el paquete.\n2. Ejecuta {installer} como administrador/root.\n'
        '3. Verifica servicio agent-nocturno.\n4. El agente comenzará a enviar telemetría a /api/ingest/.\n'
    )


def _config_payload(request, enrollment):
    soc_url = getattr(settings, 'AGENT_SOC_URL', '').strip() or f"{request.scheme}://{request.get_host()}"
    return (
        f'soc_url: {soc_url}\n'
        f'enrollment_token: {enrollment.token}\n'
        'interval: 60\n'
        'collectors:\n'
        '  - system_info\n'
        '  - auth_logs\n'
        '  - windows_eventlog\n'
        '  - docker\n'
        '  - cloud_metadata\n'
        'verify_tls: true\n'
    )


def _agent_source_files():
    base = Path(settings.BASE_DIR) / 'agent_mvp'
    paths = [
        'main.py', 'enroll.py', 'sender.py', 'collectors.py', 'cursor_store.py', 'requirements.txt', 'README.md', 'nssm.exe'
    ]
    output = []
    for rel in paths:
        file_path = base / rel
        if file_path.exists():
            output.append((f'agent/{rel}', file_path.read_bytes()))
    return output


@login_required
def downloads_page(request):
    cards = []
    for platform, metadata in SUPPORTED_PLATFORMS.items():
        cards.append({'platform': platform, 'title': metadata['title'], 'release': get_active_release(platform)})
    return render(request, 'agent_downloads/downloads.html', {'cards': cards})


@login_required
def download_installer(request, platform):
    if platform not in SUPPORTED_PLATFORMS:
        return HttpResponse(status=404)
    if is_rate_limited(request, platform, 'installer'):
        return HttpResponse('Demasiadas descargas, intenta nuevamente en un minuto.', status=429)

    release = get_active_release(platform)
    if not release:
        return HttpResponse('No existe release activo para esta plataforma. Publique uno desde /agents/releases/.', status=404)

    DownloadAudit.objects.create(
        user=request.user,
        organization=user_org(request.user),
        platform=platform,
        version=release.version,
        ip=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        type=DownloadAudit.TYPE_INSTALLER,
    )

    if release.file:
        filename = release.file.name.rsplit('/', 1)[-1]
        return FileResponse(release.file.open('rb'), as_attachment=True, filename=filename)

    if release.file_url:
        response = HttpResponse(status=302)
        response['Location'] = release.file_url
        return response

    return HttpResponse('Release activo sin archivo o URL de descarga.', status=500)


@login_required
def download_bundle(request, platform):
    if platform not in SUPPORTED_PLATFORMS:
        return HttpResponse(status=404)
    if is_rate_limited(request, platform, 'bundle'):
        return HttpResponse('Demasiadas descargas, intenta nuevamente en un minuto.', status=429)

    org = user_org(request.user)
    if not org:
        return HttpResponse('El usuario no está asociado a una organización.', status=403)

    release = get_active_release(platform)
    version = release.version if release else 'bootstrap'
    enrollment = EnrollmentToken.generate(org=org, created_by=request.user, hours=24)

    files = {
        'config.yml': _config_payload(request, enrollment).encode(),
        'README-quickstart.txt': _readme(platform, org, enrollment).encode(),
    }
    installer_name = SUPPORTED_PLATFORMS[platform]['installer_name']
    files[installer_name] = (_linux_install_script() if platform == AgentRelease.PLATFORM_LINUX else _windows_install_script()).encode()

    for rel, content in _agent_source_files():
        files[rel] = content

    DownloadAudit.objects.create(
        user=request.user,
        organization=org,
        platform=platform,
        version=version,
        ip=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        type=DownloadAudit.TYPE_BUNDLE,
    )

    if platform == AgentRelease.PLATFORM_LINUX:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            for name, content in files.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(content)
                info.mode = 0o755 if name.endswith('.sh') else 0o644
                tar.addfile(info, io.BytesIO(content))
        buf.seek(0)
        response = HttpResponse(buf.getvalue(), content_type='application/gzip')
        response['Content-Disposition'] = 'attachment; filename="agent-nocturno-linux-bundle.tar.gz"'
        return response

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode='w', compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, content in files.items():
            bundle.writestr(name, content)
    buf.seek(0)
    response = HttpResponse(buf.getvalue(), content_type='application/zip')
    response['Content-Disposition'] = 'attachment; filename="agent-nocturno-windows-bundle.zip"'
    return response


@login_required
@require_http_methods(['GET', 'POST'])
def releases_admin(request):
    if not _is_admin(request.user):
        return HttpResponseForbidden('Solo administradores.')

    if request.method == 'POST':
        form = AgentReleaseForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, 'Release guardado correctamente.')
            return redirect('agent_downloads:releases_admin')
    else:
        form = AgentReleaseForm()

    releases = AgentRelease.objects.all()
    return render(request, 'agent_downloads/releases_admin.html', {'form': form, 'releases': releases})


@login_required
@require_http_methods(['POST'])
def release_delete(request, release_id):
    if not _is_admin(request.user):
        return HttpResponseForbidden('Solo administradores.')
    rel = get_object_or_404(AgentRelease, id=release_id)
    rel.delete()
    messages.success(request, 'Release eliminado.')
    return redirect('agent_downloads:releases_admin')


@login_required
@require_http_methods(['POST'])
def release_activate(request, release_id):
    if not _is_admin(request.user):
        return HttpResponseForbidden('Solo administradores.')
    rel = get_object_or_404(AgentRelease, id=release_id)
    rel.is_active = True
    rel.save(update_fields=['is_active'])
    AgentRelease.objects.filter(platform=rel.platform, is_active=True).exclude(id=rel.id).update(is_active=False)
    messages.success(request, f'Release {rel.version} activo para {rel.platform}.')
    return redirect('agent_downloads:releases_admin')
