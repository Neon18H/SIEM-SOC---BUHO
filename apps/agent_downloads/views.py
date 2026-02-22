import io
import zipfile

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.http import FileResponse, HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse

from soc.auth import user_org
from soc.models import EnrollmentToken

from .models import AgentRelease, DownloadAudit

SUPPORTED_PLATFORMS = {
    AgentRelease.PLATFORM_LINUX: {
        'title': 'Linux (x86_64)',
        'installer_name': 'install.sh',
    },
    AgentRelease.PLATFORM_WINDOWS: {
        'title': 'Windows (x64)',
        'installer_name': 'install.ps1',
    },
}


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


def installer_script(platform):
    if platform == AgentRelease.PLATFORM_WINDOWS:
        return (
            "Write-Host 'Instalando Agente Nocturno...'\n"
            "New-Item -ItemType Directory -Force -Path C:\\ProgramData\\AgenteNocturno | Out-Null\n"
            "Copy-Item .\\config.yml C:\\ProgramData\\AgenteNocturno\\config.yml -Force\n"
            "Write-Host 'Config copiada en C:\\ProgramData\\AgenteNocturno\\config.yml'\n"
        )
    return (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "echo 'Instalando Agente Nocturno...'\n"
        "sudo mkdir -p /etc/agente-nocturno\n"
        "sudo cp ./config.yml /etc/agente-nocturno/config.yml\n"
        "echo 'Config copiada en /etc/agente-nocturno/config.yml'\n"
    )


@login_required
def downloads_page(request):
    cards = []
    for platform, metadata in SUPPORTED_PLATFORMS.items():
        cards.append({
            'platform': platform,
            'title': metadata['title'],
            'release': get_active_release(platform),
        })
    return render(request, 'agent_downloads/downloads.html', {'cards': cards})


@login_required
def download_installer(request, platform):
    if platform not in SUPPORTED_PLATFORMS:
        return HttpResponse(status=404)

    if is_rate_limited(request, platform, 'installer'):
        return HttpResponse('Demasiadas descargas, intenta nuevamente en un minuto.', status=429)

    release = get_active_release(platform)
    if not release:
        messages.warning(request, 'No hay release publicado aún')
        return HttpResponseRedirect(reverse('agent_downloads:downloads'))

    if not release.file and not release.file_url:
        messages.warning(request, 'No hay archivo de instalador disponible para este release.')
        return HttpResponseRedirect(reverse('agent_downloads:downloads'))

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

    response = HttpResponse(status=302)
    response['Location'] = release.file_url
    return response


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
    version = release.version if release else 'unreleased'

    enrollment = EnrollmentToken.generate(org=org, created_by=request.user, hours=24)

    config_payload = (
        f"soc_url: {getattr(settings, 'AGENT_SOC_URL', 'https://soc.example.local')}\n"
        f"enrollment_token: {enrollment.token}\n"
        "interval: 60\n"
        "verify_tls: true\n"
    )

    readme_payload = (
        "Agente Nocturno - Quickstart\n"
        "================================\n\n"
        f"Organización: {org.name}\n"
        f"Token expira: {enrollment.expires_at.isoformat()}\n\n"
        "1) Descomprime el ZIP\n"
        f"2) Ejecuta {SUPPORTED_PLATFORMS[platform]['installer_name']} con permisos de administrador/root\n"
        "3) Inicia el servicio del agente\n"
    )

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode='w', compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('config.yml', config_payload)
        bundle.writestr(SUPPORTED_PLATFORMS[platform]['installer_name'], installer_script(platform))
        bundle.writestr('README-quickstart.txt', readme_payload)

    zip_buffer.seek(0)

    DownloadAudit.objects.create(
        user=request.user,
        organization=org,
        platform=platform,
        version=version,
        ip=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        type=DownloadAudit.TYPE_BUNDLE,
    )

    response = HttpResponse(zip_buffer.getvalue(), content_type='application/zip')
    response['Content-Disposition'] = f'attachment; filename="agente-nocturno-{platform}-bundle.zip"'
    return response
