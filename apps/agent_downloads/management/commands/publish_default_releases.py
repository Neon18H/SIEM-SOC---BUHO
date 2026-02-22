import tarfile
import zipfile
from pathlib import Path

from django.conf import settings
from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand

from apps.agent_downloads.models import AgentRelease


class Command(BaseCommand):
    help = 'Publica releases por defecto desde archivos existentes del repositorio.'

    def handle(self, *args, **options):
        base = Path(settings.BASE_DIR)
        self._publish_linux(base)
        self._publish_windows(base)

    def _publish_linux(self, base: Path):
        release_file = self._find_existing(base, ['examples/releases/agent-linux.tar.gz', 'agent_releases/agent-linux.tar.gz'])
        if not release_file:
            src = base / 'examples/release_example/linux'
            if src.exists():
                release_file = self._create_linux_archive(src)

        if not release_file:
            self.stdout.write(self.style.WARNING('No se encontró release Linux para publicar.'))
            return

        self._upsert_release('linux', 'default-linux', release_file.read_bytes(), release_file.name)

    def _publish_windows(self, base: Path):
        release_file = self._find_existing(base, ['examples/releases/agent-windows.zip', 'agent_releases/agent-windows.zip'])
        if not release_file:
            src = base / 'examples/release_example/windows'
            if src.exists():
                release_file = self._create_windows_archive(src)

        if not release_file:
            self.stdout.write(self.style.WARNING('No se encontró release Windows para publicar.'))
            return

        self._upsert_release('windows', 'default-windows', release_file.read_bytes(), release_file.name)

    def _find_existing(self, base: Path, candidates):
        for rel in candidates:
            candidate = base / rel
            if candidate.exists() and candidate.is_file():
                return candidate
        return None

    def _create_linux_archive(self, src: Path):
        out = src / 'agent-linux.tar.gz'
        with tarfile.open(out, mode='w:gz') as tar:
            for file_path in src.rglob('*'):
                if file_path.is_file() and file_path.name != out.name:
                    tar.add(file_path, arcname=file_path.relative_to(src))
        return out

    def _create_windows_archive(self, src: Path):
        out = src / 'agent-windows.zip'
        with zipfile.ZipFile(out, mode='w', compression=zipfile.ZIP_DEFLATED) as archive:
            for file_path in src.rglob('*'):
                if file_path.is_file() and file_path.name != out.name:
                    archive.write(file_path, arcname=file_path.relative_to(src))
        return out

    def _upsert_release(self, platform, version, data: bytes, filename: str):
        release, _ = AgentRelease.objects.get_or_create(platform=platform, version=version)
        release.file.save(filename, ContentFile(data), save=False)
        release.is_active = True
        release.save()
        self.stdout.write(self.style.SUCCESS(f'Release {platform} publicado: {release.version}'))
