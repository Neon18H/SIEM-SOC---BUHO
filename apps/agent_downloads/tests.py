import io
import zipfile

from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.test import TestCase
from django.urls import reverse

from soc.models import Organization, UserProfile

from .models import AgentRelease


class AgentDownloadsTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name='Org Test')
        self.user = User.objects.create_user(username='analyst', password='secret123')
        UserProfile.objects.filter(user=self.user).update(organization=self.org, role='analyst')

    def test_downloads_page_requires_login(self):
        response = self.client.get(reverse('agent_downloads:downloads'))
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.url)

    def test_bundle_generates_token_and_valid_zip(self):
        self.client.login(username='analyst', password='secret123')
        response = self.client.get(reverse('agent_downloads:download_bundle', args=['linux']))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/zip')

        zipped = zipfile.ZipFile(io.BytesIO(response.content))
        members = set(zipped.namelist())
        self.assertIn('config.yml', members)
        self.assertIn('install.sh', members)
        self.assertIn('README-quickstart.txt', members)

        config = zipped.read('config.yml').decode('utf-8')
        self.assertIn('enrollment_token:', config)
        self.assertIn('soc_url:', config)

    def test_installer_download_when_release_exists(self):
        release = AgentRelease.objects.create(
            platform='linux',
            version='0.1.0',
            sha256='a' * 64,
            is_active=True,
        )
        release.file.save('agent-linux.bin', ContentFile(b'binary-content'))

        self.client.login(username='analyst', password='secret123')
        response = self.client.get(reverse('agent_downloads:download_installer', args=['linux']))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/octet-stream')
        self.assertIn('attachment;', response['Content-Disposition'])
