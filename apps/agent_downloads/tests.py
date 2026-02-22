import io
import tarfile

from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.test import TestCase
from django.urls import reverse

from soc.models import EnrollmentToken, Organization, UserProfile

from .models import AgentRelease


class AgentDownloadsTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name='Org Test')
        self.user = User.objects.create_user(username='analyst', password='secret123')
        profile=self.user.userprofile
        profile.organization=self.org
        profile.role='admin'
        profile.save()

    def test_bundle_linux_generates_token_and_tar(self):
        self.client.login(username='analyst', password='secret123')
        response = self.client.get(reverse('agent_downloads:download_bundle', args=['linux']))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/gzip')

        tar = tarfile.open(fileobj=io.BytesIO(response.content), mode='r:gz')
        members = set(tar.getnames())
        self.assertIn('config.yml', members)
        self.assertIn('install.sh', members)
        self.assertIn('agent/main.py', members)

    def test_installer_download_when_release_exists(self):
        release = AgentRelease(platform='linux', version='0.1.0', is_active=True)
        release.file.save('agent-linux.bin', ContentFile(b'binary-content'))
        release.save()

        self.client.login(username='analyst', password='secret123')
        response = self.client.get(reverse('agent_downloads:download_installer', args=['linux']))

        self.assertEqual(response.status_code, 200)
        self.assertIn('attachment;', response['Content-Disposition'])

    def test_releases_admin_forbidden_non_admin(self):
        viewer = User.objects.create_user(username='viewer', password='secret123')
        viewer_profile=viewer.userprofile
        viewer_profile.organization=self.org
        viewer_profile.role='viewer'
        viewer_profile.save()
        self.client.login(username='viewer', password='secret123')
        response = self.client.get(reverse('agent_downloads:releases_admin'))
        self.assertEqual(response.status_code, 403)


    def test_bundle_uses_user_org_for_token(self):
        self.client.login(username='analyst', password='secret123')
        response = self.client.get(reverse('agent_downloads:download_bundle', args=['windows']))
        self.assertEqual(response.status_code, 200)

        token = EnrollmentToken.objects.latest('id')
        self.assertEqual(token.organization, self.org)
        self.assertEqual(token.created_by, self.user)
