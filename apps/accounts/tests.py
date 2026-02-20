from django.contrib.auth import get_user_model
from django.db import connection
from django.db.models.signals import post_save
from django.test import TransactionTestCase, override_settings

from soc.models import Organization, UserProfile
from soc.signals import create_profile

User = get_user_model()


@override_settings(ALLOW_PUBLIC_SIGNUP=True, DEFAULT_SIGNUP_ROLE='viewer')
class RegisterViewTests(TransactionTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(Organization)
            schema_editor.create_model(UserProfile)

    @classmethod
    def tearDownClass(cls):
        with connection.schema_editor() as schema_editor:
            schema_editor.delete_model(UserProfile)
            schema_editor.delete_model(Organization)
        super().tearDownClass()

    def _register_payload(self, username='analista', email='analista@example.com'):
        return {
            'full_name': 'Analista SOC',
            'username': username,
            'email': email,
            'password1': 'S3guraPass!123',
            'password2': 'S3guraPass!123',
        }

    def test_register_creates_user_and_profile(self):
        post_save.disconnect(create_profile, sender=User)
        try:
            response = self.client.post('/register', data=self._register_payload())
        finally:
            post_save.connect(create_profile, sender=User)

        self.assertRedirects(response, '/dashboard', fetch_redirect_response=False)
        user = User.objects.get(username='analista')
        profile = UserProfile.objects.get(user=user)
        self.assertEqual(profile.role, UserProfile.ROLE_VIEWER)
        self.assertEqual(profile.organization.name, 'Default Org')

    def test_register_when_profile_exists_does_not_crash(self):
        response = self.client.post(
            '/register',
            data=self._register_payload(username='analista2', email='analista2@example.com'),
        )

        self.assertRedirects(response, '/dashboard', fetch_redirect_response=False)
        user = User.objects.get(username='analista2')
        self.assertEqual(UserProfile.objects.filter(user=user).count(), 1)
        profile = UserProfile.objects.get(user=user)
        self.assertEqual(profile.role, UserProfile.ROLE_VIEWER)
