from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from .models import Organization, UserProfile


class BasicModelTests(TestCase):
    def test_profile_created(self):
        u = User.objects.create_user('alice', password='x12345')
        self.assertTrue(UserProfile.objects.filter(user=u).exists())

    def test_org_default(self):
        org = Organization.objects.create(name='ACME')
        self.assertEqual(org.retention_days, 90)
