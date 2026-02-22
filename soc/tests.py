from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .models import Agent, Alert, EndpointRisk, Organization, UserProfile


class BasicModelTests(TestCase):
    def test_profile_created(self):
        u = User.objects.create_user('alice', password='x12345')
        self.assertTrue(UserProfile.objects.filter(user=u).exists())

    def test_org_default(self):
        org = Organization.objects.create(name='ACME')
        self.assertEqual(org.retention_days, 90)


class EndpointRiskAndDetectionTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name='Blue Team')
        self.agent = Agent.objects.create(
            organization=self.org,
            hostname='host-1',
            os='windows',
            ip='10.0.0.10',
            status='online',
            agent_key_hash=''
        )
        self.agent.set_agent_key('secret-agent-key')
        self.agent.save(update_fields=['agent_key_hash'])

    def _ingest(self, payload):
        base = {
            'ts': timezone.now().isoformat(),
            'source': 'agent',
            'severity': 4,
            'category': 'telemetry',
            'message': 'event',
            'host': self.agent.hostname,
            'ip': '10.0.0.10',
            'raw': {},
        }
        base.update(payload)
        return self.client.post(
            reverse('api_ingest'),
            data=base,
            content_type='application/json',
            **{'HTTP_X_AGENT_KEY': 'secret-agent-key'},
        )

    def test_risk_score_update(self):
        response = self._ingest({
            'category': 'commandline',
            'message': 'powershell encoded',
            'raw': {'cmd': 'powershell -EncodedCommand SQBtAG...'}
        })
        self.assertEqual(response.status_code, 200)
        risk = EndpointRisk.objects.get(agent=self.agent)
        self.assertGreaterEqual(risk.score, 8)

    def test_brute_force_detection(self):
        for _ in range(5):
            self._ingest({
                'category': 'user_activity',
                'message': 'failed login',
                'raw': {'action': 'failed_login', 'user': 'admin'}
            })
        self.assertTrue(Alert.objects.filter(event__agent=self.agent, title__icontains='Brute force').exists())


class EndpointsListAuthTests(TestCase):
    def setUp(self):
        self.org1 = Organization.objects.create(name='Org 1')
        self.org2 = Organization.objects.create(name='Org 2')

        self.user = User.objects.create_user('bob', password='x12345')
        profile = self.user.userprofile
        profile.organization = self.org1
        profile.save(update_fields=['organization'])

        Agent.objects.create(organization=self.org1, hostname='a1', os='linux', ip='10.1.1.1', status='online', agent_key_hash='x')
        Agent.objects.create(organization=self.org2, hostname='a2', os='linux', ip='10.2.2.2', status='online', agent_key_hash='y')

    def test_endpoints_view_requires_auth(self):
        response = self.client.get(reverse('endpoints'))
        self.assertEqual(response.status_code, 302)

    def test_endpoints_view_org_scoped(self):
        self.client.login(username='bob', password='x12345')
        response = self.client.get(reverse('endpoints'))
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('a1', content)
        self.assertNotIn('a2', content)
