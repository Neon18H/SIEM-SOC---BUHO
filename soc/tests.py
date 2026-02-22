from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .models import Agent, Alert, EndpointRisk, LogEvent, Organization, UserProfile


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


class EnrollmentAndIngestOrgEnforcementTests(TestCase):
    def setUp(self):
        self.org1 = Organization.objects.create(name='Tenant One')
        self.org2 = Organization.objects.create(name='Tenant Two')

    def test_enroll_assigns_org_from_token(self):
        from .models import EnrollmentToken
        token = EnrollmentToken.generate(org=self.org1, created_by=None, hours=1)

        response = self.client.post(
            reverse('api_enroll'),
            data={
                'token': token.token,
                'hostname': 'h1',
                'os': 'linux',
                'ip': '10.10.10.10',
            },
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 200)
        agent_id = response.json()['agent_id']
        agent = Agent.objects.get(id=agent_id)
        self.assertEqual(agent.organization, self.org1)

    def test_ingest_forces_agent_org(self):
        agent = Agent.objects.create(
            organization=self.org1,
            hostname='h2',
            os='linux',
            ip='10.0.0.5',
            status='online',
            agent_key_hash='',
        )
        agent.set_agent_key('forced-org-key')
        agent.save(update_fields=['agent_key_hash'])

        payload = {
            'ts': timezone.now().isoformat(),
            'source': 'agent',
            'severity': 4,
            'category': 'telemetry',
            'message': 'tenant check',
            'host': 'h2',
            'ip': '10.0.0.5',
            'raw': {'organization': self.org2.id},
        }
        response = self.client.post(
            reverse('api_ingest'),
            data=payload,
            content_type='application/json',
            **{'HTTP_X_AGENT_KEY': 'forced-org-key'},
        )
        self.assertEqual(response.status_code, 200)
        event = agent.logevent_set.latest('id')
        self.assertEqual(event.organization, self.org1)


class UBAApiTests(TestCase):
    def setUp(self):
        self.org1 = Organization.objects.create(name='UBA Org 1')
        self.org2 = Organization.objects.create(name='UBA Org 2')
        self.user = User.objects.create_user('uba-user', password='x12345')
        profile = self.user.userprofile
        profile.organization = self.org1
        profile.save(update_fields=['organization'])

        self.agent_org1 = Agent.objects.create(organization=self.org1, hostname='uba-a1', os='linux', ip='10.10.1.1', status='online', agent_key_hash='x')
        self.agent_org2 = Agent.objects.create(organization=self.org2, hostname='uba-a2', os='linux', ip='10.20.1.1', status='online', agent_key_hash='y')

        event = LogEvent.objects.create(
            organization=self.org1,
            agent=self.agent_org1,
            ts=timezone.now(),
            source='agent',
            severity=7,
            category='auth',
            message='failed login for admin',
            user='admin',
            raw_json={},
            parsed_json={},
        )
        Alert.objects.create(organization=self.org1, event=event, severity='High', title='Auth offense')

    def test_uba_endpoint_outside_org_returns_404(self):
        self.client.login(username='uba-user', password='x12345')
        response = self.client.get(reverse('api_uba_summary', kwargs={'agent_id': self.agent_org2.id}))
        self.assertEqual(response.status_code, 404)

    def test_uba_summary_json_shape(self):
        self.client.login(username='uba-user', password='x12345')
        response = self.client.get(reverse('api_uba_summary', kwargs={'agent_id': self.agent_org1.id}), {'range': '24h'})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        expected_keys = {
            'agent_id',
            'endpoint',
            'window',
            'total_events',
            'monitored_users',
            'offenses',
            'avg_severity',
            'system_risk_score',
        }
        self.assertTrue(expected_keys.issubset(payload.keys()))
