import hashlib
import secrets
from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class Organization(models.Model):
    name = models.CharField(max_length=120, unique=True)
    retention_days = models.PositiveIntegerField(default=90)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class UserProfile(models.Model):
    ROLE_ADMIN = 'admin'
    ROLE_ANALYST = 'analyst'
    ROLE_VIEWER = 'viewer'
    ROLE_CHOICES = [(ROLE_ADMIN, 'Admin'), (ROLE_ANALYST, 'Analyst'), (ROLE_VIEWER, 'Viewer')]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_VIEWER)


class Agent(models.Model):
    STATUS_ONLINE = 'online'
    STATUS_OFFLINE = 'offline'
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    hostname = models.CharField(max_length=120)
    os = models.CharField(max_length=120)
    ip = models.GenericIPAddressField()
    status = models.CharField(max_length=20, default=STATUS_OFFLINE)
    last_seen = models.DateTimeField(null=True, blank=True)
    agent_key_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)

    def set_agent_key(self, raw_key: str):
        self.agent_key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    def verify_key(self, raw_key: str) -> bool:
        return hashlib.sha256(raw_key.encode()).hexdigest() == self.agent_key_hash


class EnrollmentToken(models.Model):
    token = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField()
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    used = models.BooleanField(default=False)

    @classmethod
    def generate(cls, org, created_by, hours=24):
        token = secrets.token_urlsafe(32)
        return cls.objects.create(
            token=token,
            organization=org,
            created_by=created_by,
            expires_at=timezone.now() + timezone.timedelta(hours=hours),
        )


class LogEvent(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    agent = models.ForeignKey(Agent, on_delete=models.SET_NULL, null=True, blank=True)
    ts = models.DateTimeField(db_index=True)
    source = models.CharField(max_length=120)
    severity = models.PositiveSmallIntegerField(db_index=True)
    category = models.CharField(max_length=100, db_index=True)
    message = models.TextField()
    user = models.CharField(max_length=120, blank=True, db_index=True)
    ip = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    host = models.CharField(max_length=120, blank=True, db_index=True)
    raw_json = models.JSONField(default=dict)
    parsed_json = models.JSONField(default=dict)
    tags = models.JSONField(default=list)
    enriched = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)


class Rule(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    name = models.CharField(max_length=120)
    enabled = models.BooleanField(default=True)
    condition_json = models.JSONField(default=dict)
    mitre_json = models.JSONField(default=dict)
    severity = models.CharField(max_length=20, default='Medium')
    created_at = models.DateTimeField(auto_now_add=True)


class CorrelationRecord(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    window_start = models.DateTimeField()
    window_end = models.DateTimeField()
    keys_json = models.JSONField(default=dict)
    matched_events = models.ManyToManyField(LogEvent, related_name='correlations')
    created_at = models.DateTimeField(auto_now_add=True)


class Alert(models.Model):
    SEVERITY_CHOICES = [('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High'), ('Critical', 'Critical')]
    STATUS_CHOICES = [('new', 'New'), ('triaged', 'Triaged'), ('closed', 'Closed')]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    event = models.ForeignKey(LogEvent, on_delete=models.CASCADE, null=True, blank=True)
    rule = models.ForeignKey(Rule, on_delete=models.SET_NULL, null=True, blank=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    assignee = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    title = models.CharField(max_length=200, default='Generated Alert')
    details = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Case(models.Model):
    STATUS_CHOICES = [('open', 'Open'), ('investigating', 'Investigating'), ('resolved', 'Resolved')]
    PRIORITY_CHOICES = [('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    description = models.TextField()
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='open')
    priority = models.CharField(max_length=30, choices=PRIORITY_CHOICES, default='medium')
    assignee = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class CaseEventLink(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='event_links')
    event = models.ForeignKey(LogEvent, on_delete=models.CASCADE)


class CaseNote(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='notes')
    author = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    note = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)


class IRAction(models.Model):
    TYPE_CHOICES = [('block_ip', 'Block IP'), ('disable_account', 'Disable Account')]
    STATUS_CHOICES = [('pending', 'Pending'), ('executed', 'Executed'), ('failed', 'Failed')]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    case = models.ForeignKey(Case, on_delete=models.SET_NULL, null=True, blank=True)
    event = models.ForeignKey(LogEvent, on_delete=models.SET_NULL, null=True, blank=True)
    action_type = models.CharField(max_length=30, choices=TYPE_CHOICES)
    target_value = models.CharField(max_length=200)
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='pending')
    connector = models.CharField(max_length=80, default='mock-connector')
    result_json = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)


class IOC(models.Model):
    IOC_TYPES = [('ip', 'IP'), ('domain', 'Domain'), ('hash', 'Hash')]
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
    type = models.CharField(max_length=20, choices=IOC_TYPES)
    value = models.CharField(max_length=255, db_index=True)
    source = models.CharField(max_length=120)
    confidence = models.PositiveSmallIntegerField(default=50)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = ('organization', 'type', 'value')


class ParsingError(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    raw_payload = models.JSONField(default=dict)
    error = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
