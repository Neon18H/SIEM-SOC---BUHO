from django.contrib.auth.models import User
from django.db import models

from soc.models import Organization


class AgentRelease(models.Model):
    PLATFORM_LINUX = 'linux'
    PLATFORM_WINDOWS = 'windows'
    PLATFORM_CHOICES = [
        (PLATFORM_LINUX, 'Linux (x86_64)'),
        (PLATFORM_WINDOWS, 'Windows (x64)'),
    ]

    platform = models.CharField(max_length=20, choices=PLATFORM_CHOICES)
    version = models.CharField(max_length=32)
    file = models.FileField(upload_to='agents/', blank=True, null=True)
    file_url = models.URLField(blank=True)
    sha256 = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=False)
    release_notes = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.get_platform_display()} {self.version}'


class DownloadAudit(models.Model):
    TYPE_INSTALLER = 'installer'
    TYPE_BUNDLE = 'bundle'
    TYPE_CHOICES = [
        (TYPE_INSTALLER, 'Installer'),
        (TYPE_BUNDLE, 'Bundle'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    platform = models.CharField(max_length=20, choices=AgentRelease.PLATFORM_CHOICES)
    version = models.CharField(max_length=32)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.user} {self.platform} {self.version} ({self.type})'
