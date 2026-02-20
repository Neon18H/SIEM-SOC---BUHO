import hashlib
from rest_framework import permissions
from .models import Agent


def user_org(user):
    return getattr(getattr(user, 'userprofile', None), 'organization', None)


class IsAdminOrAnalyst(permissions.BasePermission):
    def has_permission(self, request, view):
        profile = getattr(request.user, 'userprofile', None)
        return bool(profile and profile.role in ['admin', 'analyst'])


class AgentKeyAuthentication:
    header = 'HTTP_X_AGENT_KEY'

    @classmethod
    def authenticate(cls, request):
        raw_key = request.META.get(cls.header)
        if not raw_key:
            return None
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        return Agent.objects.filter(agent_key_hash=key_hash).select_related('organization').first()
