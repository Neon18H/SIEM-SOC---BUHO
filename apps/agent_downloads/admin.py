from django.contrib import admin

from .models import AgentRelease, DownloadAudit


@admin.register(AgentRelease)
class AgentReleaseAdmin(admin.ModelAdmin):
    list_display = ('platform', 'version', 'is_active', 'created_at')
    list_filter = ('platform', 'is_active')
    search_fields = ('version', 'sha256')


@admin.register(DownloadAudit)
class DownloadAuditAdmin(admin.ModelAdmin):
    list_display = ('user', 'organization', 'platform', 'version', 'type', 'created_at')
    list_filter = ('platform', 'type', 'organization')
    search_fields = ('user__username', 'version', 'ip')
