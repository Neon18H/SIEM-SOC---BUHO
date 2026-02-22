from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    AgentEnrollView,
    AlertViewSet,
    CaseViewSet,
    EventViewSet,
    IngestView,
    RuleViewSet,
    alert_status_htmx,
    alerts_view,
    cases_view,
    create_ir_action,
    dashboard_view,
    endpoint_detail_view,
    endpoints_view,
    hunting_view,
    metrics_view,
    threatintel_import_view,
)

router = DefaultRouter()
router.register('events', EventViewSet, basename='events')
router.register('rules', RuleViewSet, basename='rules')
router.register('alerts', AlertViewSet, basename='alerts')
router.register('cases', CaseViewSet, basename='cases')

urlpatterns = [
    path('dashboard/', dashboard_view, name='dashboard'),
    path('hunting/', hunting_view, name='hunting'),
    path('endpoints/', endpoints_view, name='endpoints'),
    path('endpoints/<int:endpoint_id>/', endpoint_detail_view, name='endpoint_detail'),
    path('alerts/', alerts_view, name='alerts'),
    path('cases/', cases_view, name='cases'),
    path('ir/actions/create/', create_ir_action, name='ir_action_create'),
    path('alerts/<int:alert_id>/status/', alert_status_htmx, name='alert_status_htmx'),

    path('api/agents/enroll/', AgentEnrollView.as_view(), name='api_enroll'),
    path('api/ingest/', IngestView.as_view(), name='api_ingest'),
    path('api/metrics/', metrics_view, name='api_metrics'),
    path('api/threatintel/import/', threatintel_import_view, name='api_ti_import'),
    path('api/', include(router.urls)),
]
