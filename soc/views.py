import json
import secrets
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.db.models import Q
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .auth import AgentKeyAuthentication, IsAdminOrAnalyst, user_org
from .models import Agent, Alert, Case, EnrollmentToken, IRAction, LogEvent, Rule
from .serializers import AlertSerializer, CaseSerializer, EnrollmentSerializer, IngestSerializer, LogEventSerializer, RuleSerializer
from .services import correlate_login_pattern, enrich_with_ioc, evaluate_rules, import_iocs, kpis_for_org, normalize_payload, register_parsing_error
from .throttles import IngestRateThrottle


class AgentEnrollView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = EnrollmentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = get_object_or_404(EnrollmentToken, token=serializer.validated_data['token'], used=False)
        if token.expires_at < timezone.now():
            return Response({'detail': 'Token expirado'}, status=400)

        raw_agent_key = secrets.token_urlsafe(36)
        agent = Agent.objects.create(
            organization=token.organization,
            hostname=serializer.validated_data['hostname'],
            os=serializer.validated_data['os'],
            ip=serializer.validated_data['ip'],
            status='online',
            last_seen=timezone.now(),
            agent_key_hash=''
        )
        agent.set_agent_key(raw_agent_key)
        agent.save(update_fields=['agent_key_hash'])
        token.used = True
        token.save(update_fields=['used'])
        return Response({'agent_id': agent.id, 'agent_key': raw_agent_key})


class IngestView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [IngestRateThrottle]

    def post(self, request):
        agent = AgentKeyAuthentication.authenticate(request)
        if not agent:
            return Response({'detail': 'invalid agent key'}, status=401)
        serializer = IngestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        parsed = {}
        try:
            parsed = normalize_payload(data)
        except Exception as exc:
            register_parsing_error(agent.organization, request.data, exc)

        event = LogEvent.objects.create(
            organization=agent.organization,
            agent=agent,
            ts=data['ts'],
            source=data['source'],
            severity=data['severity'],
            category=data['category'],
            message=data['message'],
            user=data.get('user', ''),
            ip=data.get('ip'),
            host=data.get('host', ''),
            raw_json=data.get('raw', request.data),
            parsed_json=parsed,
            tags=[],
        )
        agent.last_seen = timezone.now()
        agent.status = 'online'
        agent.save(update_fields=['last_seen', 'status'])

        enrich_with_ioc(event)
        evaluate_rules(event)
        correlate_login_pattern(agent.organization, event)

        if Alert.objects.filter(event=event).exists():
            try:
                send_mail(
                    'Agente Nocturno - Nueva alerta',
                    f'Se generó una alerta para evento {event.id}',
                    None,
                    ['soc@example.local'],
                    fail_silently=False,
                )
            except Exception:
                pass

        return Response({'ok': True, 'event_id': event.id})


class OrgScopedMixin:
    def get_queryset(self):
        org = user_org(self.request.user)
        return self.queryset.filter(organization=org)

    def perform_create(self, serializer):
        serializer.save(organization=user_org(self.request.user))


class EventViewSet(OrgScopedMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = LogEventSerializer
    queryset = LogEvent.objects.all().select_related('agent')
    filterset_fields = ['category', 'user', 'host', 'ip']
    search_fields = ['message', 'user', 'host', 'category']
    ordering_fields = ['ts', 'severity', 'created_at']

    def get_queryset(self):
        qs = super().get_queryset()
        p = self.request.query_params
        if p.get('start'):
            qs = qs.filter(ts__gte=p['start'])
        if p.get('end'):
            qs = qs.filter(ts__lte=p['end'])
        if p.get('severity_min'):
            qs = qs.filter(severity__gte=p['severity_min'])
        if p.get('severity_max'):
            qs = qs.filter(severity__lte=p['severity_max'])
        return qs


class RuleViewSet(OrgScopedMixin, viewsets.ModelViewSet):
    serializer_class = RuleSerializer
    queryset = Rule.objects.all()
    permission_classes = [IsAuthenticated, IsAdminOrAnalyst]


class AlertViewSet(OrgScopedMixin, viewsets.ModelViewSet):
    serializer_class = AlertSerializer
    queryset = Alert.objects.all().select_related('event', 'rule')


class CaseViewSet(OrgScopedMixin, viewsets.ModelViewSet):
    serializer_class = CaseSerializer
    queryset = Case.objects.all()


@api_view(['GET'])
def metrics_view(request):
    org = user_org(request.user)
    return Response(kpis_for_org(org))


@api_view(['POST'])
def threatintel_import_view(request):
    org = user_org(request.user)
    file_type = request.data.get('file_type', 'json')
    content = request.data.get('content')
    if not content:
        return Response({'detail': 'content requerido'}, status=400)
    created = import_iocs(org, content, file_type)
    return Response({'created': created})


@login_required
def dashboard_view(request):
    ctx = {'kpis': kpis_for_org(user_org(request.user))}
    return render(request, 'soc/dashboard.html', ctx)


@login_required
def hunting_view(request):
    org = user_org(request.user)
    qs = LogEvent.objects.filter(organization=org).order_by('-ts')
    q = request.GET
    if q.get('start'):
        qs = qs.filter(ts__gte=q['start'])
    if q.get('end'):
        qs = qs.filter(ts__lte=q['end'])
    if q.get('ip'):
        qs = qs.filter(ip=q['ip'])
    if q.get('user'):
        qs = qs.filter(user=q['user'])
    if q.get('host'):
        qs = qs.filter(host=q['host'])
    if q.get('severity_min'):
        qs = qs.filter(severity__gte=q['severity_min'])
    if q.get('severity_max'):
        qs = qs.filter(severity__lte=q['severity_max'])
    if q.get('text'):
        qs = qs.filter(message__icontains=q['text'])
    if q.get('category'):
        qs = qs.filter(category=q['category'])
    return render(request, 'soc/hunting.html', {'events': qs[:200]})


@login_required
def alerts_view(request):
    org = user_org(request.user)
    alerts = Alert.objects.filter(organization=org).order_by('-created_at')[:200]
    return render(request, 'soc/alerts.html', {'alerts': alerts})


@login_required
def alert_status_htmx(request, alert_id):
    if request.method != 'POST':
        return HttpResponseBadRequest('POST only')
    alert = get_object_or_404(Alert, id=alert_id, organization=user_org(request.user))
    alert.status = request.POST.get('status', alert.status)
    alert.save(update_fields=['status'])
    return render(request, 'soc/partials/alert_row.html', {'a': alert})


@login_required
def cases_view(request):
    org = user_org(request.user)
    cases = Case.objects.filter(organization=org).order_by('-created_at')
    actions = IRAction.objects.filter(organization=org).order_by('-created_at')[:50]
    return render(request, 'soc/cases.html', {'cases': cases, 'actions': actions})


@login_required
def create_ir_action(request):
    if request.method != 'POST':
        return HttpResponseBadRequest('POST only')
    org = user_org(request.user)
    action = IRAction.objects.create(
        organization=org,
        action_type=request.POST.get('action_type', 'block_ip'),
        target_value=request.POST.get('target_value', ''),
        status='executed',
        result_json={'simulated': True},
    )
    return JsonResponse({'ok': True, 'action_id': action.id, 'status': action.status})
