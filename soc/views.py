import json
import secrets
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.db.models import Count, F, Q, Max
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
from .services import correlate_login_pattern, enrich_with_ioc, evaluate_rules, import_iocs, kpis_for_org, normalize_payload, process_endpoint_event, register_parsing_error
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
        process_endpoint_event(event)

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
    org = user_org(request.user)
    now = timezone.now()
    last_24h = now - timezone.timedelta(hours=24)
    prev_24h = last_24h - timezone.timedelta(hours=24)

    events_qs = LogEvent.objects.filter(organization=org)
    alerts_qs = Alert.objects.filter(organization=org)

    current_events = events_qs.filter(ts__gte=last_24h)
    previous_events = events_qs.filter(ts__gte=prev_24h, ts__lt=last_24h)

    auth_current = current_events.filter(category__icontains='auth')
    auth_previous = previous_events.filter(category__icontains='auth')

    def trend(current, previous):
        if current > previous:
            return 'up'
        if current < previous:
            return 'down'
        return 'flat'

    total_events = current_events.count()
    critical_alerts = alerts_qs.filter(created_at__gte=last_24h, severity='Critical').count()
    auth_failures = auth_current.filter(Q(message__icontains='fail') | Q(message__icontains='invalid')).count()
    auth_success = auth_current.filter(Q(message__icontains='success') | Q(message__icontains='accepted')).count()
    agents_online = Agent.objects.filter(organization=org, status=Agent.STATUS_ONLINE).count()

    mitre_counts = {}
    mitre_alerts = alerts_qs.filter(created_at__gte=last_24h).select_related('rule')
    for alert in mitre_alerts:
        mitre_json = (alert.rule.mitre_json if alert.rule else {}) or {}
        labels = []
        if isinstance(mitre_json, dict):
            if isinstance(mitre_json.get('techniques'), list):
                labels.extend([str(x) for x in mitre_json['techniques'] if x])
            if mitre_json.get('technique'):
                labels.append(str(mitre_json['technique']))
            if mitre_json.get('tactic'):
                labels.append(str(mitre_json['tactic']))
        if not labels:
            labels = ['Unknown']
        for label in labels:
            mitre_counts[label] = mitre_counts.get(label, 0) + 1

    os_distribution = {
        row['os']: row['total']
        for row in Agent.objects.filter(organization=org).values('os').annotate(total=Count('id')).order_by('-total')
    }

    top_agents = list(
        current_events
        .values(hostname=F('agent__hostname'))
        .annotate(total=Count('id'))
        .order_by('-total')[:5]
    )
    for agent in top_agents:
        agent['hostname'] = agent['hostname'] or 'Unknown agent'

    severities = {
        'Critical': lambda q: q.filter(severity__gte=9),
        'High': lambda q: q.filter(severity__gte=7, severity__lt=9),
        'Medium': lambda q: q.filter(severity__gte=4, severity__lt=7),
        'Low': lambda q: q.filter(severity__lt=4),
    }
    labels = []
    datasets = {name: [] for name in severities}
    for hour_offset in range(23, -1, -1):
        hour_end = now - timezone.timedelta(hours=hour_offset)
        hour_start = hour_end - timezone.timedelta(hours=1)
        hour_events = events_qs.filter(ts__gte=hour_start, ts__lt=hour_end)
        labels.append(hour_end.strftime('%H:%M'))
        for severity_name, filter_builder in severities.items():
            datasets[severity_name].append(filter_builder(hour_events).count())

    time_series_data = {
        'labels': labels,
        'datasets': datasets,
    }

    recent_alerts = alerts_qs.select_related('event', 'assignee').order_by('-created_at')[:12]

    ctx = {
        'kpis': {
            'total_events': total_events,
            'critical_alerts': critical_alerts,
            'auth_failures': auth_failures,
            'auth_success': auth_success,
            'agents_online': agents_online,
        },
        'trends': {
            'total_events': trend(total_events, previous_events.count()),
            'critical_alerts': trend(critical_alerts, alerts_qs.filter(created_at__gte=prev_24h, created_at__lt=last_24h, severity='Critical').count()),
            'auth_failures': trend(auth_failures, auth_previous.filter(Q(message__icontains='fail') | Q(message__icontains='invalid')).count()),
            'auth_success': trend(auth_success, auth_previous.filter(Q(message__icontains='success') | Q(message__icontains='accepted')).count()),
        },
        'mitre_distribution': mitre_counts,
        'os_distribution': os_distribution,
        'top_agents': top_agents,
        'time_series_data': json.dumps(time_series_data),
        'recent_alerts': recent_alerts,
    }
    return render(request, 'soc/dashboard.html', ctx)


@login_required
def endpoints_view(request):
    org = user_org(request.user)
    qs = Agent.objects.filter(organization=org).select_related('endpoint_risk')
    q = request.GET
    if q.get('status'):
        qs = qs.filter(status=q['status'])
    if q.get('os'):
        qs = qs.filter(os__icontains=q['os'])
    if q.get('org'):
        qs = qs.filter(organization__name__icontains=q['org'])
    if q.get('risk_min'):
        qs = qs.filter(endpoint_risk__score__gte=q['risk_min'])

    since_24h = timezone.now() - timezone.timedelta(hours=24)
    agents = qs.annotate(
        risk_score=Max('endpoint_risk__score'),
        alerts_24h=Count('logevent__alert', filter=Q(logevent__alert__created_at__gte=since_24h), distinct=True),
    ).order_by('-risk_score', '-last_seen')
    return render(request, 'soc/endpoints.html', {'agents': agents})


@login_required
def endpoint_detail_view(request, endpoint_id):
    org = user_org(request.user)
    agent = get_object_or_404(Agent, id=endpoint_id, organization=org)
    since_24h = timezone.now() - timezone.timedelta(hours=24)
    events = LogEvent.objects.filter(organization=org, agent=agent, ts__gte=since_24h).order_by('-ts')

    telemetry = list(events.filter(category='telemetry').order_by('ts').values('ts', 'raw_json'))
    chart_labels = [row['ts'].strftime('%H:%M') for row in telemetry]
    cpu_data = [row['raw_json'].get('cpu', 0) for row in telemetry]
    ram_data = [row['raw_json'].get('ram', 0) for row in telemetry]

    ctx = {
        'agent': agent,
        'risk': getattr(agent, 'endpoint_risk', None),
        'top_alerts': Alert.objects.filter(organization=org, event__agent=agent).order_by('-created_at')[:5],
        'telemetry_events': events.filter(category='telemetry')[:50],
        'user_events': events.filter(category='user_activity')[:50],
        'command_events': events.filter(category='commandline')[:50],
        'service_events': events.filter(category='service')[:50],
        'file_events': events.filter(category='file_activity')[:50],
        'alerts': Alert.objects.filter(organization=org, event__agent=agent).order_by('-created_at')[:50],
        'chart_labels': json.dumps(chart_labels),
        'chart_cpu': json.dumps(cpu_data),
        'chart_ram': json.dumps(ram_data),
    }
    return render(request, 'soc/endpoint_detail.html', ctx)


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
