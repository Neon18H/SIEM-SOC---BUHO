from collections import defaultdict

from django.contrib.auth.decorators import login_required
from django.db.models import Avg, Count, Q
from django.db.models.functions import TruncHour
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone

from .auth import user_org
from .models import Agent, Alert, LogEvent


RANGE_MAP = {
    '1h': timezone.timedelta(hours=1),
    '24h': timezone.timedelta(hours=24),
    '7d': timezone.timedelta(days=7),
}


def _range_start(range_name: str):
    window = RANGE_MAP.get(range_name, RANGE_MAP['24h'])
    return timezone.now() - window


def _get_agent_or_404(request, agent_id: int):
    org = user_org(request.user)
    return get_object_or_404(Agent, id=agent_id, organization=org), org


def _event_risk_points(event: LogEvent) -> int:
    category = (event.category or '').lower()
    message = (event.message or '').lower()
    tags = [str(tag).lower() for tag in (event.tags or [])]

    score = 0
    if 'auth' in category and ('fail' in message or 'invalid' in message or 'denied' in message):
        score += 20
    if any(token in message for token in ['sudo', 'admin', 'privilege']) or 'privilege' in category:
        score += 25
    if any(token in message for token in ['encodedcommand', 'powershell -enc', 'wget ', 'curl ', 'net user', 'mimikatz']):
        score += 30
    if any(token in message for token in ['/tmp', '\\temp\\', 'appdata\\local\\temp', 'temp\\']) or 'temp_exec' in tags:
        score += 25
    if any(token in tags for token in ['auth_failure', 'suspicious', 'privilege']):
        score += 10

    return min(score, 100)


@login_required
def uba_summary_api(request, agent_id):
    agent, org = _get_agent_or_404(request, agent_id)
    since = _range_start(request.GET.get('range', '24h'))
    events = LogEvent.objects.filter(organization=org, agent=agent, ts__gte=since)
    alerts = Alert.objects.filter(organization=org, event__agent=agent, created_at__gte=since)

    users = events.exclude(user='').values('user').distinct().count()
    monitored_users = events.exclude(user='').values('user').annotate(total=Count('id'))
    max_user_events = max([row['total'] for row in monitored_users], default=1)
    risk_estimate = min(100, int((alerts.count() * 12) + (max_user_events * 4)))

    payload = {
        'agent_id': agent.id,
        'endpoint': agent.hostname,
        'window': request.GET.get('range', '24h'),
        'total_events': events.count(),
        'monitored_users': users,
        'offenses': alerts.count(),
        'avg_severity': round(events.aggregate(avg=Avg('severity'))['avg'] or 0, 2),
        'system_risk_score': risk_estimate,
    }
    return JsonResponse(payload)


@login_required
def uba_users_api(request, agent_id):
    agent, org = _get_agent_or_404(request, agent_id)
    since = _range_start(request.GET.get('range', '24h'))
    events = LogEvent.objects.filter(organization=org, agent=agent, ts__gte=since).exclude(user='')

    users_payload = []
    for user_name in events.values_list('user', flat=True).distinct():
        user_events = events.filter(user=user_name)
        points = sum(_event_risk_points(evt) for evt in user_events[:200])
        normalized_risk = min(100, int(points / max(user_events.count(), 1)))
        users_payload.append({
            'user': user_name,
            'events': user_events.count(),
            'risk_score': normalized_risk,
            'failed_logins': user_events.filter(
                Q(category__icontains='auth')
                & (Q(message__icontains='fail') | Q(message__icontains='invalid') | Q(message__icontains='denied'))
            ).count(),
            'last_seen': user_events.order_by('-ts').values_list('ts', flat=True).first(),
        })

    users_payload.sort(key=lambda row: (-row['risk_score'], -row['events']))
    return JsonResponse({'items': users_payload[:15]})


@login_required
def uba_offenses_api(request, agent_id):
    agent, org = _get_agent_or_404(request, agent_id)
    since = _range_start(request.GET.get('range', '24h'))
    alerts = Alert.objects.filter(organization=org, event__agent=agent, created_at__gte=since).select_related('rule').order_by('-created_at')

    items = []
    for alert in alerts[:25]:
        technique = alert.mitre_technique_id or (alert.rule.mitre_json.get('technique') if alert.rule and isinstance(alert.rule.mitre_json, dict) else '')
        items.append({
            'id': alert.id,
            'title': alert.title,
            'severity': alert.severity,
            'rule': alert.rule.name if alert.rule else 'Unknown rule',
            'technique': technique or 'N/A',
            'created_at': alert.created_at,
        })

    return JsonResponse({'items': items})


@login_required
def uba_score_series_api(request, agent_id):
    agent, org = _get_agent_or_404(request, agent_id)
    since = _range_start(request.GET.get('range', '24h'))
    events = LogEvent.objects.filter(organization=org, agent=agent, ts__gte=since)

    buckets = (
        events.annotate(hour=TruncHour('ts'))
        .values('hour')
        .annotate(avg_severity=Avg('severity'), total=Count('id'))
        .order_by('hour')
    )
    labels = []
    values = []
    for row in buckets:
        score = min(100, int((row['avg_severity'] or 0) * 10 + row['total'] * 2))
        labels.append(row['hour'].strftime('%d %b %H:%M'))
        values.append(score)

    return JsonResponse({'labels': labels, 'series': values})


@login_required
def uba_risk_breakdown_api(request, agent_id):
    agent, org = _get_agent_or_404(request, agent_id)
    since = _range_start(request.GET.get('range', '24h'))
    events = LogEvent.objects.filter(organization=org, agent=agent, ts__gte=since)

    breakdown = defaultdict(int)
    for event in events[:500]:
        category = (event.category or '').lower()
        message = (event.message or '').lower()
        tags = [str(tag).lower() for tag in (event.tags or [])]

        if event.user:
            breakdown['user_risk'] += 1
        if 'auth' in category or 'login' in message:
            breakdown['auth_risk'] += 1
        if 'privilege' in category or 'sudo' in message or 'admin' in message:
            breakdown['privilege_risk'] += 1
        if 'process' in category or 'command' in category or 'powershell' in message:
            breakdown['process_risk'] += 1
        if 'network' in category or 'dns' in message or 'connection' in message or 'network' in tags:
            breakdown['network_risk'] += 1

    keys = ['user_risk', 'auth_risk', 'privilege_risk', 'process_risk', 'network_risk']
    return JsonResponse({'labels': keys, 'values': [breakdown[key] for key in keys]})
