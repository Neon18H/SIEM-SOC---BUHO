import csv
import io
import json
import re
from datetime import timedelta

from django.db.models import Count
from django.utils import timezone

from .models import Alert, CorrelationRecord, EndpointRisk, IOC, LogEvent, ParsingError, Rule

MITRE_MAPPING = {
    'brute_force': ('Credential Access', 'T1110'),
    'suspicious_execution': ('Execution', 'T1059'),
    'new_admin_user': ('Persistence', 'T1136'),
    'suspicious_powershell': ('Execution', 'T1059.001'),
}


def normalize_payload(payload: dict):
    parsed = {
        'timestamp': payload.get('ts').isoformat() if hasattr(payload.get('ts'), 'isoformat') else payload.get('ts'),
        'ip': payload.get('ip'),
        'user': payload.get('user', ''),
        'host': payload.get('host', ''),
        'action': None,
        'outcome': None,
    }
    msg = (payload.get('message') or '').lower()
    if 'login' in msg:
        parsed['action'] = 'login'
        parsed['outcome'] = 'failure' if any(x in msg for x in ['fail', 'denied', 'invalid']) else 'success'
    if 'port scan' in msg:
        parsed['action'] = 'network_scan'
    if 'malware' in msg:
        parsed['action'] = 'malware_detected'

    raw = payload.get('raw') or {}
    if isinstance(raw, dict):
        parsed.update(raw)
    return parsed


def evaluate_rules(event: LogEvent):
    rules = Rule.objects.filter(organization=event.organization, enabled=True)
    created = []
    for rule in rules:
        c = rule.condition_json
        ok = True
        if c.get('category_equals') and event.category != c['category_equals']:
            ok = False
        if c.get('severity_gte') is not None and event.severity < int(c['severity_gte']):
            ok = False
        if c.get('message_contains') and c['message_contains'].lower() not in event.message.lower():
            ok = False
        if c.get('user_equals') and event.user != c['user_equals']:
            ok = False
        if c.get('ip_equals') and str(event.ip) != c['ip_equals']:
            ok = False
        if c.get('tag_contains') and c['tag_contains'] not in (event.tags or []):
            ok = False
        if c.get('regex_match') and not re.search(c['regex_match'], event.message):
            ok = False
        if ok:
            created.append(Alert.objects.create(
                organization=event.organization,
                event=event,
                rule=rule,
                severity=rule.severity if rule.severity in ['Low', 'Medium', 'High', 'Critical'] else 'Medium',
                title=f"Rule match: {rule.name}",
                details=json.dumps(rule.mitre_json),
            ))
    return created


def correlate_login_pattern(org, event: LogEvent):
    if event.parsed_json.get('action') != 'login':
        return None
    user = event.user
    ip = str(event.ip) if event.ip else None
    if not user and not ip:
        return None

    window_start = event.ts - timedelta(minutes=30)
    base = LogEvent.objects.filter(organization=org, ts__gte=window_start, ts__lte=event.ts, category='auth')
    if user:
        base = base.filter(user=user)
    elif ip:
        base = base.filter(ip=ip)

    failures = base.filter(parsed_json__outcome='failure').count()
    success = base.filter(parsed_json__outcome='success').order_by('-ts').first()
    if failures >= 5 and success and success.id == event.id:
        corr = CorrelationRecord.objects.create(
            organization=org,
            name='5 failed logins + 1 success',
            window_start=window_start,
            window_end=event.ts,
            keys_json={'user': user, 'ip': ip},
        )
        corr.matched_events.set(base)
        Alert.objects.create(
            organization=org,
            event=event,
            severity='High',
            title='Correlation: Brute force likely succeeded',
            details=f'user={user} ip={ip}',
        )
        return corr
    return None


def enrich_with_ioc(event: LogEvent):
    hits = []
    if event.ip:
        hits.extend(list(IOC.objects.filter(type='ip', value=str(event.ip)).values_list('value', flat=True)))
        hits.extend(list(IOC.objects.filter(organization=event.organization, type='ip', value=str(event.ip)).values_list('value', flat=True)))
    msg = event.message.lower()
    for ioc in IOC.objects.filter(type='domain'):
        if ioc.value.lower() in msg:
            hits.append(ioc.value)
    if hits:
        tags = set(event.tags or [])
        tags.update([f'ioc:{h}' for h in hits])
        event.tags = list(tags)
        event.enriched = True
        if event.severity < 8:
            event.severity = min(10, event.severity + 2)
        event.save(update_fields=['tags', 'enriched', 'severity'])
        Alert.objects.create(
            organization=event.organization,
            event=event,
            severity='High',
            title='Threat Intel match',
            details=', '.join(hits),
        )


def _to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _append_risk(agent, points, reason):
    endpoint_risk, _ = EndpointRisk.objects.get_or_create(organization=agent.organization, agent=agent)
    reasons = list(endpoint_risk.reasons or [])
    reasons.append({
        'ts': timezone.now().isoformat(),
        'reason': reason,
        'points': points,
    })
    endpoint_risk.reasons = reasons[-20:]
    endpoint_risk.score = min(100, endpoint_risk.score + points)
    endpoint_risk.save(update_fields=['score', 'reasons', 'updated_at'])


def _create_detection_alert(event, key, title, details=''):
    tactic, technique_id = MITRE_MAPPING.get(key, ('', ''))
    return Alert.objects.create(
        organization=event.organization,
        event=event,
        severity='High',
        title=title,
        details=details,
        mitre_tactic=tactic,
        mitre_technique_id=technique_id,
    )


def process_endpoint_event(event: LogEvent):
    raw = event.raw_json if isinstance(event.raw_json, dict) else {}
    category = (event.category or '').lower()

    if category == 'telemetry':
        agent = event.agent
        agent.current_cpu = _to_float(raw.get('cpu'))
        agent.current_ram = _to_float(raw.get('ram'))
        agent.current_disk = _to_float(raw.get('disk'))
        agent.current_gpu = _to_float(raw.get('gpu'))
        agent.save(update_fields=['current_cpu', 'current_ram', 'current_disk', 'current_gpu'])

    if category == 'user_activity':
        action = (raw.get('action') or '').lower()
        role = (raw.get('role') or '').lower()
        if action in {'admin_added', 'role_elevated'} or (action == 'new_user' and role == 'admin'):
            _append_risk(event.agent, 15, 'new admin user detected')
            _create_detection_alert(event, 'new_admin_user', 'New admin user detected', json.dumps(raw))

        if action == 'failed_login':
            window_start = event.ts - timedelta(minutes=10)
            fails = LogEvent.objects.filter(
                organization=event.organization,
                agent=event.agent,
                category='user_activity',
                ts__gte=window_start,
                raw_json__action='failed_login',
            ).count()
            if fails >= 5:
                _append_risk(event.agent, 10, 'brute-force pattern')
                _create_detection_alert(event, 'brute_force', 'Brute force pattern detected', f'failed logins={fails}')

    if category == 'commandline':
        cmd = (raw.get('cmd') or event.message or '').lower()
        if 'encodedcommand' in cmd or ('bash' in cmd and any(k in cmd for k in ['curl ', 'wget ', 'base64 -d'])):
            _append_risk(event.agent, 8, 'suspicious shell execution')
            _create_detection_alert(event, 'suspicious_powershell', 'Suspicious command line detected', cmd)

    if category == 'file_activity':
        action = (raw.get('action') or '').lower()
        path = (raw.get('path') or '').lower()
        if action == 'execute' and any(temp_path in path for temp_path in ['/tmp/', '\\temp\\', '/var/tmp/']):
            _append_risk(event.agent, 5, 'execution from temp path')
            recent_cpu = LogEvent.objects.filter(
                organization=event.organization,
                agent=event.agent,
                category='telemetry',
                ts__gte=event.ts - timedelta(minutes=5),
                raw_json__cpu__gte=80,
            ).exists()
            outbound = LogEvent.objects.filter(
                organization=event.organization,
                agent=event.agent,
                category='network',
                ts__gte=event.ts - timedelta(minutes=10),
            ).exclude(raw_json__dst_ip__startswith='10.').exists()
            if recent_cpu and outbound:
                _create_detection_alert(event, 'suspicious_execution', 'Suspicious execution chain', json.dumps(raw))


def import_iocs(org, content: str, file_type: str):
    if file_type == 'json':
        data = json.loads(content)
    else:
        reader = csv.DictReader(io.StringIO(content))
        data = list(reader)
    created = 0
    for row in data:
        _, was_created = IOC.objects.get_or_create(
            organization=org,
            type=row['type'],
            value=row['value'],
            defaults={
                'source': row.get('source', 'import'),
                'confidence': int(row.get('confidence', 50)),
            },
        )
        created += 1 if was_created else 0
    return created


def register_parsing_error(org, payload, error):
    ParsingError.objects.create(organization=org, raw_payload=payload, error=str(error))


def kpis_for_org(org):
    today = timezone.now().date()
    return {
        'events_today': LogEvent.objects.filter(organization=org, ts__date=today).count(),
        'new_alerts': Alert.objects.filter(organization=org, status='new').count(),
        'agents_online': org.agent_set.filter(status='online').count(),
        'top_categories': list(
            LogEvent.objects.filter(organization=org)
            .values('category')
            .annotate(total=Count('id'))
            .order_by('-total')[:5]
        ),
    }
