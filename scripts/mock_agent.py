import random
import requests
from datetime import datetime, UTC

BASE = 'http://localhost:8000'
TOKEN = 'PUT_ENROLLMENT_TOKEN'

cats = [
    ('auth', 'Login failed for user admin', 6),
    ('auth', 'Login success for user admin', 4),
    ('network', 'port scan detected from source', 7),
    ('malware', 'malware signature match trojan', 9),
]


def main():
    enroll = requests.post(f'{BASE}/api/agents/enroll/', json={
        'token': TOKEN,
        'hostname': 'demo-agent-01',
        'os': 'linux',
        'ip': '10.10.10.5',
    }, timeout=10)
    enroll.raise_for_status()
    data = enroll.json()
    key = data['agent_key']

    for i in range(200):
        c, msg, sev = random.choice(cats)
        payload = {
            'ts': datetime.now(UTC).isoformat(),
            'source': 'mock_agent',
            'severity': sev,
            'category': c,
            'message': msg,
            'user': random.choice(['admin', 'root', 'svc-backup', 'analyst']),
            'ip': f'192.168.1.{random.randint(1, 220)}',
            'host': 'server-lab-1',
            'raw': {'event_no': i},
        }
        r = requests.post(f'{BASE}/api/ingest/', json=payload, headers={'X-AGENT-KEY': key}, timeout=10)
        print(i, r.status_code)


if __name__ == '__main__':
    main()
