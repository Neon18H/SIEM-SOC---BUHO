import json
import socket
from pathlib import Path

import requests


def enroll(soc_url, token, os_name, ip, verify_tls=True, secret_file='secret.json'):
    payload = {'token': token, 'hostname': socket.gethostname(), 'os': os_name, 'ip': ip}
    res = requests.post(f"{soc_url.rstrip('/')}/api/agents/enroll/", json=payload, timeout=15, verify=verify_tls)
    res.raise_for_status()
    data = res.json()
    Path(secret_file).write_text(json.dumps({'agent_key': data['agent_key']}), encoding='utf-8')
    return data['agent_key']
