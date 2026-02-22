import os
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path

import psutil


def _now():
    return datetime.now(timezone.utc).isoformat()


def system_info_event():
    return {
        'ts': _now(),
        'source': 'agent.system',
        'severity': 2,
        'category': 'system_info',
        'message': 'system snapshot',
        'host': socket.gethostname(),
        'raw': {
            'cpu_percent': psutil.cpu_percent(interval=0.2),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'hostname': socket.gethostname(),
            'os': platform.platform(),
            'ip': socket.gethostbyname(socket.gethostname()),
        },
    }


def collect_linux_auth(cursor):
    events = []
    for path in ['/var/log/auth.log', '/var/log/secure']:
        file = Path(path)
        if not file.exists():
            continue
        last = cursor.get(path, 0)
        with file.open('r', encoding='utf-8', errors='ignore') as fh:
            fh.seek(last)
            for line in fh.readlines()[-200:]:
                events.append({'ts': _now(), 'source': 'linux.auth', 'severity': 5, 'category': 'auth', 'message': line.strip(), 'host': socket.gethostname(), 'raw': {'path': path}})
            cursor[path] = fh.tell()
    return events, cursor


def collect_windows_eventlog(cursor):
    if os.name != 'nt':
        return [], cursor
    return [], cursor


def collect_docker_info():
    docker_sock = Path('/var/run/docker.sock')
    if docker_sock.exists():
        return [{'ts': _now(), 'source': 'docker', 'severity': 3, 'category': 'docker', 'message': 'docker socket present', 'raw': {'socket': str(docker_sock)}}]
    return []


def collect_cloud_metadata():
    return []
