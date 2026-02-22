import os
import platform
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import psutil


def _now():
    return datetime.now(timezone.utc).isoformat()


def _top_processes(limit=5):
    procs = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            info = proc.info
            procs.append({
                'pid': info['pid'],
                'name': info['name'],
                'cpu': info.get('cpu_percent') or 0,
                'mem': round(info.get('memory_percent') or 0, 2),
            })
        except Exception:
            continue
    return sorted(procs, key=lambda item: (item['cpu'], item['mem']), reverse=True)[:limit]


def system_info_event():
    net = psutil.net_io_counters()
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
            'net_bytes_sent': net.bytes_sent,
            'net_bytes_recv': net.bytes_recv,
            'hostname': socket.gethostname(),
            'os': platform.platform(),
            'ip': socket.gethostbyname(socket.gethostname()),
            'top_processes': _top_processes(),
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
            for line in fh.readlines()[-300:]:
                events.append({'ts': _now(), 'source': 'linux.auth', 'severity': 5, 'category': 'auth', 'message': line.strip(), 'host': socket.gethostname(), 'raw': {'path': path}})
            cursor[path] = fh.tell()
    return events, cursor


def _read_windows_channel(channel, cursor):
    marker = f'win:{channel}'
    last_record = int(cursor.get(marker, 0))
    cmd = ['wevtutil', 'qe', channel, '/f:text', '/c:20', '/rd:true']
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return [], last_record

    events = []
    blocks = [b.strip() for b in result.stdout.split('\n\n') if 'Record ID:' in b]
    newest = last_record
    for block in reversed(blocks):
        rec_id = 0
        for line in block.splitlines():
            if line.startswith('Record ID:'):
                rec_id = int(line.split(':', 1)[1].strip())
                break
        if rec_id <= last_record:
            continue
        newest = max(newest, rec_id)
        compact = ' | '.join(line.strip() for line in block.splitlines() if line.strip())
        events.append({'ts': _now(), 'source': f'windows.{channel.lower()}', 'severity': 5, 'category': 'windows_eventlog', 'message': compact[:4000], 'host': socket.gethostname(), 'raw': {'channel': channel, 'record_id': rec_id}})
    return events, newest


def collect_windows_eventlog(cursor):
    if os.name != 'nt':
        return [], cursor

    all_events = []
    for channel in ['Security', 'System', 'Application']:
        channel_events, newest = _read_windows_channel(channel, cursor)
        cursor[f'win:{channel}'] = newest
        all_events.extend(channel_events)
    return all_events, cursor
