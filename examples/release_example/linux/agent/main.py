import argparse
import json
import os
import platform
import socket
import time
from pathlib import Path

import yaml

from collectors import collect_cloud_metadata, collect_docker_info, collect_linux_auth, collect_windows_eventlog, system_info_event
from cursor_store import CursorStore
from enroll import enroll
from sender import send_event


def read_config(path):
    with open(path, 'r', encoding='utf-8') as fh:
        return yaml.safe_load(fh)


def resolve_secret_path(config_path):
    if os.name == 'nt':
        return Path('C:/ProgramData/AgentNocturno/secret.json')
    return Path('/etc/agent-nocturno/agent-secret.json')


def get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return '127.0.0.1'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='config.yml')
    args = parser.parse_args()

    cfg = read_config(args.config)
    secret_path = resolve_secret_path(args.config)
    cursor_path = secret_path.parent / 'cursor.json'

    if secret_path.exists():
        agent_key = json.loads(secret_path.read_text(encoding='utf-8')).get('agent_key')
    else:
        agent_key = enroll(cfg['soc_url'], cfg['enrollment_token'], platform.platform(), get_ip(), cfg.get('verify_tls', True), str(secret_path))

    store = CursorStore(cursor_path)

    while True:
        cursor = store.load()
        events = [system_info_event()]
        linux_events, cursor = collect_linux_auth(cursor)
        windows_events, cursor = collect_windows_eventlog(cursor)
        events.extend(linux_events)
        events.extend(windows_events)
        events.extend(collect_docker_info())
        events.extend(collect_cloud_metadata())

        for event in events:
            send_event(cfg['soc_url'], agent_key, event, cfg.get('verify_tls', True))
        store.save(cursor)
        time.sleep(int(cfg.get('interval', 60)))


if __name__ == '__main__':
    main()
