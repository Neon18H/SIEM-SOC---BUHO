import argparse
import json
import logging
import os
import platform
import socket
import time
from pathlib import Path

import yaml

from collectors import collect_linux_auth, collect_windows_eventlog, system_info_event
from cursor_store import CursorStore
from enroll import enroll
from sender import send_event


LOGGER = logging.getLogger('agent-nocturno')


def read_config(path):
    with open(path, 'r', encoding='utf-8') as fh:
        return yaml.safe_load(fh)


def resolve_state_paths():
    if os.name == 'nt':
        base = Path('C:/ProgramData/AgentNocturno')
    else:
        base = Path('/etc/agent-nocturno')
    base.mkdir(parents=True, exist_ok=True)
    return base / 'agent-secret.json', base / 'cursor.json'


def resolve_log_file():
    if os.name == 'nt':
        log_path = Path('C:/ProgramData/AgentNocturno/agent.log')
    else:
        log_path = Path('/var/log/agent-nocturno/agent.log')
    log_path.parent.mkdir(parents=True, exist_ok=True)
    return log_path


def setup_logging():
    log_file = resolve_log_file()
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
        handlers=[logging.FileHandler(log_file, encoding='utf-8'), logging.StreamHandler()],
    )


def get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return '127.0.0.1'


def ensure_agent_key(cfg, secret_path):
    if secret_path.exists():
        data = json.loads(secret_path.read_text(encoding='utf-8') or '{}')
        key = data.get('agent_key')
        if key:
            return key

    LOGGER.info('Agent key no encontrado, iniciando enrollment automático')
    return enroll(cfg['soc_url'], cfg['enrollment_token'], platform.platform(), get_ip(), cfg.get('verify_tls', True), str(secret_path))


def main():
    setup_logging()
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='config.yml')
    args = parser.parse_args()

    cfg = read_config(args.config)
    secret_path, cursor_path = resolve_state_paths()
    interval = int(cfg.get('interval', 10))
    store = CursorStore(cursor_path)

    while True:
        try:
            agent_key = ensure_agent_key(cfg, secret_path)
            cursor = store.load()
            events = [system_info_event()]
            linux_events, cursor = collect_linux_auth(cursor)
            windows_events, cursor = collect_windows_eventlog(cursor)
            events.extend(linux_events)
            events.extend(windows_events)

            for event in events:
                send_event(cfg['soc_url'], agent_key, event, cfg.get('verify_tls', True))
            store.save(cursor)
            LOGGER.info('Ciclo completado. eventos_enviados=%s', len(events))
        except Exception as exc:
            LOGGER.exception('Error en loop principal: %s', exc)

        time.sleep(interval)


if __name__ == '__main__':
    main()
