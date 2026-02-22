import time

import requests


def send_event(soc_url, agent_key, payload, verify_tls=True, retries=5):
    url = f"{soc_url.rstrip('/')}/api/ingest/"
    headers = {'X-AGENT-KEY': agent_key, 'Content-Type': 'application/json'}

    delay = 1
    for _ in range(retries):
        try:
            res = requests.post(url, json=payload, headers=headers, timeout=10, verify=verify_tls)
            if res.status_code < 300:
                return True
        except Exception:
            pass
        time.sleep(delay)
        delay = min(delay * 2, 30)
    return False
