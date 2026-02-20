#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8000}"

if [[ -n "${DJANGO_WSGI_MODULE:-}" ]]; then
  WSGI_MODULE="${DJANGO_WSGI_MODULE}"
else
  WSGI_MODULE="$(python - <<'PY'
import pathlib
import re

root = pathlib.Path('.').resolve()
manage_py = root / 'manage.py'
module_candidates = []

if manage_py.exists():
    text = manage_py.read_text(encoding='utf-8')
    match = re.search(r"DJANGO_SETTINGS_MODULE'\s*,\s*'([^']+)'", text)
    if match:
        settings_module = match.group(1)
        if settings_module.endswith('.settings'):
            base_module = settings_module.rsplit('.', 1)[0]
            module_candidates.append(f"{base_module}.wsgi")

for candidate in ('config.wsgi', 'buho.wsgi'):
    if candidate not in module_candidates:
        module_candidates.append(candidate)

for candidate in module_candidates:
    mod_path = root / pathlib.Path(*candidate.split('.')).with_suffix('.py')
    if mod_path.exists():
        print(candidate)
        raise SystemExit(0)

for wsgi_path in root.glob('*/wsgi.py'):
    print(f"{wsgi_path.parent.name}.wsgi")
    raise SystemExit(0)

raise SystemExit('No se encontró un módulo WSGI válido. Define DJANGO_WSGI_MODULE.')
PY
)"
fi

echo "[entrypoint] Running migrations..."
python manage.py migrate --noinput

echo "[entrypoint] Collecting static files..."
python manage.py collectstatic --noinput

echo "[entrypoint] Starting gunicorn with ${WSGI_MODULE}:application on 0.0.0.0:${PORT}"
exec gunicorn "${WSGI_MODULE}:application" --bind "0.0.0.0:${PORT}"
