# Agente Nocturno (SIEM web estilo Wazuh)

SIEM MVP multi-tenant construido con **Django 5 + DRF + Bootstrap 5 + HTMX + PostgreSQL**, preparado para desplegarse en Railway.

## Arquitectura
- Backend: Django 5.x, DRF, JWT
- DB: PostgreSQL (Railway plugin) usando `DATABASE_URL` con SSL obligatorio
- Front: Bootstrap 5 dark SOC + CSS propio + HTMX + Chart.js
- Jobs: comando de retención `purge_old_logs` (Celery/Redis opcional preparado por settings)
- Seguridad: CSRF web, JWT API usuarios, `X-AGENT-KEY` para agentes, throttling DRF en ingest

---

## Fase 1 — Scaffolding + auth/roles/org + layout dark + Railway base

### Archivos creados/modificados
- `manage.py`
- `config/settings.py`, `config/urls.py`, `config/wsgi.py`, `config/asgi.py`, `config/celery.py`
- `soc/models.py`, `soc/signals.py`, `soc/apps.py`, `soc/admin.py`
- `templates/base.html`, `templates/registration/login.html`
- `static/css/soc.css`
- `requirements.txt`, `Procfile`, `runtime.txt`

### Local
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

### Pruebas curl
```bash
curl -X POST http://localhost:8000/api/token/ -H 'Content-Type: application/json' -d '{"username":"admin","password":"***"}'
```

---

## Fase 2 — Agentes + tokens + enroll + ingest + tabla eventos

### Incluye
- Endpoint enroll: `POST /api/agents/enroll/`
- Endpoint ingest: `POST /api/ingest/` con `X-AGENT-KEY`
- Modelo `Agent`, `EnrollmentToken`, `LogEvent`
- Listado eventos API `GET /api/events/`

### Curl
```bash
curl -X POST http://localhost:8000/api/agents/enroll/ -H 'Content-Type: application/json' -d '{"token":"TOKEN","hostname":"host1","os":"linux","ip":"10.0.0.8"}'

curl -X POST http://localhost:8000/api/ingest/ \
  -H 'X-AGENT-KEY: AGENT_KEY' -H 'Content-Type: application/json' \
  -d '{"ts":"2026-01-01T10:00:00Z","source":"syslog","severity":7,"category":"auth","message":"Login failed","user":"admin","ip":"1.2.3.4","host":"srv1","raw":{"line":"..."}}'
```

---

## Fase 3 — Normalización/parsing + hunting + pivots

### Incluye
- Parser robusto `normalize_payload`
- Registro de errores sin romper ingesta (`ParsingError`)
- Vista `/hunting` con filtros: rango, ip/user/host, severidad, texto, categoría
- Pivot rápido por IP y User desde resultados

### Curl
```bash
curl -H 'Authorization: Bearer <JWT>' 'http://localhost:8000/api/events/?ip=1.2.3.4&severity_min=5'
```

---

## Fase 4 — Reglas + alertas + dashboard + métricas/gráficas

### Incluye
- CRUD `/api/rules/`
- Motor de reglas por `condition_json` (+ MITRE en `mitre_json`)
- Alertas y CRUD `/api/alerts/`
- Dashboard `/` con KPIs y Chart.js
- HTMX para cambio de estado de alertas sin recargar
- `GET /api/metrics/`

### Ejemplo regla
```json
{
  "name": "High auth failures",
  "enabled": true,
  "condition_json": {
    "category_equals": "auth",
    "severity_gte": 7,
    "message_contains": "failed"
  },
  "mitre_json": {"tactic":"Credential Access","technique_id":"T1110","technique_name":"Brute Force"},
  "severity": "High"
}
```

---

## Fase 5 — Correlación + Threat Intel + Cases + IR + retención

### Incluye
- Correlación MVP: `5 fallos login + 1 éxito posterior` => `CorrelationRecord` + alerta
- IOC + importador `/api/threatintel/import/` (JSON/CSV en campo `content`)
- Enriquecimiento en ingest (tags `ioc:*`, `enriched=true`, posible subida severidad)
- Casos CRUD `/api/cases/`
- Acciones IR simuladas (`block_ip`, `disable_account`) con estado `pending/executed/failed`
- Comando `python manage.py purge_old_logs`

### Curl TI
```bash
curl -X POST http://localhost:8000/api/threatintel/import/ \
 -H 'Authorization: Bearer <JWT>' -H 'Content-Type: application/json' \
 -d '{"file_type":"json","content":"[{""type"":""ip"",""value"":""1.2.3.4"",""source"":""abuseipdb"",""confidence"":90}]"}'
```

---

## Fase 6 — Hardening + tests básicos + documentación + demo script

### Incluye
- Throttling DRF para ingest (`ingest` scope)
- Roles por `UserProfile` (Admin/Analyst/Viewer)
- Multi-tenancy por `organization` en querysets API/UI
- `soc/tests.py` básico
- Script demo `/scripts/mock_agent.py` (enroll + envío 200 eventos)

### Demo
```bash
python scripts/mock_agent.py
```

---

## Endpoints mínimos implementados
- `POST /api/agents/enroll/`
- `POST /api/ingest/`
- `GET /api/events/`
- `GET /api/metrics/`
- CRUD `/api/rules/`
- CRUD `/api/alerts/`
- CRUD `/api/cases/`
- `POST /api/threatintel/import/`

---

## Despliegue Railway (obligatorio)

1. Crear proyecto en Railway.
2. Conectar repo.
3. Agregar plugin PostgreSQL.
4. Variables de entorno:
   - `DATABASE_URL` (la inyecta Railway automáticamente al agregar PostgreSQL)
   - `SECRET_KEY`
   - `DEBUG=False`
   - `DJANGO_ALLOWED_HOSTS=buho-ob-production.up.railway.app,.railway.app,localhost,127.0.0.1`
   - `DJANGO_CSRF_TRUSTED_ORIGINS=https://buho-ob-production.up.railway.app`
5. El comando de arranque queda en `Procfile`:
   ```bash
   web: gunicorn config.wsgi:application --bind 0.0.0.0:$PORT
   ```
6. Ejecutar una vez en Railway shell:
   ```bash
   python manage.py migrate
   python manage.py collectstatic --noinput
   ```
7. Confirmar conexión a PostgreSQL revisando logs del deploy y ejecutando:
   ```bash
   python manage.py dbshell
   ```

### Static en Railway
- WhiteNoise activado (`WhiteNoiseMiddleware` + `CompressedManifestStaticFilesStorage`).

---

## Notas de seguridad
- Hashing de passwords: estándar Django.
- CSRF activo en vistas web.
- JWT para usuarios API.
- `X-AGENT-KEY` para ingest de agentes.
- Separación de datos por organización en todas las vistas/endpoint principales.
