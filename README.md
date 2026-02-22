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
   - `DJANGO_ALLOWED_HOSTS=.up.railway.app,localhost,127.0.0.1`
   - `DJANGO_CSRF_TRUSTED_ORIGINS=https://*.up.railway.app`
   - `DJANGO_SECURE_PROXY_SSL_HEADER=true`
   - `DJANGO_SECURE_SSL_REDIRECT=false` (luego se puede cambiar a `true`)
5. Comandos de deploy en `Procfile`:
   ```bash
   web: bash scripts/entrypoint.sh
   ```
6. Asegúrate de que el entrypoint sea ejecutable:
   ```bash
   chmod +x scripts/entrypoint.sh
   ```
7. Si necesitas ejecutarlos manualmente en Railway shell:
   ```bash
   python manage.py migrate
   python manage.py collectstatic --noinput
   ```
8. Confirmar conexión a PostgreSQL revisando logs del deploy y ejecutando:
   ```bash
   python manage.py dbshell
   ```

### Entrypoint Railway
- El script `scripts/entrypoint.sh` ejecuta `migrate`, `collectstatic` y luego arranca Gunicorn.
- Detecta automáticamente el módulo WSGI (por ejemplo `config.wsgi` o `buho.wsgi`) a partir de `manage.py` o rutas disponibles.
- Puedes forzar el módulo con la variable de entorno `DJANGO_WSGI_MODULE` si necesitas sobreescribir la detección automática.

### Static en Railway
- WhiteNoise activado (`WhiteNoiseMiddleware` + `CompressedManifestStaticFilesStorage`).

---

## Notas de seguridad
- Hashing de passwords: estándar Django.
- CSRF activo en vistas web.
- JWT para usuarios API.
- `X-AGENT-KEY` para ingest de agentes.
- Separación de datos por organización en todas las vistas/endpoint principales.

---

## Centro de Descargas del Agente

### URLs
- `GET /agents/downloads/`
- `GET /agents/downloads/installer/<platform>/`
- `GET /agents/downloads/bundle/<platform>/`

### Cómo publicar un release
1. Inicia sesión como admin y abre `/admin`.
2. Crea un `AgentRelease` con plataforma (`linux` o `windows`), versión y notas.
3. Sube el instalador en el campo `file` (se guarda en `MEDIA_ROOT/agents/`), o define `file_url` si usas storage externo.
4. Calcula el SHA256 y guárdalo en el campo `sha256`:
   ```bash
   sha256sum ./agente-nocturno-linux-x86_64
   ```
5. Marca `is_active=True` en el release que quieres publicar para esa plataforma.
6. (Opcional) Desactiva releases anteriores de la misma plataforma para evitar ambigüedad.

### Notas operativas
- La descarga rápida crea un `EnrollmentToken` de 24 horas para la organización del usuario.
- Cada descarga genera auditoría en `DownloadAudit` con usuario, organización, IP, user agent y tipo (`installer`/`bundle`).
- Las vistas de descarga requieren login y aplican rate-limit básico por usuario/plataforma.

## Centro de Descargas funcional (Wazuh-like)

### Publicar releases (admin)
1. Entrar a `GET /agents/releases/`.
2. Cargar release por plataforma (`linux` o `windows`) con versión y archivo (`.tar.gz` Linux / `.zip` Windows).
3. El archivo se guarda en `MEDIA_ROOT/agents/` automáticamente.
4. El SHA256 se calcula automáticamente al guardar.
5. Activar release. El sistema garantiza solo 1 activo por plataforma.

### Seed rápido para publicar releases por defecto
```bash
python manage.py publish_default_releases
```
Busca archivos existentes (`examples/releases/*` o `agent_releases/*`). Si no existen, empaqueta automáticamente `examples/release_example/linux` y `examples/release_example/windows` y publica un release activo por plataforma.

### Descargas
- Instalador activo: `GET /agents/downloads/installer/<platform>`
- Bundle preconfigurado: `GET /agents/downloads/bundle/<platform>`
  - Crea `EnrollmentToken` de 24h para la organización del usuario autenticado.
  - Registra auditoría en `DownloadAudit`.
  - Estructura del bundle Linux (`.tar.gz`):
    - `config.yml`
    - `install.sh`
    - `README-quickstart.txt`
    - `agent/main.py`, `agent/enroll.py`, `agent/sender.py`, `agent/collectors.py`, `agent/cursor_store.py`, `agent/requirements.txt`
    - `payload/*` (contenido del release activo, si existe)
  - Estructura del bundle Windows (`.zip`):
    - `config.yml`
    - `install.ps1`
    - `README-quickstart.txt`
    - `agent/*` (MVP Python)
    - `agent/nssm.exe`
    - `payload/*` (contenido del release activo, si existe)

### Agente MVP empaquetable
Carpeta: `agent_mvp/`
- `main.py`: loop de telemetría cada N segundos
- `collectors.py`: system info, auth logs Linux incremental, base Windows eventlog, docker, cloud metadata
- `enroll.py`: `POST /api/agents/enroll/` y guarda `agent_key`
- `sender.py`: `POST /api/ingest/` con `X-AGENT-KEY` + backoff exponencial
- `cursor_store.py`: cursores JSON

### Instalación Linux/Windows
- Linux: ejecuta `install.sh` como root; instala venv en `/opt/agent-nocturno/`, config en `/etc/agent-nocturno/`, y `systemd` service `agent-nocturno`.
- Windows: ejecuta `install.ps1` admin; instala en `C:\ProgramData\AgentNocturno`, crea servicio con NSSM y valida con `Get-Service`.


---

## EDR-lite por Endpoint (Agente Nocturno)

### UI
- `GET /endpoints/`: tabla por endpoint con hostname, OS, IP, estado, `last_seen`, risk score y alertas 24h.
- `GET /endpoints/<id>/`: detalle con overview + tabs (Telemetry, Users, Command Line, Services, Files, Alerts) y gráfica 24h CPU/RAM con Chart.js.

### Contrato de ingesta `/api/ingest/`
Cada evento del agente debe incluir:
- `ts` (ISO8601)
- `category`
- `host`
- `user` (si aplica)
- `ip` (si aplica)
- `raw` (JSON completo del evento)

Campos recomendados adicionales:
- `source` (default `agent`)
- `severity` (0-10, default 3)
- `message` (texto libre)

Categorías soportadas:
- `telemetry`: `cpu`, `ram`, `disk`, `net`, `gpu`
- `process`: lista top N de procesos
- `user_activity`: `login/logout/new_user/admin_added/failed_login/...`
- `commandline`: `cmd`, `user`, `parent`, `pid`
- `service`: `service_name`, `action=start|stop|install`
- `file_activity`: `action=download|execute`, `path`, `sha256` opcional
- `network`: `dst_ip`, `dst_port`, `domain` opcional
- `detection`: detección local opcional emitida por agente

### Detecciones server-side (MVP)
- `brute_force`: múltiples `failed_login` en ventana corta.
- `suspicious_execution`: ejecución en carpeta temporal + CPU alta + salida de red.
- `new_admin_user`: alta de usuario con privilegios administrativos.
- `suspicious_powershell`: `EncodedCommand` o shell sospechoso.

Cada detección puede generar alerta con mapeo MITRE (`mitre_tactic`, `mitre_technique_id`) y actualizar `EndpointRisk`.
