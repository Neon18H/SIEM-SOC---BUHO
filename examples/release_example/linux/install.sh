#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/agent-nocturno"
CONF_DIR="/etc/agent-nocturno"
SECRET_FILE="${CONF_DIR}/agent-secret.json"
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin agentnocturno 2>/dev/null || true
sudo mkdir -p "${INSTALL_DIR}" "${CONF_DIR}"
sudo cp "${BASE_DIR}/config.yml" "${CONF_DIR}/config.yml"
if [ -f "${BASE_DIR}/secret.json" ]; then sudo cp "${BASE_DIR}/secret.json" "${SECRET_FILE}"; fi
sudo rsync -a --delete "${BASE_DIR}/agent/" "${INSTALL_DIR}/"
sudo python3 -m venv "${INSTALL_DIR}/venv"
sudo "${INSTALL_DIR}/venv/bin/pip" install --upgrade pip
sudo "${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"
