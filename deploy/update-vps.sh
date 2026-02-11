#!/usr/bin/env bash
#
# update-vps.sh — Pull latest changes and redeploy skills-bridge.
#
# Usage:
#   ssh root@76.13.118.222 'bash /opt/skills-bridge/deploy/update-vps.sh'
#
# Or copy this script to the VPS and run it.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

INSTALL_DIR="/opt/skills-bridge"
SERVICE_NAME="skills-bridge"

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root."
    exit 1
fi

if [[ ! -d "${INSTALL_DIR}/.git" ]]; then
    error "No git repository found at ${INSTALL_DIR}. Run deploy-vps.sh first."
    exit 1
fi

cd "${INSTALL_DIR}"

# ── 1. Pull latest changes ─────────────────────────────────────────
info "Pulling latest changes..."
git pull --ff-only

# ── 2. Install dependencies ────────────────────────────────────────
info "Installing npm dependencies..."
npm ci --omit=dev 2>/dev/null || npm install --omit=dev

# ── 3. Build ───────────────────────────────────────────────────────
info "Building project..."
npm run build

# ── 4. Fix ownership ───────────────────────────────────────────────
chown -R mcp:mcp "${INSTALL_DIR}"

# ── 5. Restart service ─────────────────────────────────────────────
info "Restarting ${SERVICE_NAME}..."
systemctl restart "${SERVICE_NAME}"
sleep 2

# ── 6. Show status ─────────────────────────────────────────────────
echo ""
systemctl status "${SERVICE_NAME}" --no-pager -l

echo ""
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    info "Update complete — ${SERVICE_NAME} is running."
else
    error "Update complete but ${SERVICE_NAME} failed to start."
    echo "  Check logs: journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
fi
