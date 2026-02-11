#!/usr/bin/env bash
#
# deploy-vps.sh — Bootstrap the skills-bridge MCP server on a fresh
# Hostinger VPS (Ubuntu 24.04, 8 GB RAM).
#
# Usage:
#   scp -r deploy/* root@76.13.118.222:/tmp/skills-bridge-deploy/
#   ssh root@76.13.118.222 'bash /tmp/skills-bridge-deploy/deploy-vps.sh'
#
# The script is idempotent: re-running it will skip steps that are
# already complete and apply any new configuration.

set -euo pipefail
IFS=$'\n\t'

# ── Colour helpers ──────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── Pre-flight checks ──────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root."
    exit 1
fi

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_URL="https://github.com/rblake2320/claude-desktop-mcp-bridge.git"
INSTALL_DIR="/opt/skills-bridge"
SERVICE_USER="mcp"
NODE_MAJOR=22

info "Starting skills-bridge deployment..."
info "Deploy assets directory: ${DEPLOY_DIR}"

# ── 1. System packages ─────────────────────────────────────────────
info "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq

# ── 2. Node.js 22 LTS via NodeSource ───────────────────────────────
if ! command -v node &>/dev/null || [[ "$(node -v | cut -d. -f1 | tr -d 'v')" -lt ${NODE_MAJOR} ]]; then
    info "Installing Node.js ${NODE_MAJOR} LTS..."
    apt-get install -y -qq ca-certificates curl gnupg
    mkdir -p /etc/apt/keyrings
    curl -fsSL "https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key" \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg --yes
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list
    apt-get update -qq
    apt-get install -y -qq nodejs
    info "Node.js $(node -v) installed."
else
    info "Node.js $(node -v) already present — skipping."
fi

# ── 3. Nginx + Certbot ─────────────────────────────────────────────
info "Installing nginx and certbot..."
apt-get install -y -qq nginx certbot python3-certbot-nginx

# ── 4. Create mcp system user ──────────────────────────────────────
if ! id "${SERVICE_USER}" &>/dev/null; then
    info "Creating system user '${SERVICE_USER}'..."
    useradd --system --shell /usr/sbin/nologin --home-dir "/home/${SERVICE_USER}" --create-home "${SERVICE_USER}"
else
    info "User '${SERVICE_USER}' already exists — skipping."
fi

# ── 5. Clone / update the repository ───────────────────────────────
if [[ -d "${INSTALL_DIR}/.git" ]]; then
    info "Repository already cloned — pulling latest changes..."
    git -C "${INSTALL_DIR}" pull --ff-only
else
    info "Cloning repository to ${INSTALL_DIR}..."
    git clone "${REPO_URL}" "${INSTALL_DIR}"
fi

# ── 6. Install dependencies & build ────────────────────────────────
info "Installing npm dependencies..."
cd "${INSTALL_DIR}"
npm ci --omit=dev 2>/dev/null || npm install --omit=dev
info "Building project..."
npm run build

# ── 7. Generate .env with auth token ───────────────────────────────
ENV_FILE="${INSTALL_DIR}/.env"
if [[ -f "${ENV_FILE}" ]]; then
    info "Existing .env found — preserving it."
    # Source existing env to grab token for display later
    set +u
    source "${ENV_FILE}" 2>/dev/null || true
    MCP_TOKEN="${MCP_AUTH_TOKEN:-}"
    set -u
else
    MCP_TOKEN="$(openssl rand -hex 32)"
    info "Generating new .env with auth token..."
    cat > "${ENV_FILE}" <<ENVEOF
# skills-bridge production environment
PORT=3001
HOST=127.0.0.1
MCP_AUTH_TOKEN=${MCP_TOKEN}
SKILLS_PATH=/home/${SERVICE_USER}/.claude/skills/
TIMEOUT=60000
ALLOWED_PATHS=${INSTALL_DIR}
NODE_ENV=production
ENVEOF
    chmod 600 "${ENV_FILE}"
fi

# Create the skills directory for the mcp user
mkdir -p "/home/${SERVICE_USER}/.claude/skills"

# ── 8. Fix ownership ───────────────────────────────────────────────
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "/home/${SERVICE_USER}"

# ── 9. Install systemd service ─────────────────────────────────────
info "Installing systemd service..."
cp "${DEPLOY_DIR}/skills-bridge.service" /etc/systemd/system/skills-bridge.service
systemctl daemon-reload
systemctl enable skills-bridge

# ── 10. Install nginx configuration ────────────────────────────────
info "Installing nginx configuration..."
cp "${DEPLOY_DIR}/nginx-mcp.conf" /etc/nginx/sites-available/mcp.conf
ln -sf /etc/nginx/sites-available/mcp.conf /etc/nginx/sites-enabled/mcp.conf

# Remove default site if it exists (avoids port-80 conflict)
rm -f /etc/nginx/sites-enabled/default

# Validate nginx config before reloading
if nginx -t 2>&1; then
    systemctl reload nginx
    info "Nginx configuration loaded."
else
    warn "Nginx config test failed — check /etc/nginx/sites-available/mcp.conf"
    warn "You likely need to update server_name and obtain SSL certs first."
fi

# ── 11. Start the service ──────────────────────────────────────────
info "Starting skills-bridge service..."
systemctl restart skills-bridge
sleep 2

if systemctl is-active --quiet skills-bridge; then
    info "skills-bridge is running."
else
    warn "skills-bridge failed to start. Check: journalctl -u skills-bridge -n 50"
fi

# ── 12. Firewall (ufw) ─────────────────────────────────────────────
if command -v ufw &>/dev/null; then
    info "Configuring firewall..."
    ufw allow 'Nginx Full' >/dev/null 2>&1 || true
    ufw allow OpenSSH       >/dev/null 2>&1 || true
    ufw --force enable       >/dev/null 2>&1 || true
fi

# ── Done ────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  skills-bridge deployment complete"
echo "============================================================"
echo ""
echo "  Service status : $(systemctl is-active skills-bridge 2>/dev/null || echo 'unknown')"
echo "  Listening on   : 127.0.0.1:3001 (behind nginx)"
echo "  Logs           : journalctl -u skills-bridge -f"
echo ""

if [[ -n "${MCP_TOKEN:-}" ]]; then
    echo "  ┌──────────────────────────────────────────────────────────────────────┐"
    echo "  │  MCP_AUTH_TOKEN (save this — it will not be shown again):            │"
    echo "  │  ${MCP_TOKEN}  │"
    echo "  └──────────────────────────────────────────────────────────────────────┘"
fi

echo ""
echo "  NEXT STEPS:"
echo "  1. Update server_name in /etc/nginx/sites-available/mcp.conf"
echo "     with your actual domain (e.g. mcp.yourdomain.com)."
echo "  2. Obtain SSL certificate:"
echo "       certbot --nginx -d mcp.yourdomain.com"
echo "  3. Test the endpoint:"
echo "       curl -H 'Authorization: Bearer <TOKEN>' https://mcp.yourdomain.com/health"
echo ""
