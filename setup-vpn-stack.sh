#!/usr/bin/env bash
set -Eeuo pipefail

# Debian 12 VPN + front-end management bootstrap.
# Features include SSH banner customization, custom HTTP behavior,
# modern admin panel assets, domain certificate handshake checks, and protocol status tooling.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "[ERROR] Run this script as root or with sudo."
  exit 1
fi

DRY_RUN=0
DOMAIN="vpn.example.com"
EMAIL="admin@example.com"
SSH_BANNER_MODE="1"
ENABLE_UDPGW=1
DEFAULT_WG_PORT=51820
DEFAULT_OVPN_PORT=1194
DEFAULT_IPSEC_UDP_500=500
DEFAULT_IPSEC_UDP_4500=4500
DEFAULT_UDPGW_PORT=7300
ADMIN_USERNAME="${VPN_ADMIN_USERNAME:-saeka}"
# Never hardcode the admin password: env override, or a generated one-off.
if [ -z "${VPN_ADMIN_PASSWORD:-}" ]; then
  ADMIN_PASSWORD="$(openssl rand -base64 24 | tr -d '/+=
' | head -c 24)"
  echo "[i] Generated admin password (override with VPN_ADMIN_PASSWORD env var)"
else
  ADMIN_PASSWORD="$VPN_ADMIN_PASSWORD"
fi

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --domain DOMAIN               Public domain used by the frontend and TLS testing (default: vpn.example.com)
  --email EMAIL                 Email for certificate and admin notes
  --ssh-banner-mode MODE        SSH banner mode 1, 2, or 3 (default: 1)
  --disable-udpgw               Do not configure badvpn UDPGW support
  --dry-run                    Print actions without applying changes
  -h, --help                   Show this help

Environment:
  VPN_ADMIN_USERNAME            Initial admin username (default: saeka)
  VPN_ADMIN_PASSWORD            Initial password; prompted securely if omitted
EOF
}

log() {
  printf '\n[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

warn() {
  printf '\n[WARN] %s\n' "$*" >&2
}

fail() {
  printf '\n[ERROR] %s\n' "$*" >&2
  exit 1
}

prompt_admin_credentials() {
  if [[ -f /var/lib/vpnfront/admin.sqlite3 ]]; then
    return 0
  fi

  [[ "$ADMIN_USERNAME" =~ ^[A-Za-z0-9_.-]{3,32}$ ]] || fail "VPN_ADMIN_USERNAME must be 3-32 letters, digits, dots, underscores, or hyphens."

  if [[ -z "$ADMIN_PASSWORD" ]]; then
    [[ -t 0 ]] || fail "Set VPN_ADMIN_PASSWORD or run this installer from a terminal to enter the initial admin password securely."
    local confirmation
    read -r -s -p "Initial admin password for ${ADMIN_USERNAME} (minimum 10 characters): " ADMIN_PASSWORD
    printf '\n'
    read -r -s -p "Confirm initial admin password: " confirmation
    printf '\n'
    [[ "$ADMIN_PASSWORD" == "$confirmation" ]] || fail "Admin passwords did not match."
  fi

  [[ ${#ADMIN_PASSWORD} -ge 10 && ${#ADMIN_PASSWORD} -le 256 ]] || fail "Initial admin password must be 10-256 characters."
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)
      DOMAIN="${2:-}"
      [[ -n "$DOMAIN" ]] || fail "--domain requires a value"
      shift 2
      ;;
    --email)
      EMAIL="${2:-}"
      [[ -n "$EMAIL" ]] || fail "--email requires a value"
      shift 2
      ;;
    --ssh-banner-mode)
      SSH_BANNER_MODE="${2:-}"
      [[ "$SSH_BANNER_MODE" =~ ^[123]$ ]] || fail "--ssh-banner-mode must be 1, 2, or 3"
      shift 2
      ;;
    --disable-udpgw)
      ENABLE_UDPGW=0
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
done

if [[ ! "$DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]; then
  fail "--domain must be a fully qualified domain name, for example vpn.example.com"
fi

if [[ ! "$EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then
  fail "--email must be a valid email address"
fi

if [[ ! -f /etc/os-release ]]; then
  fail "/etc/os-release not found; expected Debian-based OS."
fi

if ! grep -Eq 'PRETTY_NAME="Debian GNU/Linux 12' /etc/os-release; then
  warn "This script targets Debian 12. Continuing anyway because compatibility may still be acceptable."
fi

run_step() {
  local description="$1"
  shift
  log "$description"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[DRY-RUN] $*"
    return 0
  fi
  "$@"
}

ensure_base_dir() {
  mkdir -p /etc/vpnfront /var/lib/vpnfront /etc/ssl/localcerts /etc/nginx/conf.d /etc/wireguard /etc/openvpn /var/www/vpn-panel /etc/ssh
  chmod 700 /etc/vpnfront
  touch /var/lib/vpnfront/status.json
}

install_packages() {
  run_step "Updating package index" apt-get update
  run_step "Installing Debian 12 packages" apt-get install -y \
    curl ca-certificates gnupg lsb-release openssl jq net-tools ufw nginx \
    certbot python3-certbot-nginx wireguard-tools openvpn strongswan dnsmasq \
    dnsutils iproute2 whois iptables-persistent python3 python3-venv whiptail
}

configure_kernel() {
  cat > /etc/sysctl.d/99-vpn-forwarding.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
EOF
  sysctl --system >/dev/null 2>&1 || true
}

configure_ufw() {
  local udpgw_rule=""
  local outbound_interface
  outbound_interface="$(ip -4 route show default | awk 'NR == 1 {print $5}')"
  [[ "$outbound_interface" =~ ^[[:alnum:]_.:-]+$ ]] || fail "Could not determine the VPS outbound network interface."
  if [[ "$ENABLE_UDPGW" -eq 1 && "$(command -v badvpn-udpgw 2>/dev/null || true)" == "/usr/bin/badvpn-udpgw" ]]; then
    udpgw_rule='ufw allow 7300/tcp comment "UDPGW over SSH transport"'
  fi

  run_step "Configuring UFW firewall" bash -c "
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp comment "SSH"
    ufw allow 80/tcp comment "HTTP"
    ufw allow 443/tcp comment "HTTPS"
    ufw allow 51820/udp comment "WireGuard"
    ufw allow 1194/udp comment "OpenVPN"
    ufw allow 500/udp comment "IPsec IKE"
    ufw allow 4500/udp comment "IPsec NAT-T"
    ufw route allow in on wg0 out on ${outbound_interface} from 10.42.0.0/24
    ufw allow in on wg0 to 10.42.0.1 port 53 proto udp comment "VPN DNS"
    ufw allow in on wg0 to 10.42.0.1 port 53 proto tcp comment "VPN DNS"
    ${udpgw_rule}
    ufw --force enable
  "
}

configure_udpgw() {
  if [[ "$ENABLE_UDPGW" -ne 1 ]]; then
    warn "UDPGW disabled by request."
    return 0
  fi

  if ! command -v badvpn-udpgw >/dev/null 2>&1; then
    warn "badvpn-udpgw is not available from the configured Debian repositories; UDPGW service was not enabled."
    warn "Install a trusted badvpn-udpgw package or binary, then rerun this function with the service template."
    return 0
  fi

  cat > /etc/systemd/system/udpgw.service <<EOF
[Unit]
Description=UDPGW datagram gateway for authorized SSH tunnel clients
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 0.0.0.0:${DEFAULT_UDPGW_PORT} --max-clients 256 --client-socket-sndbuf 65536 --client-socket-rcvbuf 65536
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now udpgw.service
}

domain_points_to_vps() {
  local resolved_ip public_ip
  public_ip="$(curl -4fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
  [[ -n "$public_ip" ]] || return 1

  while read -r resolved_ip; do
    [[ "$resolved_ip" == "$public_ip" ]] && return 0
  done < <(getent ahostsv4 "$DOMAIN" | awk '{print $1}' | sort -u)

  warn "${DOMAIN} does not currently resolve to this VPS public IPv4 (${public_ip})."
  return 1
}

obtain_acme_certificate() {
  local cert_path="/etc/ssl/localcerts/${DOMAIN}.pem"
  local key_path="/etc/ssl/localcerts/${DOMAIN}.key"

  if ! domain_points_to_vps; then
    warn "Skipping Let's Encrypt issuance. Point DNS to this VPS before retrying."
    return 0
  fi

    if certbot certonly --nginx --non-interactive --agree-tos --email "$EMAIL" \
      -d "$DOMAIN"; then
    ln -sfn "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$cert_path"
    ln -sfn "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$key_path"
    systemctl reload nginx
    log "Let's Encrypt certificate installed for ${DOMAIN}."
  else
    warn "Let's Encrypt issuance failed; retaining the temporary certificate."
  fi
}

generate_self_signed_cert() {
  local cert_path="/etc/ssl/localcerts/${DOMAIN}.pem"
  local key_path="/etc/ssl/localcerts/${DOMAIN}.key"

  if [[ -f "$cert_path" && -f "$key_path" ]]; then
    return 0
  fi

  openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
    -keyout "$key_path" \
    -out "$cert_path" \
    -subj "/CN=${DOMAIN}" \
    -addext "subjectAltName=DNS:${DOMAIN},DNS:www.${DOMAIN},IP:127.0.0.1" \
    >/dev/null 2>&1 || fail "Failed to generate self-signed certificate for ${DOMAIN}"

  chmod 600 "$key_path"
  chmod 644 "$cert_path"
  cat "$cert_path" "$key_path" > "/etc/ssl/localcerts/${DOMAIN}.full.pem" || true
}

configure_ssh_banner() {
  local banner_text=""
  case "$SSH_BANNER_MODE" in
    1)
      banner_text=$(cat <<EOF
========================================
  CHKDARKMASTER VPN ACCESS CONTROL
  Domain: ${DOMAIN}
  Secure access only. Unauthorized use is prohibited.
  Ingress monitored and logged.
========================================
EOF
)
      ;;
    2)
      banner_text=$(cat <<EOF
========================================
  ACCESS GRANTED TO AUTHORIZED OPERATORS
  VPS: ${DOMAIN}
  Validate identity before receiving a session.
  All activity is recorded.
========================================
EOF
)
      ;;
    3)
      banner_text=$(cat <<EOF
========================================
  CHKDARKMASTER // SECURITY NODE
  Route: ${DOMAIN}
  This system is restricted to approved access only.
  Authorized users only.
========================================
EOF
)
      ;;
  esac

  cat > /etc/ssh/banner <<EOF
${banner_text}
EOF

  if grep -Eq '^Banner ' /etc/ssh/sshd_config; then
    sed -i "s#^Banner .*#Banner /etc/ssh/banner#" /etc/ssh/sshd_config
  else
    echo "Banner /etc/ssh/banner" >> /etc/ssh/sshd_config
  fi

  cat > /etc/update-motd.d/99-vpn-banner <<EOF
#!/bin/bash
printf '\n%s\n' "${banner_text}"
EOF
  chmod 755 /etc/update-motd.d/99-vpn-banner

  if command -v sshd >/dev/null 2>&1; then
    sshd -T >/dev/null 2>&1 || true
    systemctl reload ssh || systemctl reload sshd || true
  fi
}

write_status_reporter() {
  install -m 755 "$SCRIPT_DIR/vpn-status.py" /usr/local/bin/vpn-status-report
  DOMAIN="$DOMAIN" SSH_BANNER_MODE="$SSH_BANNER_MODE" /usr/local/bin/vpn-status-report >/var/lib/vpnfront/status.json
}

configure_admin_api() {
  install -m 755 "$SCRIPT_DIR/admin-api.py" /usr/local/bin/vpn-admin-api
  VPN_ADMIN_DB=/var/lib/vpnfront/admin.sqlite3 \
    VPN_ADMIN_INITIAL_USER="$ADMIN_USERNAME" \
    VPN_ADMIN_INITIAL_PASSWORD="$ADMIN_PASSWORD" \
    /usr/local/bin/vpn-admin-api --init-admin
  unset ADMIN_PASSWORD

  cat > /etc/systemd/system/vpn-admin-api.service <<'EOF'
[Unit]
Description=Authenticated VPN administration API
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=-/etc/vpnfront/.env
ExecStart=/usr/local/bin/vpn-admin-api --host 127.0.0.1 --port 8081
Restart=on-failure
RestartSec=3
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/vpnfront /etc/wireguard /etc/dnsmasq.d

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now vpn-admin-api.service
}

configure_status_refresh() {
  cat > /etc/systemd/system/vpn-status-refresh.service <<'EOF'
[Unit]
Description=Refresh VPN node status report
After=local-fs.target

[Service]
Type=oneshot
EnvironmentFile=-/etc/vpnfront/.env
ExecStart=/bin/sh -c '/usr/local/bin/vpn-status-report > /var/lib/vpnfront/status.json.tmp && mv /var/lib/vpnfront/status.json.tmp /var/lib/vpnfront/status.json'
EOF

  cat > /etc/systemd/system/vpn-status-refresh.timer <<'EOF'
[Unit]
Description=Refresh VPN node status every 30 seconds

[Timer]
OnBootSec=10s
OnUnitActiveSec=30s
AccuracySec=1s
Unit=vpn-status-refresh.service

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now vpn-status-refresh.timer
}

write_cert_checker() {
  cat > /usr/local/bin/vpn-cert-check <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

DOMAIN="${1:-${DOMAIN:-vpn.example.com}}"
PORT="${2:-443}"

if [[ -z "$DOMAIN" ]]; then
  echo "Usage: $0 <domain> [port]" >&2
  exit 2
fi

echo "Testing TLS handshake for ${DOMAIN}:${PORT}"
openssl s_client -connect "${DOMAIN}:${PORT}" -servername "${DOMAIN}" -showcerts </dev/null 2>/tmp/vpn-cert-check.err | sed -n '1,40p'
STATUS=$?
if [[ $STATUS -eq 0 ]]; then
  echo "Handshake: OK"
else
  echo "Handshake: FAIL"
  cat /tmp/vpn-cert-check.err >&2 || true
  exit $STATUS
fi
EOF
  chmod 755 /usr/local/bin/vpn-cert-check
}

deploy_web_panel() {
  if [[ -d "$SCRIPT_DIR/web-panel" ]]; then
    cp -r "$SCRIPT_DIR/web-panel"/* /var/www/vpn-panel/
    chown -R www-data:www-data /var/www/vpn-panel 2>/dev/null || true
  else
    cat > /var/www/vpn-panel/index.html <<'EOF'
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>VPN Panel</title>
    <style>
      body { font-family: sans-serif; background: #0b1020; color: #e7eefc; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
      .card { background: rgba(17,24,39,0.8); border: 1px solid rgba(255,255,255,0.12); border-radius: 16px; padding: 30px; }
      h1 { margin-bottom: 20px; }
      .badge { color: #7ef9c6; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>CHKDARKMASTER <span class="badge">VPN Panel</span></h1>
      <p>Modern admin panel assets are available from the repository.</p>
    </div>
  </body>
</html>
EOF
  fi
}

configure_nginx_frontend() {
  cat > /etc/nginx/conf.d/vpn_handshake_map.conf <<'EOF'
map "$server_protocol:$http_upgrade" $chkdarkmaster_handshake {
    default 0;
    "HTTP/1.1:CHKDARKMASTER" 1;
}
EOF

  cat > /etc/nginx/conf.d/vpn_frontend.conf <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
  listen 443 ssl;
  listen [::]:443 ssl;
    server_name ${DOMAIN} www.${DOMAIN};

    ssl_certificate /etc/ssl/localcerts/${DOMAIN}.pem;
    ssl_certificate_key /etc/ssl/localcerts/${DOMAIN}.key;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers HIGH:!aNULL:!MD5;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'" always;

    location = / {
      if (\$chkdarkmaster_handshake = 1) {
        add_header Upgrade "CHKDARKMASTER" always;
        add_header Connection "upgrade" always;
        add_header X-Status "CHKDARKMASTER" always;
        return 101;
      }
      root /var/www/vpn-panel;
      try_files /portal.html =404;
    }

    location = /status {
        default_type application/json;
        return 200 '{"status":"ok","service":"vpn-frontend","domain":"${DOMAIN}"}\n';
    }

    location = /healthz {
        default_type text/plain;
        return 200 'healthy\n';
    }

    location = /admin {
      return 301 /admin/;
    }

    location = /admin/ {
      alias /var/www/vpn-panel/index.html;
    }

    location ^~ /admin/ {
      alias /var/www/vpn-panel/;
    }

    location = /api {
      return 308 /api/;
    }

    location ^~ /api/ {
      proxy_http_version 1.1;
      proxy_set_header Host \$host;
      proxy_set_header X-Real-IP \$remote_addr;
      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto https;
      proxy_connect_timeout 3s;
      proxy_read_timeout 60s;
      proxy_pass http://127.0.0.1:8081;
    }

    location / {
      root /var/www/vpn-panel;
      try_files \$uri =404;
    }
}
EOF

    rm -f /etc/nginx/conf.d/backend_service.conf
  rm -f /etc/nginx/sites-enabled/default
  nginx -t >/dev/null 2>&1 || fail "Nginx configuration is invalid."
  systemctl enable --now nginx || fail "Failed to enable Nginx."
}

configure_wireguard() {
  local outbound_interface
  outbound_interface="$(ip -4 route show default | awk 'NR == 1 {print $5}')"
  [[ "$outbound_interface" =~ ^[[:alnum:]_.:-]+$ ]] || fail "Could not determine the VPS outbound network interface."

  if [[ ! -f /etc/wireguard/server.key ]]; then
    wg genkey > /etc/wireguard/server.key
  fi

  if [[ ! -f /etc/wireguard/server.pub ]]; then
    wg pubkey < /etc/wireguard/server.key > /etc/wireguard/server.pub
  fi

  if [[ ! -f /etc/wireguard/wg0.conf ]]; then
    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.42.0.1/24
ListenPort = ${DEFAULT_WG_PORT}
PrivateKey = $(cat /etc/wireguard/server.key)
PostUp = iptables -A FORWARD -i %i -o ${outbound_interface} -j ACCEPT; iptables -A FORWARD -i ${outbound_interface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.42.0.0/24 -o ${outbound_interface} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o ${outbound_interface} -j ACCEPT || true; iptables -D FORWARD -i ${outbound_interface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || true; iptables -t nat -D POSTROUTING -s 10.42.0.0/24 -o ${outbound_interface} -j MASQUERADE || true
EOF
  elif ! grep -q '10\.42\.0\.0/24.*MASQUERADE' /etc/wireguard/wg0.conf; then
    local temporary_config
    temporary_config="$(mktemp /etc/wireguard/wg0.conf.XXXXXX)"
    awk -v outbound_interface="$outbound_interface" '
      /^SaveConfig[[:space:]]*=/ { next }
      /^\[Interface\]$/ {
        print
        print "PostUp = iptables -A FORWARD -i %i -o " outbound_interface " -j ACCEPT; iptables -A FORWARD -i " outbound_interface " -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.42.0.0/24 -o " outbound_interface " -j MASQUERADE"
        print "PostDown = iptables -D FORWARD -i %i -o " outbound_interface " -j ACCEPT || true; iptables -D FORWARD -i " outbound_interface " -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || true; iptables -t nat -D POSTROUTING -s 10.42.0.0/24 -o " outbound_interface " -j MASQUERADE || true"
        next
      }
      { print }
    ' /etc/wireguard/wg0.conf > "$temporary_config"
    chmod 600 "$temporary_config"
    mv "$temporary_config" /etc/wireguard/wg0.conf
  else
    sed -i '/^SaveConfig[[:space:]]*=/d' /etc/wireguard/wg0.conf
  fi

  chmod 600 /etc/wireguard/server.key /etc/wireguard/wg0.conf
  chmod 644 /etc/wireguard/server.pub
  if systemctl is-active --quiet wg-quick@wg0; then
    systemctl restart wg-quick@wg0 || warn "WireGuard config was updated but the interface did not restart."
  else
    systemctl enable --now wg-quick@wg0 || warn "WireGuard could not be started."
  fi
}

configure_dns_filter() {
  mkdir -p /etc/dnsmasq.d /etc/systemd/system/dnsmasq.service.d /var/lib/vpnfront
  touch /var/lib/vpnfront/ads-source.hosts /var/lib/vpnfront/ads.hosts
  chmod 644 /var/lib/vpnfront/ads-source.hosts /var/lib/vpnfront/ads.hosts
  if [[ ! -f /var/lib/vpnfront/adblock.json ]]; then
    printf '{"enabled":false,"host_count":0,"updated_at":null,"last_error":null}\n' >/var/lib/vpnfront/adblock.json
  fi
  chmod 600 /var/lib/vpnfront/adblock.json
  cat > /etc/dnsmasq.d/vpnfront.conf <<'EOF'
interface=wg0
listen-address=10.42.0.1
bind-interfaces
no-resolv
server=1.1.1.1
server=9.9.9.9
cache-size=10000
domain-needed
bogus-priv
EOF
  cat > /usr/local/bin/vpn-adblock-update <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

STATE=/var/lib/vpnfront/adblock.json
HOSTS=/var/lib/vpnfront/ads.hosts
SOURCE=https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts

if [[ ! -f "$STATE" ]] || [[ "$(jq -r '.enabled // false' "$STATE")" != "true" ]]; then
  exit 0
fi

record_error() {
  local temporary timestamp
  temporary="$(mktemp /var/lib/vpnfront/adblock-state.XXXXXX)"
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  jq --arg updated_at "$timestamp" --arg last_error "Blocklist download or validation failed; previous list retained." \
    '.updated_at = $updated_at | .last_error = $last_error' "$STATE" >"$temporary"
  chmod 600 "$temporary"
  mv "$temporary" "$STATE"
}

raw="$(mktemp /var/lib/vpnfront/adblock-raw.XXXXXX)"
candidate="$(mktemp /var/lib/vpnfront/ads-candidate.XXXXXX)"
backup="$(mktemp /var/lib/vpnfront/ads-backup.XXXXXX)"
trap 'rm -f "$raw" "$candidate" "$backup"' EXIT

if ! curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --max-time 90 "$SOURCE" -o "$raw"; then
  record_error
  exit 1
fi

if ! awk '
  $1 == "0.0.0.0" || $1 == "127.0.0.1" {
    for (i = 2; i <= NF; i++) {
      host = tolower($i)
      if (host ~ /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/ && host !~ /\.\./ && host !~ /\.$/ && host !~ /\.local$/ && host != "localhost" && host != "broadcasthost") {
        print "0.0.0.0 " host
      }
    }
  }
' "$raw" | sort -u >"$candidate"; then
  record_error
  exit 1
fi

host_count="$(wc -l <"$candidate")"
if (( host_count < 100 || host_count > 2000000 )); then
  record_error
  exit 1
fi

cp -p "$HOSTS" "$backup"
chmod 644 "$candidate"
mv "$candidate" "$HOSTS"
if ! dnsmasq --test >/dev/null 2>&1 || ! systemctl reload dnsmasq; then
  mv "$backup" "$HOSTS"
  systemctl reload dnsmasq >/dev/null 2>&1 || true
  record_error
  exit 1
fi

temporary_state="$(mktemp /var/lib/vpnfront/adblock-state.XXXXXX)"
timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq --arg updated_at "$timestamp" --argjson host_count "$host_count" \
  '.host_count = $host_count | .updated_at = $updated_at | .last_error = null' "$STATE" >"$temporary_state"
chmod 600 "$temporary_state"
mv "$temporary_state" "$STATE"
EOF
  chmod 755 /usr/local/bin/vpn-adblock-update
  cat > /etc/systemd/system/dnsmasq.service.d/vpnfront.conf <<'EOF'
[Unit]
After=wg-quick@wg0.service
Requires=wg-quick@wg0.service
EOF
  cat > /etc/systemd/system/vpn-adblock-update.service <<'EOF'
[Unit]
Description=Refresh VPN DNS ad-block list
After=network-online.target dnsmasq.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpn-adblock-update
EOF
  cat > /etc/systemd/system/vpn-adblock-update.timer <<'EOF'
[Unit]
Description=Refresh VPN DNS ad-block list weekly

[Timer]
OnBootSec=5min
OnUnitActiveSec=1w
RandomizedDelaySec=1h
Unit=vpn-adblock-update.service

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now dnsmasq || warn "The VPN-only DNS resolver could not be started."
  systemctl enable --now vpn-adblock-update.timer || warn "The ad-block list update timer could not be enabled."
}

configure_openvpn() {
  cat > /etc/openvpn/server.conf <<EOF
port ${DEFAULT_OVPN_PORT}
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem
server 10.8.0.0 255.255.255.0
keepalive 10 120
persist-key
persist-tun
status /var/log/openvpn-status.log
verb 3
EOF

  if [[ ! -f /etc/openvpn/server.key ]]; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
      -keyout /etc/openvpn/server.key \
      -out /etc/openvpn/server.crt \
      -subj "/CN=${DOMAIN}" >/dev/null 2>&1 || true
    cp /etc/openvpn/server.crt /etc/openvpn/ca.crt
    openssl dhparam -out /etc/openvpn/dh.pem 2048 >/dev/null 2>&1 || true
  fi

  if systemctl list-unit-files | grep -q '^openvpn.service'; then
    systemctl enable --now openvpn || true
  else
    systemctl enable --now openvpn-server@server || true
  fi
}

configure_ipsec() {
  cat > /etc/ipsec.conf <<EOF
config setup
    uniqueids=no
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2, mgr 2"

conn %default
    keyexchange=ikev2
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256!
    dpdaction=clear
    dpddelay=30s
    rekey=no
    left=%any
    leftsubnet=0.0.0.0/0
    leftfirewall=yes
    right=%any
    rightdns=1.1.1.1,8.8.8.8
    rightsubnet=0.0.0.0/0
    auto=add

conn vpn-${DOMAIN}
    left=%defaultroute
    leftid="${DOMAIN}"
    leftcert=/etc/ssl/localcerts/${DOMAIN}.pem
    right=%any
    rightsourceip=10.60.0.0/24
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256!
    keyingtries=%forever
EOF

  cat > /etc/ipsec.secrets <<EOF
: RSA "${DOMAIN}"
EOF

  chmod 600 /etc/ipsec.secrets
  ipsec rereadall >/dev/null 2>&1 || true
  ipsec restart >/dev/null 2>&1 || true
}

configure_midnight_restart() {
  cat > /etc/systemd/system/vpnfront-restart.service <<'EOF'
[Unit]
Description=Restart VPN frontend services

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'for unit in nginx wg-quick@wg0 openvpn strongswan udpgw; do /bin/systemctl restart "$unit" || true; done'
EOF

  cat > /etc/systemd/system/vpnfront-restart.timer <<'EOF'
[Unit]
Description=Restart VPN frontend services every day at local midnight

[Timer]
OnCalendar=*-*-* 00:00:00
Persistent=true
Unit=vpnfront-restart.service

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now vpnfront-restart.timer
}

create_management_tool() {
  cat > /usr/local/bin/vpn-admin <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "[ERROR] Run as root."
  exit 1
fi

show_status() {
  echo "==== Service status ===="
  systemctl --no-pager status nginx wg-quick@wg0 openvpn strongswan --lines=25 || true
  echo "==== Port scan ===="
  ss -tulpn | grep -E ':80|:443|:1194|:51820|:500|:4500|:7300' || true
  echo "==== Midnight restart timer ===="
  systemctl --no-pager status vpnfront-restart.timer --lines=8 || true
}

show_protocols() {
  echo "==== Protocol summary ===="
  /usr/local/bin/vpn-status-report || true
}

check_cert() {
  /usr/local/bin/vpn-cert-check "${DOMAIN:-vpn.example.com}" 443 || true
}

show_adblock() {
  echo "==== VPN DNS ad blocking ===="
  if [[ -f /var/lib/vpnfront/adblock.json ]]; then jq . /var/lib/vpnfront/adblock.json; else echo "Ad-block state is not initialized."; fi
  systemctl --no-pager status dnsmasq vpn-adblock-update.timer --lines=8 || true
}

toggle_adblock() {
  local choice="${1:-}"
  case "$choice" in
    on)
      printf 'addn-hosts=/var/lib/vpnfront/ads.hosts\n' >/etc/dnsmasq.d/vpnfront-adblock.conf
      dnsmasq --test && systemctl reload dnsmasq
      jq '.enabled = true' /var/lib/vpnfront/adblock.json >/var/lib/vpnfront/adblock.json.tmp && mv /var/lib/vpnfront/adblock.json.tmp /var/lib/vpnfront/adblock.json
      ;;
    off)
      rm -f /etc/dnsmasq.d/vpnfront-adblock.conf
      dnsmasq --test && systemctl reload dnsmasq
      jq '.enabled = false' /var/lib/vpnfront/adblock.json >/var/lib/vpnfront/adblock.json.tmp && mv /var/lib/vpnfront/adblock.json.tmp /var/lib/vpnfront/adblock.json
      ;;
    *) echo "Usage: $0 adblock {status|on|off}"; return 1 ;;
  esac
  show_adblock
}

restart_all() {
  systemctl restart nginx wg-quick@wg0 openvpn strongswan || true
  echo "Services restarted."
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    status) show_status; exit 0 ;;
    protocols) show_protocols; exit 0 ;;
    cert) check_cert; exit 0 ;;
    restart) restart_all; exit 0 ;;
    adblock) [[ "${2:-status}" == status ]] && show_adblock || toggle_adblock "${2:-}"; exit $? ;;
    *) echo "Usage: $0 {status|protocols|cert|restart|adblock {status|on|off}}"; exit 1 ;;
  esac
done

cat <<'MENU'
VPN Management Console
1) Show service status
2) Show protocol summary
3) Check domain certificate handshake
4) Restart all services
5) Show VPN DNS ad-block status
6) Enable VPN DNS ad blocking
7) Disable VPN DNS ad blocking
0) Exit
MENU

while true; do
  printf 'Select option: '
  read -r choice || break
  case "$choice" in
    1) show_status ;;
    2) show_protocols ;;
    3) check_cert ;;
    4) restart_all ;;
    5) show_adblock ;;
    6) toggle_adblock on ;;
    7) toggle_adblock off ;;
    0) exit 0 ;;
    *) echo "Invalid option" ;;
  esac
done
EOF
  chmod 755 /usr/local/bin/vpn-admin
}

write_env_file() {
  cat > /etc/vpnfront/.env <<EOF
DOMAIN=${DOMAIN}
EMAIL=${EMAIL}
SSH_BANNER_MODE=${SSH_BANNER_MODE}
WG_PORT=${DEFAULT_WG_PORT}
OVPN_PORT=${DEFAULT_OVPN_PORT}
IPSEC_PORT_UDP_500=${DEFAULT_IPSEC_UDP_500}
IPSEC_PORT_UDP_4500=${DEFAULT_IPSEC_UDP_4500}
EOF
  chmod 600 /etc/vpnfront/.env
}

main() {
  log "Starting Debian 12 VPN installation for ${DOMAIN}"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY RUN enabled; no changes applied."
    echo "Would install packages, configure SSH banner, Nginx, WireGuard, OpenVPN, IPsec, UFW, and the admin panel for ${DOMAIN}."
    exit 0
  fi

  prompt_admin_credentials
  ensure_base_dir
  write_env_file
  install_packages
  configure_kernel
  configure_ufw
  generate_self_signed_cert
  configure_ssh_banner
  write_status_reporter
  write_cert_checker
  deploy_web_panel
  configure_nginx_frontend
  configure_wireguard
  configure_dns_filter
  configure_admin_api
  configure_openvpn
  configure_ipsec
  configure_udpgw
  configure_midnight_restart
  create_management_tool
  obtain_acme_certificate
  DOMAIN="$DOMAIN" SSH_BANNER_MODE="$SSH_BANNER_MODE" /usr/local/bin/vpn-status-report >/var/lib/vpnfront/status.json
  configure_status_refresh

  log "Bootstrap complete."
  log "Front-end domain: ${DOMAIN}"
  log "Certificate path: /etc/ssl/localcerts/${DOMAIN}.pem"
  log "Management tool: /usr/local/bin/vpn-admin"
  log "User portal: https://${DOMAIN}/"
  log "Admin panel: https://${DOMAIN}/admin"
  log "Certificate test: /usr/local/bin/vpn-cert-check ${DOMAIN} 443"
}

main "$@"
