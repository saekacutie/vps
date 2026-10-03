#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import http.cookies
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import subprocess
import threading
import tempfile
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit


DB_PATH = Path(os.environ.get("VPN_ADMIN_DB", "/var/lib/vpnfront/admin.sqlite3"))
STATUS_PATH = Path(os.environ.get("VPN_STATUS_PATH", "/var/lib/vpnfront/status.json"))
WEB_DIR = Path(os.environ.get("VPN_WEB_DIR", Path(__file__).resolve().parent / "web-panel"))
SESSION_COOKIE = "vpn_session"
SESSION_TTL = 8 * 60 * 60
CLIENT_SESSION_COOKIE = "vpn_client_session"
CLIENT_SESSION_TTL = 12 * 60 * 60
PBKDF2_ITERATIONS = 310_000
BOOTSTRAP_PASSWORD_MIN_LENGTH = 10
PASSWORD_MIN_LENGTH = 14
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MAX_BODY_SIZE = 8192
MAX_ADMINS = 20
CLIENT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0")
WG_CONFIG_PATH = Path(os.environ.get("WG_CONFIG_PATH", "/etc/wireguard/wg0.conf"))
ADBLOCK_CONFIG_PATH = Path(os.environ.get("ADBLOCK_CONFIG_PATH", "/etc/dnsmasq.d/vpnfront-adblock.conf"))
ADBLOCK_HOSTS_PATH = Path(os.environ.get("ADBLOCK_HOSTS_PATH", "/var/lib/vpnfront/ads.hosts"))
ADBLOCK_STATE_PATH = Path(os.environ.get("ADBLOCK_STATE_PATH", "/var/lib/vpnfront/adblock.json"))
ADBLOCK_SOURCE_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
WG_CLIENT_NETWORK = ipaddress.ip_network("10.42.0.0/24")
WG_GATEWAY_ADDRESS = ipaddress.ip_address("10.42.0.1")
WG_DEFAULT_PORT = 51820
WG_HANDSHAKE_ACTIVE_SECONDS = 180
CLIENT_DURATION_OPTIONS = {0, 1, 7, 30, 90}
client_operations_lock = threading.RLock()
SERVICE_UNITS = {
    "nginx": ("nginx.service",),
    "wireguard": ("wg-quick@wg0.service", "wg-quick@.service"),
    "openvpn": ("openvpn.service", "openvpn-server@.service"),
    "ipsec": ("strongswan.service", "strongswan-starter.service"),
}
DEFAULT_SERVICE_UNITS = {
    "nginx": "nginx.service",
    "wireguard": "wg-quick@wg0.service",
    "openvpn": "openvpn-server@server.service",
    "ipsec": "strongswan-starter.service",
}
LOGIN_FAILURE_LIMIT = 5
LOGIN_WINDOW_SECONDS = 900
login_attempts = {}
login_attempts_lock = threading.Lock()
logger = logging.getLogger("vpn-admin-api")


class ExpiredClientError(ValueError):
    pass


@contextmanager
def database():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_database():
    DB_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(DB_PATH.parent, 0o700)
    with database() as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS admins (
                username TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                must_change_password INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash BLOB PRIMARY KEY,
                username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vpn_clients (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL UNIQUE,
                private_key TEXT NOT NULL,
                address TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                password_salt BLOB,
                password_hash BLOB,
                must_change_password INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS client_sessions (
                token_hash BLOB PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES vpn_clients(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            """
        )
        client_columns = {row["name"] for row in connection.execute("PRAGMA table_info(vpn_clients)")}
        if "password_salt" not in client_columns:
            connection.execute("ALTER TABLE vpn_clients ADD COLUMN password_salt BLOB")
        if "password_hash" not in client_columns:
            connection.execute("ALTER TABLE vpn_clients ADD COLUMN password_hash BLOB")
        if "must_change_password" not in client_columns:
            connection.execute("ALTER TABLE vpn_clients ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 1")
    if DB_PATH.exists():
        os.chmod(DB_PATH, 0o600)


def validate_username(username):
    if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Username must be 3-32 letters, digits, dots, underscores, or hyphens.")


def validate_password(password, minimum=PASSWORD_MIN_LENGTH):
    if not isinstance(password, str) or len(password) < minimum or len(password) > 256:
        raise ValueError(f"Password must be between {minimum} and 256 characters.")


def password_digest(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)


def add_admin(username, password, must_change_password=True, bootstrap=False):
    validate_username(username)
    validate_password(password, BOOTSTRAP_PASSWORD_MIN_LENGTH if bootstrap else PASSWORD_MIN_LENGTH)
    salt = secrets.token_bytes(16)
    digest = password_digest(password, salt)
    with database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        count = connection.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
        if count >= MAX_ADMINS:
            raise ValueError("The maximum number of admin accounts has been reached.")
        try:
            connection.execute(
                "INSERT INTO admins(username, salt, password_hash, created_at, must_change_password) VALUES (?, ?, ?, ?, ?)",
                (username, salt, digest, int(time.time()), int(must_change_password)),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("That username already exists.") from exc


def bootstrap_admin(username, password):
    validate_username(username)
    validate_password(password, BOOTSTRAP_PASSWORD_MIN_LENGTH)
    salt = secrets.token_bytes(16)
    digest = password_digest(password, salt)
    with database() as connection:
        count = connection.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
        if count:
            return False
        connection.execute(
            "INSERT INTO admins(username, salt, password_hash, created_at, must_change_password) VALUES (?, ?, ?, ?, 1)",
            (username, salt, digest, int(time.time())),
        )
    return True


def verify_password(username, password):
    with database() as connection:
        row = connection.execute(
            "SELECT salt, password_hash, must_change_password FROM admins WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None:
        password_digest(password, b"\0" * 16)
        return None
    if not hmac.compare_digest(password_digest(password, row["salt"]), row["password_hash"]):
        return None
    return {"username": username, "must_change_password": bool(row["must_change_password"])}


def verify_client_password(username, password):
    with database() as connection:
        row = connection.execute(
            "SELECT id, password_salt, password_hash, must_change_password FROM vpn_clients WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None or row["password_salt"] is None or row["password_hash"] is None:
        password_digest(password, b"\0" * 16)
        return None
    if not hmac.compare_digest(password_digest(password, row["password_salt"]), row["password_hash"]):
        return None
    return {"id": row["id"], "username": username, "must_change_password": bool(row["must_change_password"])}


def new_session(username):
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("ascii")).digest()
    with database() as connection:
        connection.execute("DELETE FROM sessions WHERE expires_at < ?", (int(time.time()),))
        connection.execute(
            "INSERT INTO sessions(token_hash, username, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
            (token_hash, username, csrf_token, int(time.time()) + SESSION_TTL),
        )
    return token, csrf_token


def new_client_session(client_id):
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("ascii")).digest()
    with database() as connection:
        connection.execute("DELETE FROM client_sessions WHERE expires_at < ?", (int(time.time()),))
        connection.execute(
            "INSERT INTO client_sessions(token_hash, client_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
            (token_hash, client_id, csrf_token, int(time.time()) + CLIENT_SESSION_TTL),
        )
    return token, csrf_token


def reset_client_portal_password(client_id):
    with database() as connection:
        row = connection.execute("SELECT username FROM vpn_clients WHERE id = ?", (client_id,)).fetchone()
        if row is None:
            raise ValueError("VPN account not found.")
        temporary_password = secrets.token_urlsafe(18)
        salt = secrets.token_bytes(16)
        digest = password_digest(temporary_password, salt)
        connection.execute(
            "UPDATE vpn_clients SET password_salt = ?, password_hash = ?, must_change_password = 1 WHERE id = ?",
            (salt, digest, client_id),
        )
        connection.execute("DELETE FROM client_sessions WHERE client_id = ?", (client_id,))
    return row["username"], temporary_password


def delete_user_sessions(username):
    with database() as connection:
        connection.execute("DELETE FROM sessions WHERE username = ?", (username,))


def list_admins():
    with database() as connection:
        rows = connection.execute("SELECT username, created_at FROM admins ORDER BY username COLLATE NOCASE").fetchall()
    return [{"username": row["username"], "created_at": row["created_at"]} for row in rows]


def delete_admin(username, current_username):
    if username == current_username:
        raise ValueError("You cannot remove the account you are using.")
    with database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        count = connection.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
        if count <= 1:
            raise ValueError("The last admin account cannot be removed.")
        cursor = connection.execute("DELETE FROM admins WHERE username = ?", (username,))
        if cursor.rowcount == 0:
            raise ValueError("Admin account not found.")


def validate_client_name(username):
    if not isinstance(username, str) or not CLIENT_NAME_PATTERN.fullmatch(username):
        raise ValueError("Client name must be 3-32 letters, digits, dots, underscores, or hyphens.")


def wireguard_command(arguments, input_text=None):
    try:
        result = subprocess.run(
            ["wg", *arguments],
            input=input_text,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("WireGuard is unavailable. Check that wg0 is running.") from exc
    if result.returncode != 0:
        raise RuntimeError("WireGuard operation failed. Check that wg0 is running.")
    return result.stdout.strip()


def _parse_allowed_networks(value):
    networks = []
    for address in value.split(","):
        try:
            networks.append(ipaddress.ip_network(address.strip(), strict=False))
        except ValueError:
            continue
    return networks


def _configured_peer_networks(config_text):
    networks = []
    in_peer = False
    for line in config_text.splitlines():
        section = re.fullmatch(r"\s*\[([^]]+)\]\s*", line)
        if section:
            in_peer = section.group(1).lower() == "peer"
        elif in_peer:
            allowed = re.match(r"\s*AllowedIPs\s*=\s*(.+)", line, re.IGNORECASE)
            if allowed:
                networks.extend(_parse_allowed_networks(allowed.group(1)))
    return networks


def _live_peer_networks(dump):
    networks = []
    for line in dump.splitlines():
        columns = line.split("\t")
        if len(columns) >= 8:
            networks.extend(_parse_allowed_networks(columns[3]))
    return networks


def _allocate_client_address(connection, config_text, dump):
    allocated = {
        ipaddress.ip_address(row[0])
        for row in connection.execute("SELECT address FROM vpn_clients")
    }
    networks = _configured_peer_networks(config_text) + _live_peer_networks(dump)
    for address in WG_CLIENT_NETWORK.hosts():
        if address == WG_GATEWAY_ADDRESS or address in allocated:
            continue
        if any(address in network for network in networks):
            continue
        return address
    raise ValueError("The WireGuard address pool is full.")


def _write_wireguard_config(config_text):
    WG_CONFIG_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(prefix=".wg0-", dir=WG_CONFIG_PATH.parent, text=True)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as temporary_file:
            temporary_file.write(config_text)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, WG_CONFIG_PATH)
        os.chmod(WG_CONFIG_PATH, 0o600)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def _wireguard_endpoint():
    endpoint = os.environ.get("DOMAIN", "vpn.example.com").strip()
    try:
        address = ipaddress.ip_address(endpoint)
        endpoint = f"[{address}]" if address.version == 6 else str(address)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]+", endpoint) or endpoint.startswith(".") or endpoint.endswith("."):
            raise RuntimeError("The configured VPN endpoint is invalid.")
    try:
        port = int(os.environ.get("WG_PORT", str(WG_DEFAULT_PORT)))
    except ValueError as exc:
        raise RuntimeError("The configured WireGuard port is invalid.") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("The configured WireGuard port is invalid.")
    return f"{endpoint}:{port}"


def read_adblock_state():
    try:
        state = json.loads(ADBLOCK_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        state = {}
    if not isinstance(state, dict):
        state = {}
    return {
        "enabled": state.get("enabled") is True,
        "hostCount": max(0, int(state.get("host_count", 0) or 0)),
        "updatedAt": state.get("updated_at"),
        "lastError": state.get("last_error"),
        "source": "StevenBlack hosts",
        "sourceUrl": ADBLOCK_SOURCE_URL,
    }


def _atomic_private_write(path, content):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent, text=True)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as temporary_file:
            temporary_file.write(content)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def _write_adblock_state(enabled, host_count=0, updated_at=None, last_error=None):
    state = {
        "enabled": bool(enabled),
        "host_count": max(0, int(host_count)),
        "updated_at": updated_at,
        "last_error": last_error,
    }
    _atomic_private_write(ADBLOCK_STATE_PATH, json.dumps(state, separators=(",", ":")) + "\n")
    return read_adblock_state()


def set_adblock_enabled(enabled):
    if not isinstance(enabled, bool):
        raise ValueError("Ad blocking must be enabled or disabled.")
    previous_config = ADBLOCK_CONFIG_PATH.read_bytes() if ADBLOCK_CONFIG_PATH.exists() else None
    previous_state = ADBLOCK_STATE_PATH.read_bytes() if ADBLOCK_STATE_PATH.exists() else None
    current_state = read_adblock_state()
    if current_state["enabled"] == enabled:
        return current_state
    try:
        if enabled:
            _atomic_private_write(ADBLOCK_CONFIG_PATH, f"addn-hosts={ADBLOCK_HOSTS_PATH}\n")
        else:
            ADBLOCK_CONFIG_PATH.unlink(missing_ok=True)
        _write_adblock_state(
            enabled,
            host_count=current_state["hostCount"],
            updated_at=current_state["updatedAt"],
            last_error=None,
        )
        validation = subprocess.run(
            ["dnsmasq", "--test"], capture_output=True, text=True, timeout=10, check=False
        )
        if validation.returncode != 0:
            raise RuntimeError("dnsmasq rejected the ad-block configuration.")
        reload_result = subprocess.run(
            ["systemctl", "reload", "dnsmasq"], capture_output=True, text=True, timeout=15, check=False
        )
        if reload_result.returncode != 0:
            raise RuntimeError("The VPN DNS resolver could not reload its configuration.")
        if enabled:
            update_result = subprocess.run(
                ["systemctl", "start", "--no-block", "vpn-adblock-update.service"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if update_result.returncode != 0:
                raise RuntimeError("The ad-block list updater could not be started.")
        return read_adblock_state()
    except (OSError, subprocess.TimeoutExpired, RuntimeError):
        if previous_config is None:
            ADBLOCK_CONFIG_PATH.unlink(missing_ok=True)
        else:
            _atomic_private_write(ADBLOCK_CONFIG_PATH, previous_config.decode("utf-8"))
        if previous_state is None:
            ADBLOCK_STATE_PATH.unlink(missing_ok=True)
        else:
            _atomic_private_write(ADBLOCK_STATE_PATH, previous_state.decode("utf-8"))
        try:
            subprocess.run(["systemctl", "reload", "dnsmasq"], capture_output=True, text=True, timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired):
            logger.exception("Failed to roll back DNS resolver configuration")
        raise


def create_wireguard_client(username, duration_days):
    validate_client_name(username)
    if isinstance(duration_days, bool) or not isinstance(duration_days, int) or duration_days not in CLIENT_DURATION_OPTIONS:
        raise ValueError("Choose an account duration of 1, 7, 30, or 90 days, or no expiry.")

    with client_operations_lock, database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT 1 FROM vpn_clients WHERE username = ?", (username,)).fetchone():
            raise ValueError("That VPN account name already exists.")
        try:
            config_text = WG_CONFIG_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError("WireGuard configuration is unavailable.") from exc
        live_dump = wireguard_command(["show", WG_INTERFACE, "dump"])
        server_public_key = wireguard_command(["show", WG_INTERFACE, "public-key"])
        endpoint = _wireguard_endpoint()
        address = _allocate_client_address(connection, config_text, live_dump)
        private_key = wireguard_command(["genkey"])
        public_key = wireguard_command(["pubkey"], input_text=f"{private_key}\n")
        if not private_key or not public_key:
            raise RuntimeError("WireGuard did not generate a client key pair.")

        now = int(time.time())
        expires_at = now + duration_days * 86400 if duration_days else None
        client_id = secrets.token_hex(16)
        temporary_password = secrets.token_urlsafe(18)
        password_salt = secrets.token_bytes(16)
        password_hash = password_digest(temporary_password, password_salt)
        peer_config = f"[Peer]\nPublicKey = {public_key}\nAllowedIPs = {address}/32\n"
        updated_config = f"{config_text.rstrip()}\n\n{peer_config}"
        _write_wireguard_config(updated_config)
        try:
            wireguard_command(["set", WG_INTERFACE, "peer", public_key, "allowed-ips", f"{address}/32"])
        except RuntimeError:
            _write_wireguard_config(config_text)
            raise
        connection.execute(
            "INSERT INTO vpn_clients(id, username, public_key, private_key, address, created_at, expires_at, password_salt, password_hash, must_change_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (client_id, username, public_key, private_key, str(address), now, expires_at, password_salt, password_hash),
        )
        client_config = (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {address}/32\n"
            f"DNS = {WG_GATEWAY_ADDRESS}\n\n"
            "[Peer]\n"
            f"PublicKey = {server_public_key}\n"
            f"Endpoint = {endpoint}\n"
            "AllowedIPs = 0.0.0.0/0\n"
            "PersistentKeepalive = 25\n"
        )
    return {"id": client_id, "username": username, "address": str(address), "createdAt": now, "expiresAt": expires_at, "temporaryPassword": temporary_password}, client_config


def _remove_peer_block(config_text, public_key):
    blocks = []
    current = []
    for line in config_text.splitlines():
        if re.fullmatch(r"\s*\[[^]]+\]\s*", line) and current:
            blocks.append(current)
            current = []
        current.append(line)
    if current:
        blocks.append(current)

    kept = []
    for block in blocks:
        is_target = (
            block[0].strip().lower() == "[peer]"
            and any(re.fullmatch(rf"\s*PublicKey\s*=\s*{re.escape(public_key)}\s*", line, re.IGNORECASE) for line in block[1:])
        )
        if not is_target:
            kept.extend(block)
    return "\n".join(kept).rstrip() + "\n"


def revoke_wireguard_client(client_id):
    with client_operations_lock:
        with database() as connection:
            row = connection.execute("SELECT public_key FROM vpn_clients WHERE id = ?", (client_id,)).fetchone()
        if row is None:
            raise ValueError("VPN account not found.")
        try:
            config_text = WG_CONFIG_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError("WireGuard configuration is unavailable.") from exc
        updated_config = _remove_peer_block(config_text, row["public_key"])
        _write_wireguard_config(updated_config)
        try:
            wireguard_command(["set", WG_INTERFACE, "peer", row["public_key"], "remove"])
        except RuntimeError:
            _write_wireguard_config(config_text)
            raise
        with database() as connection:
            connection.execute("DELETE FROM vpn_clients WHERE id = ?", (client_id,))


def expire_wireguard_clients(now=None):
    current_time = int(time.time()) if now is None else int(now)
    with database() as connection:
        expired = connection.execute(
            "SELECT id FROM vpn_clients WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (current_time,),
        ).fetchall()
    for row in expired:
        try:
            revoke_wireguard_client(row["id"])
        except (RuntimeError, ValueError) as exc:
            logger.warning("action=expire_vpn_client result=failed error=%s", type(exc).__name__)


def _wireguard_peer_metrics():
    try:
        dump = wireguard_command(["show", WG_INTERFACE, "dump"])
    except RuntimeError:
        return {}
    peers = {}
    for line in dump.splitlines():
        columns = line.split("\t")
        if len(columns) < 8:
            continue
        try:
            peers[columns[0]] = {
                "endpoint": columns[2] if columns[2] != "(none)" else None,
                "lastHandshake": int(columns[4]) or None,
                "bytesReceived": int(columns[5]),
                "bytesSent": int(columns[6]),
            }
        except ValueError:
            continue
    return peers


def list_wireguard_clients(now=None):
    current_time = int(time.time()) if now is None else int(now)
    expire_wireguard_clients(current_time)
    peer_metrics = _wireguard_peer_metrics()
    with database() as connection:
        rows = connection.execute(
            "SELECT id, username, public_key, address, created_at, expires_at, password_hash FROM vpn_clients ORDER BY created_at DESC"
        ).fetchall()
    clients = []
    for row in rows:
        metrics = peer_metrics.get(row["public_key"], {})
        handshake = metrics.get("lastHandshake")
        clients.append({
            "id": row["id"],
            "username": row["username"],
            "protocol": "wireguard",
            "address": row["address"],
            "createdAt": row["created_at"],
            "expiresAt": row["expires_at"],
            "durationDays": round((row["expires_at"] - row["created_at"]) / 86400) if row["expires_at"] else 0,
            "ageSeconds": max(0, current_time - row["created_at"]),
            "remainingSeconds": max(0, row["expires_at"] - current_time) if row["expires_at"] else None,
            "lastHandshake": handshake,
            "handshakeAgeSeconds": max(0, current_time - handshake) if handshake else None,
            "endpoint": metrics.get("endpoint"),
            "bytesReceived": metrics.get("bytesReceived", 0),
            "bytesSent": metrics.get("bytesSent", 0),
            "portalReady": row["password_hash"] is not None,
            "status": "expired" if row["expires_at"] and row["expires_at"] <= current_time else "connected" if handshake and 0 <= current_time - handshake <= WG_HANDSHAKE_ACTIVE_SECONDS else "idle",
        })
    return clients


def get_wireguard_client_account(client_id, now=None):
    for client in list_wireguard_clients(now):
        if client["id"] == client_id:
            return client
    raise ValueError("VPN account not found or has expired.")


def get_wireguard_client_config(client_id):
    with database() as connection:
        row = connection.execute(
            "SELECT username, private_key, address, expires_at FROM vpn_clients WHERE id = ?",
            (client_id,),
        ).fetchone()
    if row is None:
        raise ValueError("VPN account not found.")
    if row["expires_at"] is not None and row["expires_at"] <= int(time.time()):
        raise ExpiredClientError("This VPN account has expired.")
    endpoint = _wireguard_endpoint()
    server_public_key = wireguard_command(["show", WG_INTERFACE, "public-key"])
    return row["username"], (
        "[Interface]\n"
        f"PrivateKey = {row['private_key']}\n"
        f"Address = {row['address']}/32\n"
        f"DNS = {WG_GATEWAY_ADDRESS}\n\n"
        "[Peer]\n"
        f"PublicKey = {server_public_key}\n"
        f"Endpoint = {endpoint}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "PersistentKeepalive = 25\n"
    )


def login_allowed(client_ip):
    cutoff = time.time() - LOGIN_WINDOW_SECONDS
    with login_attempts_lock:
        attempts = [stamp for stamp in login_attempts.get(client_ip, []) if stamp >= cutoff]
        login_attempts[client_ip] = attempts
        return len(attempts) < LOGIN_FAILURE_LIMIT


def record_login_failure(client_ip):
    cutoff = time.time() - LOGIN_WINDOW_SECONDS
    with login_attempts_lock:
        attempts = [stamp for stamp in login_attempts.get(client_ip, []) if stamp >= cutoff]
        attempts.append(time.time())
        login_attempts[client_ip] = attempts


def clear_login_failures(client_ip):
    with login_attempts_lock:
        login_attempts.pop(client_ip, None)


def resolve_service_unit(service_key):
    result = subprocess.run(
        ["systemctl", "list-unit-files", "--type=service", "--no-legend"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    available = {line.split()[0] for line in (result.stdout or "").splitlines() if line.split()}
    for candidate in SERVICE_UNITS[service_key]:
        if candidate in available:
            if candidate.endswith("@.service"):
                instance = "wg0" if service_key == "wireguard" else "server"
                return candidate.replace("@.service", f"@{instance}.service")
            return candidate
    return DEFAULT_SERVICE_UNITS[service_key]


class AdminHandler(BaseHTTPRequestHandler):
    STATIC_TYPES = {
        ".html": "text/html; charset=utf-8",
        ".js": "application/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".json": "application/json",
        ".svg": "image/svg+xml",
        ".png": "image/png",
        ".ico": "image/x-icon",
    }

    def serve_static(self, path):
        """Serve the bundled web-panel UI. Path-traversal safe."""
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        target = (WEB_DIR / rel).resolve()
        try:
            target.relative_to(WEB_DIR.resolve())
        except ValueError:
            self.send_json(403, {"error": "Forbidden."})
            return
        if target.is_dir():
            target = target / "index.html"
        if not target.is_file():
            self.send_json(404, {"error": "Not found."})
            return
        ctype = self.STATIC_TYPES.get(target.suffix.lower(), "application/octet-stream")
        try:
            data = target.read_bytes()
        except OSError:
            self.send_json(500, {"error": "Unable to read file."})
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    server_version = "VPNAdmin"
    sys_version = ""

    def log_message(self, message, *args):
        logger.info("%s %s", self.client_address[0], message % args)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        super().end_headers()

    def send_json(self, status, payload, headers=()):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, status, body, content_type, headers=()):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)

    def read_json(self):
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Expected an application/json request.")
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid request length.") from exc
        if size < 0 or size > MAX_BODY_SIZE:
            raise ValueError("Request body is too large.")
        try:
            value = json.loads(self.rfile.read(size))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Invalid JSON request.") from exc
        if not isinstance(value, dict):
            raise ValueError("Expected a JSON object.")
        return value

    def origin_is_valid(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        host = self.headers.get("Host", "")
        scheme = self.headers.get("X-Forwarded-Proto", "https")
        return hmac.compare_digest(origin.rstrip("/"), f"{scheme}://{host}".rstrip("/"))

    def get_session(self):
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return None
        morsel = cookie.get(SESSION_COOKIE)
        if morsel is None:
            return None
        token_hash = hashlib.sha256(morsel.value.encode("ascii", errors="ignore")).digest()
        with database() as connection:
            row = connection.execute(
                "SELECT sessions.username, sessions.csrf_token, sessions.expires_at, admins.must_change_password "
                "FROM sessions JOIN admins USING(username) WHERE sessions.token_hash = ?",
                (token_hash,),
            ).fetchone()
            if row is not None and row["expires_at"] < int(time.time()):
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
                return None
        if row is None:
            return None
        return {
            "username": row["username"],
            "csrf_token": row["csrf_token"],
            "must_change_password": bool(row["must_change_password"]),
            "token_hash": token_hash,
        }

    def get_client_session(self):
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return None
        morsel = cookie.get(CLIENT_SESSION_COOKIE)
        if morsel is None:
            return None
        token_hash = hashlib.sha256(morsel.value.encode("ascii", errors="ignore")).digest()
        with database() as connection:
            row = connection.execute(
                "SELECT client_sessions.client_id, vpn_clients.username, client_sessions.csrf_token, client_sessions.expires_at, vpn_clients.must_change_password "
                "FROM client_sessions JOIN vpn_clients ON vpn_clients.id = client_sessions.client_id WHERE client_sessions.token_hash = ?",
                (token_hash,),
            ).fetchone()
            if row is not None and row["expires_at"] < int(time.time()):
                connection.execute("DELETE FROM client_sessions WHERE token_hash = ?", (token_hash,))
                return None
        if row is None:
            return None
        return {
            "client_id": row["client_id"],
            "username": row["username"],
            "csrf_token": row["csrf_token"],
            "must_change_password": bool(row["must_change_password"]),
            "token_hash": token_hash,
        }

    def require_client_session(self, allow_forced_password_change=False):
        session = self.get_client_session()
        if session is None:
            self.send_json(401, {"error": "Client sign-in required."})
            return None
        if session["must_change_password"] and not allow_forced_password_change:
            self.send_json(428, {"error": "Change your temporary password before continuing."})
            return None
        return session

    def require_client_csrf(self, session):
        supplied = self.headers.get("X-CSRF-Token", "")
        if not supplied or not hmac.compare_digest(supplied, session["csrf_token"]):
            self.send_json(403, {"error": "Invalid CSRF token."})
            return False
        return True

    def require_session(self, allow_forced_password_change=False):
        session = self.get_session()
        if session is None:
            self.send_json(401, {"error": "Authentication required."})
            return None
        if session["must_change_password"] and not allow_forced_password_change:
            self.send_json(428, {"error": "Change the initial password before continuing."})
            return None
        return session

    def require_csrf(self, session):
        supplied = self.headers.get("X-CSRF-Token", "")
        if not supplied or not hmac.compare_digest(supplied, session["csrf_token"]):
            self.send_json(403, {"error": "Invalid CSRF token."})
            return False
        return True

    def set_session_cookie(self, token):
        return ("Set-Cookie", f"{SESSION_COOKIE}={token}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; Secure; SameSite=Strict")

    def clear_session_cookie(self):
        return ("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict")

    def set_client_session_cookie(self, token):
        return ("Set-Cookie", f"{CLIENT_SESSION_COOKIE}={token}; Path=/; Max-Age={CLIENT_SESSION_TTL}; HttpOnly; Secure; SameSite=Strict")

    def clear_client_session_cookie(self):
        return ("Set-Cookie", f"{CLIENT_SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict")

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/portal/session":
            expire_wireguard_clients()
            session = self.get_client_session()
            if session is None:
                self.send_json(200, {"authenticated": False})
            else:
                self.send_json(200, {
                    "authenticated": True,
                    "username": session["username"],
                    "csrfToken": session["csrf_token"],
                    "mustChangePassword": session["must_change_password"],
                })
            return

        if path == "/api/portal/account":
            session = self.require_client_session()
            if session is None:
                return
            try:
                self.send_json(200, {"account": get_wireguard_client_account(session["client_id"])})
            except ValueError as exc:
                self.send_json(410, {"error": str(exc)}, [self.clear_client_session_cookie()])
            return

        if path == "/api/portal/config":
            session = self.require_client_session()
            if session is None:
                return
            try:
                username, config = get_wireguard_client_config(session["client_id"])
            except ExpiredClientError as exc:
                self.send_json(410, {"error": str(exc)}, [self.clear_client_session_cookie()])
                return
            except (ValueError, RuntimeError) as exc:
                self.send_json(503, {"error": str(exc)})
                return
            self.send_text(
                200,
                config,
                "text/plain; charset=utf-8",
                [("Content-Disposition", f'attachment; filename="{username}.conf"')],
            )
            return

        if path == "/api/session":
            session = self.get_session()
            if session is None:
                self.send_json(200, {"authenticated": False})
            else:
                self.send_json(200, {
                    "authenticated": True,
                    "username": session["username"],
                    "csrfToken": session["csrf_token"],
                    "mustChangePassword": session["must_change_password"],
                })
            return

        if path == "/api/status":
            if self.require_session() is None:
                return
            try:
                payload = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self.send_json(503, {"error": "Node status is not available."})
                return
            self.send_json(200, payload)
            return

        if path == "/api/adblock":
            if self.require_session() is None:
                return
            self.send_json(200, {"adblock": read_adblock_state()})
            return

        if path == "/api/users":
            if self.require_session() is None:
                return
            self.send_json(200, {"users": list_admins()})
            return

        client_config_match = re.fullmatch(r"/api/clients/([a-f0-9]{32})/config", path)
        if client_config_match:
            if self.require_session() is None:
                return
            try:
                username, config = get_wireguard_client_config(client_config_match.group(1))
            except ExpiredClientError as exc:
                self.send_json(410, {"error": str(exc)})
                return
            except ValueError as exc:
                self.send_json(404, {"error": str(exc)})
                return
            except RuntimeError as exc:
                self.send_json(503, {"error": str(exc)})
                return
            self.send_text(
                200,
                config,
                "text/plain; charset=utf-8",
                [("Content-Disposition", f'attachment; filename="{username}.conf"')],
            )
            return

        if path == "/api/clients":
            if self.require_session() is None:
                return
            try:
                self.send_json(200, {"clients": list_wireguard_clients()})
            except (OSError, sqlite3.Error):
                self.send_json(503, {"error": "VPN account data is unavailable."})
            return

        if not path.startswith("/api/"):
            self.serve_static(path)
            return
        self.send_json(404, {"error": "Not found."})

    def do_POST(self):
        path = urlsplit(self.path).path
        if not self.origin_is_valid():
            self.send_json(403, {"error": "Cross-origin request rejected."})
            return
        try:
            payload = self.read_json()
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
            return

        if path == "/api/portal/login":
            self.client_login(payload)
            return

        if path == "/api/portal/logout":
            session = self.require_client_session(allow_forced_password_change=True)
            if session is None or not self.require_client_csrf(session):
                return
            with database() as connection:
                connection.execute("DELETE FROM client_sessions WHERE token_hash = ?", (session["token_hash"],))
            self.send_json(200, {"ok": True}, [self.clear_client_session_cookie()])
            return

        if path == "/api/portal/password":
            self.change_client_password(payload)
            return

        if path == "/api/login":
            self.login(payload)
            return

        if path == "/api/logout":
            session = self.require_session(allow_forced_password_change=True)
            if session is None or not self.require_csrf(session):
                return
            with database() as connection:
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (session["token_hash"],))
            self.send_json(200, {"ok": True}, [self.clear_session_cookie()])
            return

        if path == "/api/password":
            self.change_password(payload)
            return

        session = self.require_session()
        if session is None or not self.require_csrf(session):
            return

        if path == "/api/adblock":
            enabled = payload.get("enabled")
            try:
                state = set_adblock_enabled(enabled)
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
                return
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                logger.warning("admin=%s action=adblock_toggle enabled=%s error=%s", session["username"], enabled, type(exc).__name__)
                self.send_json(503, {"error": str(exc)})
                return
            logger.info("admin=%s action=adblock_toggle enabled=%s", session["username"], enabled)
            self.send_json(200, {"adblock": state})
            return

        if path == "/api/users":
            try:
                username = payload.get("username")
                password = payload.get("password")
                add_admin(username, password)
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
                return
            logger.info("admin=%s action=add_admin target=%s", session["username"], username)
            self.send_json(201, {"ok": True, "username": username})
            return

        if path == "/api/clients":
            username = payload.get("username")
            duration_days = payload.get("durationDays")
            try:
                client, config = create_wireguard_client(username, duration_days)
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
                return
            except RuntimeError as exc:
                logger.warning("admin=%s action=create_vpn_client result=failed error=%s", session["username"], type(exc).__name__)
                self.send_json(503, {"error": str(exc)})
                return
            logger.info("admin=%s action=create_vpn_client target=%s protocol=wireguard", session["username"], username)
            self.send_json(201, {"client": client, "config": config})
            return

        client_password_match = re.fullmatch(r"/api/clients/([a-f0-9]{32})/password", path)
        if client_password_match:
            try:
                username, temporary_password = reset_client_portal_password(client_password_match.group(1))
            except ValueError as exc:
                self.send_json(404, {"error": str(exc)})
                return
            logger.info("admin=%s action=reset_vpn_client_password target=%s", session["username"], username)
            self.send_json(200, {"username": username, "temporaryPassword": temporary_password})
            return

        service_match = re.fullmatch(r"/api/services/([a-z]+)/restart", path)
        if service_match:
            service_key = service_match.group(1)
            if service_key not in SERVICE_UNITS:
                self.send_json(404, {"error": "Unknown service."})
                return
            try:
                unit = resolve_service_unit(service_key)
                result = subprocess.run(
                    ["systemctl", "restart", unit.removesuffix(".service")],
                    capture_output=True,
                    text=True,
                    timeout=45,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                logger.warning("admin=%s action=restart service=%s error=%s", session["username"], service_key, type(exc).__name__)
                self.send_json(502, {"error": "Service restart failed. Check the system journal."})
                return
            if result.returncode != 0:
                logger.warning("admin=%s action=restart service=%s result=failed", session["username"], service_key)
                self.send_json(502, {"error": "Service restart failed. Check the system journal."})
                return
            logger.info("admin=%s action=restart service=%s result=ok", session["username"], service_key)
            try:
                subprocess.run(
                    ["systemctl", "start", "vpn-status-refresh.service"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                logger.warning("admin=%s action=refresh_status result=failed", session["username"])
            self.send_json(200, {"ok": True, "service": service_key})
            return

        self.send_json(404, {"error": "Not found."})

    def do_DELETE(self):
        path = urlsplit(self.path).path
        if not self.origin_is_valid():
            self.send_json(403, {"error": "Cross-origin request rejected."})
            return
        session = self.require_session()
        if session is None or not self.require_csrf(session):
            return
        client_match = re.fullmatch(r"/api/clients/([a-f0-9]{32})", path)
        if client_match:
            try:
                revoke_wireguard_client(client_match.group(1))
            except ValueError as exc:
                self.send_json(404, {"error": str(exc)})
                return
            except RuntimeError as exc:
                logger.warning("admin=%s action=revoke_vpn_client result=failed error=%s", session["username"], type(exc).__name__)
                self.send_json(503, {"error": str(exc)})
                return
            logger.info("admin=%s action=revoke_vpn_client id=%s", session["username"], client_match.group(1))
            self.send_json(200, {"ok": True})
            return
        match = re.fullmatch(r"/api/users/([^/]+)", path)
        if not match:
            self.send_json(404, {"error": "Not found."})
            return
        username = unquote(match.group(1))
        try:
            delete_admin(username, session["username"])
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
            return
        logger.info("admin=%s action=remove_admin target=%s", session["username"], username)
        self.send_json(200, {"ok": True})

    def login(self, payload):
        client_ip = self.headers.get("X-Real-IP") or self.client_address[0]
        if not login_allowed(client_ip):
            self.send_json(429, {"error": "Too many failed sign-in attempts. Try again later."})
            return
        username = payload.get("username", "")
        password = payload.get("password", "")
        if not isinstance(username, str) or not isinstance(password, str):
            user = None
        else:
            user = verify_password(username, password)
        if user is None:
            record_login_failure(client_ip)
            self.send_json(401, {"error": "Username or password is incorrect."})
            return
        clear_login_failures(client_ip)
        token, csrf_token = new_session(username)
        logger.info("admin=%s action=login", username)
        self.send_json(200, {
            "authenticated": True,
            "username": username,
            "csrfToken": csrf_token,
            "mustChangePassword": user["must_change_password"],
        }, [self.set_session_cookie(token)])

    def client_login(self, payload):
        client_ip = f"client:{self.headers.get('X-Real-IP') or self.client_address[0]}"
        if not login_allowed(client_ip):
            self.send_json(429, {"error": "Too many failed sign-in attempts. Try again later."})
            return
        username = payload.get("username", "")
        password = payload.get("password", "")
        user = verify_client_password(username, password) if isinstance(username, str) and isinstance(password, str) else None
        if user is None:
            record_login_failure(client_ip)
            self.send_json(401, {"error": "Username or password is incorrect."})
            return
        clear_login_failures(client_ip)
        token, csrf_token = new_client_session(user["id"])
        logger.info("vpn_client=%s action=portal_login", username)
        self.send_json(200, {
            "authenticated": True,
            "username": username,
            "csrfToken": csrf_token,
            "mustChangePassword": user["must_change_password"],
        }, [self.set_client_session_cookie(token)])

    def change_client_password(self, payload):
        session = self.require_client_session(allow_forced_password_change=True)
        if session is None or not self.require_client_csrf(session):
            return
        old_password = payload.get("oldPassword", "")
        new_password = payload.get("newPassword", "")
        user = verify_client_password(session["username"], old_password) if isinstance(old_password, str) else None
        if user is None or user["id"] != session["client_id"]:
            self.send_json(401, {"error": "Current password is incorrect."})
            return
        try:
            validate_password(new_password)
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
            return
        salt = secrets.token_bytes(16)
        digest = password_digest(new_password, salt)
        with database() as connection:
            connection.execute(
                "UPDATE vpn_clients SET password_salt = ?, password_hash = ?, must_change_password = 0 WHERE id = ?",
                (salt, digest, session["client_id"]),
            )
            connection.execute("DELETE FROM client_sessions WHERE client_id = ?", (session["client_id"],))
        token, csrf_token = new_client_session(session["client_id"])
        logger.info("vpn_client=%s action=portal_password_change", session["username"])
        self.send_json(200, {
            "ok": True,
            "username": session["username"],
            "csrfToken": csrf_token,
            "mustChangePassword": False,
        }, [self.set_client_session_cookie(token)])

    def change_password(self, payload):
        session = self.require_session(allow_forced_password_change=True)
        if session is None or not self.require_csrf(session):
            return
        old_password = payload.get("oldPassword", "")
        new_password = payload.get("newPassword", "")
        user = verify_password(session["username"], old_password) if isinstance(old_password, str) else None
        if user is None:
            self.send_json(401, {"error": "Current password is incorrect."})
            return
        try:
            validate_password(new_password)
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
            return
        salt = secrets.token_bytes(16)
        digest = password_digest(new_password, salt)
        with database() as connection:
            connection.execute(
                "UPDATE admins SET salt = ?, password_hash = ?, must_change_password = 0 WHERE username = ?",
                (salt, digest, session["username"]),
            )
            connection.execute("DELETE FROM sessions WHERE username = ?", (session["username"],))
        token, csrf_token = new_session(session["username"])
        logger.info("admin=%s action=change_password", session["username"])
        self.send_json(200, {
            "ok": True,
            "username": session["username"],
            "csrfToken": csrf_token,
            "mustChangePassword": False,
        }, [self.set_session_cookie(token)])


def serve(host, port):
    address = ipaddress.ip_address(host)
    if not address.is_loopback:
        raise ValueError("The admin API must bind to a loopback address.")
    init_database()
    threading.Thread(target=wireguard_expiry_worker, daemon=True, name="wireguard-expiry").start()
    server = ThreadingHTTPServer((host, port), AdminHandler)
    server.daemon_threads = True
    logger.info("Admin API listening on %s:%s", host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def wireguard_expiry_worker():
    while True:
        try:
            expire_wireguard_clients()
        except Exception as exc:
            logger.warning("action=expire_vpn_clients error=%s", type(exc).__name__)
        time.sleep(30)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--init-admin", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.init_admin:
        init_database()
        with database() as connection:
            existing_admins = connection.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
        if existing_admins:
            print("Admin database already initialized; existing accounts were preserved.")
            return
        username = os.environ.get("VPN_ADMIN_INITIAL_USER", "saeka")
        password = os.environ.get("VPN_ADMIN_INITIAL_PASSWORD", "")
        if not password:
            parser.error("VPN_ADMIN_INITIAL_PASSWORD must be provided through the environment.")
        created = bootstrap_admin(username, password)
        print("Initial admin created; password change is required on first sign-in." if created else "Admin database already initialized; existing accounts were preserved.")
        return
    serve(args.host, args.port)


if __name__ == "__main__":
    main()