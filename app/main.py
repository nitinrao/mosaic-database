from __future__ import annotations

import hashlib
import asyncio
from collections import OrderedDict
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request
from glob import glob
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dataclasses import dataclass
from typing import Annotated, Any, Callable, Literal, Protocol

from cryptography.fernet import Fernet, InvalidToken
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

try:
    import psycopg
    from psycopg import sql as psycopg_sql
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    psycopg_sql = None
    dict_row = None

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("MOSAIC_DB_PATH", ROOT / "mosaic-database.db"))
DATABASE_URL = os.getenv("MOSAIC_DATABASE_URL", "")
DATABASE_URLS = [x.strip() for x in os.getenv("MOSAIC_DATABASE_URLS", "").split(",") if x.strip()]
ADMIN_KEY = os.getenv("MOSAIC_ADMIN_KEY", "")
CREDENTIAL_ENCRYPTION_KEY = os.getenv("MOSAIC_CREDENTIAL_ENCRYPTION_KEY", "")
BRANCH_ROOT = Path(os.getenv("MOSAIC_BRANCH_ROOT", ROOT / "data"))
BRANCH_ENGINE_NAME = os.getenv("MOSAIC_BRANCH_ENGINE", "copy")
IDLE_REAPER_SECONDS = int(os.getenv("MOSAIC_BRANCH_IDLE_SECONDS", "900"))
PORT_MIN = int(os.getenv("MOSAIC_POSTGRES_PORT_MIN", "55432"))
RATE_LIMIT_REQUESTS = int(os.getenv("MOSAIC_RATE_LIMIT_REQUESTS", "120"))
PUBLIC_SIGNUP_RATE_LIMIT_REQUESTS = int(os.getenv("MOSAIC_PUBLIC_SIGNUP_RATE_LIMIT_REQUESTS", "5"))
PUBLIC_LISTENER = os.getenv("MOSAIC_PUBLIC_LISTENER", "").lower() == "true"
RATE_LIMIT_SWEEP_THRESHOLD = 256
RATE_LIMIT_SWEEP_INTERVAL_SECONDS = 60.0
MAX_DATABASES_TOTAL = int(os.getenv("MOSAIC_MAX_DATABASES_TOTAL", "50"))
MOSAIC_PUBLIC_ENDPOINT = os.getenv("MOSAIC_PUBLIC_ENDPOINT", "https://database-api.mosaicos.com")
MOSAIC_INTROSPECTION_URL = os.getenv(
    "MOSAIC_INTROSPECTION_URL",
    "https://sandbox.mosaicos.com/v1/introspect",
)
MOSAIC_INTROSPECTION_TIMEOUT_SECONDS = float(
    os.getenv("MOSAIC_INTROSPECTION_TIMEOUT_SECONDS", "3")
)
TRUST_CLOUDFLARE_IP = os.getenv("MOSAIC_TRUST_CLOUDFLARE_IP", "").lower() == "true"
NODE_ID = os.getenv("MOSAIC_NODE_ID", "local")
PROMOTION_MAX_LAG_BYTES = int(os.getenv("MOSAIC_PROMOTION_MAX_LAG_BYTES", str(10 * 1024 * 1024 * 1024)))
PROMOTION_MAX_LAG_AGE_SECONDS = int(os.getenv("MOSAIC_PROMOTION_MAX_LAG_AGE_SECONDS", "300"))
NODE_AGENT_TOKEN = os.getenv("MOSAIC_NODE_AGENT_TOKEN", "")
NODE_AGENT_CA_BUNDLE = os.getenv("MOSAIC_NODE_AGENT_CA_BUNDLE", "")
ALLOW_PLAINTEXT_NODE_AGENT = os.getenv("MOSAIC_ALLOW_PLAINTEXT_NODE_AGENT", "").lower() == "true"
REPLICATION_WAL_RETENTION_BYTES = int(os.getenv("MOSAIC_REPLICATION_WAL_RETENTION_BYTES", str(10 * 1024**3)))
REPLICATION_USER_PREFIX = "mosaic_repl_"
REPLICATION_SLOT_INACTIVE_POLLS = 20
REPLICATION_SLOT_INACTIVE_POLL_SECONDS = 0.05
RESERVED_BRANCH_NAMES = {".replicas", "replicas"}
PLANS = {
    "shared": {"monthly_cents": 10000, "max_databases": 5, "max_branches": 20, "max_rows": 10000, "max_bytes": 1000000, "statement_timeout_ms": 5000, "max_deploy_operations": 20, "max_deploys_per_day": 50},
    "dedicated": {"monthly_cents": 50000, "max_databases": 20, "max_branches": 100, "max_rows": 100000, "max_bytes": 10000000, "statement_timeout_ms": 30000, "max_deploy_operations": 100, "max_deploys_per_day": 200},
}
MCP_PROTOCOL_VERSION = "2025-03-26"
MCP_TOOLS = [{"name": n, "description": d, "inputSchema": {"type": "object"}} for n, d in (
    ("inspect_schema", "Inspect branch schema"), ("query", "Execute one governed statement"),
    ("deploy", "Create a declarative schema deploy"), ("get_deploy", "Get a schema deploy"),
    ("create_branch", "Create a branch"), ("list_branches", "List branches"))]
_rate: dict[str, list[float]] = {}
_rate_lock = threading.Lock()
_rate_last_sweep = 0.0
logger = logging.getLogger(__name__)


@dataclass
class MosaicIdentityCacheEntry:
    identity: dict | None
    cached_at: float
    expires_at: float
    stale_until: float


_mosaic_identity_cache: OrderedDict[str, MosaicIdentityCacheEntry] = OrderedDict()
_mosaic_identity_cache_lock = threading.Lock()


def background_interval(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        return max(1, int(raw))
    except ValueError:
        logger.warning("invalid %s=%r; using %ss", name, raw, default)
        return default


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def token(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(18)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def mosaic_identity_cache_ttl(negative: bool = False) -> float:
    name = "MOSAIC_INTROSPECTION_NEGATIVE_TTL_SECONDS" if negative else "MOSAIC_INTROSPECTION_CACHE_TTL_SECONDS"
    default = "2" if negative else "3"
    try:
        return max(0.0, float(os.getenv(name, default)))
    except ValueError:
        return float(default)


def mosaic_identity_stale_seconds() -> float:
    try:
        return max(0.0, float(os.getenv("MOSAIC_INTROSPECTION_STALE_SECONDS", "60")))
    except ValueError:
        return 60.0


def mosaic_identity_cache_cap() -> int:
    try:
        return max(1, int(os.getenv("MOSAIC_INTROSPECTION_CACHE_CAP", "1024")))
    except ValueError:
        return 1024


def _mosaic_cache_get(key_digest: str, current: float) -> tuple[dict | None, bool] | None:
    with _mosaic_identity_cache_lock:
        entry = _mosaic_identity_cache.get(key_digest)
        if not entry:
            return None
        _mosaic_identity_cache.move_to_end(key_digest)
        if current <= entry.expires_at:
            return entry.identity, False
        if entry.identity is not None and current <= entry.stale_until:
            return entry.identity, True
        if entry.identity is None:
            _mosaic_identity_cache.pop(key_digest, None)
        return None


def _mosaic_cache_put(key_digest: str, identity: dict | None, current: float):
    negative = identity is None
    ttl = mosaic_identity_cache_ttl(negative)
    stale_until = current + ttl
    if not negative:
        stale_until += mosaic_identity_stale_seconds()
    entry = MosaicIdentityCacheEntry(identity, current, current + ttl, stale_until)
    with _mosaic_identity_cache_lock:
        _mosaic_identity_cache[key_digest] = entry
        _mosaic_identity_cache.move_to_end(key_digest)
        while len(_mosaic_identity_cache) > mosaic_identity_cache_cap():
            _mosaic_identity_cache.popitem(last=False)


def _mosaic_identity_unavailable() -> HTTPException:
    return HTTPException(503, "identity service unavailable")


def _parse_mosaic_identity(body: bytes) -> dict:
    try:
        payload = json.loads(body)
    except (TypeError, ValueError) as exc:
        raise _mosaic_identity_unavailable() from exc
    if not isinstance(payload, dict):
        raise _mosaic_identity_unavailable()
    organization_id = payload.get("organization_id")
    scopes = payload.get("scopes")
    status = payload.get("status")
    if not isinstance(organization_id, str) or not organization_id:
        raise _mosaic_identity_unavailable()
    if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
        raise _mosaic_identity_unavailable()
    if not isinstance(status, str):
        raise _mosaic_identity_unavailable()
    return {
        "organization_id": organization_id,
        "scopes": scopes,
        "resource_profile": payload.get("resource_profile"),
        "status": status,
    }


def introspect_mosaic_key(key: str) -> dict:
    url = os.getenv("MOSAIC_INTROSPECTION_URL", MOSAIC_INTROSPECTION_URL)
    if not url:
        raise HTTPException(401, "invalid tenant API key")
    key_digest = digest(key)
    current = time.time()
    cached = _mosaic_cache_get(key_digest, current)
    if cached is not None:
        identity, stale = cached
        if identity is None:
            raise HTTPException(401, "invalid tenant API key")
        if not stale:
            return identity
    request = urllib.request.Request(
        url,
        method="POST",
        headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(
            request,
            timeout=float(os.getenv(
                "MOSAIC_INTROSPECTION_TIMEOUT_SECONDS",
                str(MOSAIC_INTROSPECTION_TIMEOUT_SECONDS),
            )),
        ) as response:
            status = getattr(response, "status", None)
            if status is None:
                status = response.getcode()
            body = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            _mosaic_cache_put(key_digest, None, current)
            raise HTTPException(401, "invalid tenant API key") from None
        if exc.code < 500:
            raise _mosaic_identity_unavailable() from None
        cached = _mosaic_cache_get(key_digest, current)
        if cached is not None and cached[0] is not None:
            return cached[0]
        raise _mosaic_identity_unavailable() from None
    except (OSError, TimeoutError, ValueError):
        cached = _mosaic_cache_get(key_digest, current)
        if cached is not None and cached[0] is not None:
            return cached[0]
        raise _mosaic_identity_unavailable() from None
    if status == 401:
        _mosaic_cache_put(key_digest, None, current)
        raise HTTPException(401, "invalid tenant API key")
    if status >= 500:
        cached = _mosaic_cache_get(key_digest, current)
        if cached is not None and cached[0] is not None:
            return cached[0]
        raise _mosaic_identity_unavailable()
    if status != 200:
        raise _mosaic_identity_unavailable()
    identity = _parse_mosaic_identity(body)
    if identity["status"] != "active":
        _mosaic_cache_put(key_digest, None, current)
        raise HTTPException(401, "Mosaic identity is not active")
    _mosaic_cache_put(key_digest, identity, current)
    return identity


def normalize_email(value: str) -> str:
    return value.strip().lower()


def derive_tenant_name(email: str, requested_name: str) -> str:
    clean_name = requested_name.strip().replace("\n", " ")
    if clean_name:
        return clean_name[:100]
    local_part = re.split(r"[@._-]+", email.split("@", 1)[0])[0] or "Workspace"
    return f"{local_part} workspace"[:100]


def replication_identifier(database_id: str, node_id: str | None = None) -> str:
    value = database_id if node_id is None else f"{database_id}\0{node_id}"
    return "mosaic_" + hashlib.sha256(value.encode()).hexdigest()[:56]


def pg_bin(name: str) -> str:
    configured = os.getenv("MOSAIC_PG_BIN_DIR")
    candidates = [str(Path(configured) / name)] if configured else []
    candidates += [shutil.which(name) or ""]
    candidates += sorted(glob(f"/usr/lib/postgresql/*/bin/{name}"), reverse=True)
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return name


def configured_nodes() -> list[tuple[str, str]]:
    raw = os.getenv("MOSAIC_NODE_HOSTS", "local")
    nodes = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        node_id, separator, address = item.partition("=")
        nodes.append((node_id.strip(), address.strip() if separator else ""))
    return nodes or [("local", "")]


def node_ids() -> list[str]:
    return [node_id for node_id, _ in configured_nodes()]


def node_url(node_id: str) -> str:
    for configured_id, address in configured_nodes():
        if configured_id == node_id:
            return address
    raise RuntimeError(f"unknown database node {node_id}")


def node_private_addresses() -> dict[str, str]:
    raw = os.getenv("MOSAIC_NODE_PRIVATE_ADDRESSES", "")
    result = {}
    for item in raw.split(","):
        node_id, separator, address = item.strip().partition("=")
        if separator and node_id and address:
            result[node_id.strip()] = address.strip()
    return result


def node_address(node_id: str) -> str:
    if node_id not in node_ids():
        raise RuntimeError(f"unknown database node {node_id}")
    if node_id == "local" and len(node_ids()) == 1 and not node_private_addresses().get(node_id):
        return "127.0.0.1"
    address = node_private_addresses().get(node_id)
    if not address:
        if len(node_ids()) == 1 and node_id == "local":
            return "127.0.0.1"
        raise RuntimeError("MOSAIC_NODE_PRIVATE_ADDRESSES must map every configured node for multi-host deployment")
    return address


def placement_node(database_id: str) -> str:
    nodes = node_ids()
    index = int.from_bytes(hashlib.sha256(database_id.encode()).digest()[:8], "big") % len(nodes)
    return nodes[index]


class Conn:
    def __init__(self, raw, postgres: bool):
        self.raw, self.postgres = raw, postgres

    def execute(self, sql: str, params=()):
        return self.raw.execute(sql.replace("?", "%s") if self.postgres else sql, params)

    def script(self, sql: str):
        if self.postgres:
            for statement in sql.split(";"):
                if statement.strip():
                    self.raw.execute(statement)
        else:
            self.raw.executescript(sql)

    def commit(self):
        self.raw.commit()

    def rollback(self):
        self.raw.rollback()

    def close(self):
        self.raw.close()


def db() -> Conn:
    urls = DATABASE_URLS or ([DATABASE_URL] if DATABASE_URL else [])
    if urls:
        if psycopg is None:
            raise RuntimeError("psycopg is required for PostgreSQL control plane")
        last = None
        for url in urls:
            try:
                return Conn(psycopg.connect(url, row_factory=dict_row), True)
            except Exception as exc:
                last = exc
        raise RuntimeError("unable to connect to control-plane PostgreSQL") from last
    raw = sqlite3.connect(DB_PATH, check_same_thread=False)
    raw.row_factory = sqlite3.Row
    raw.execute("PRAGMA foreign_keys=ON")
    return Conn(raw, False)


def initialize_schema(c: Conn):
    integer = "BIGSERIAL PRIMARY KEY" if c.postgres else "INTEGER PRIMARY KEY AUTOINCREMENT"
    c.script(f"""
    CREATE TABLE IF NOT EXISTS tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL, plan TEXT NOT NULL, api_key_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, origin TEXT NOT NULL DEFAULT 'local');
    CREATE TABLE IF NOT EXISTS mosaic_organization_tenants (organization_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL UNIQUE REFERENCES tenants(id), created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS public_signups (email TEXT PRIMARY KEY, tenant_id TEXT NOT NULL UNIQUE REFERENCES tenants(id), tenant_name TEXT NOT NULL, last_key_created_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS databases (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), name TEXT NOT NULL, root_path TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(tenant_id,name));
    CREATE TABLE IF NOT EXISTS branches (id TEXT PRIMARY KEY, database_id TEXT NOT NULL REFERENCES databases(id), name TEXT NOT NULL, parent_id TEXT, path TEXT NOT NULL, port INTEGER NOT NULL, pid INTEGER, status TEXT NOT NULL, credential_encrypted TEXT NOT NULL, last_query_at TEXT NOT NULL, created_at TEXT NOT NULL, host_id TEXT NOT NULL DEFAULT 'local', UNIQUE(database_id,name));
    CREATE TABLE IF NOT EXISTS replication_credentials (database_id TEXT PRIMARY KEY REFERENCES databases(id), username TEXT NOT NULL, credential_encrypted TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS replicas (id TEXT PRIMARY KEY, database_id TEXT NOT NULL REFERENCES databases(id), primary_branch_id TEXT NOT NULL REFERENCES branches(id), host_id TEXT NOT NULL, path TEXT NOT NULL, port INTEGER NOT NULL, status TEXT NOT NULL, lag_bytes INTEGER, lag_sampled_at TEXT, created_at TEXT NOT NULL, slot_name TEXT NOT NULL DEFAULT '', attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT, last_error TEXT, UNIQUE(database_id,host_id));
    CREATE TABLE IF NOT EXISTS abandoned_clusters (id TEXT PRIMARY KEY, database_id TEXT NOT NULL REFERENCES databases(id), host_id TEXT NOT NULL, path TEXT NOT NULL, port INTEGER NOT NULL, created_at TEXT NOT NULL, reason TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS usage_events (id {integer}, tenant_id TEXT NOT NULL REFERENCES tenants(id), kind TEXT NOT NULL, quantity INTEGER NOT NULL, unit TEXT NOT NULL, occurred_at TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{{}}', idempotency_key TEXT NOT NULL DEFAULT '');
    CREATE TABLE IF NOT EXISTS audit_log (id {integer}, tenant_id TEXT, action TEXT NOT NULL, actor TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{{}}', created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS deploy_requests (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), database_id TEXT NOT NULL REFERENCES databases(id), branch_id TEXT NOT NULL REFERENCES branches(id), operations TEXT NOT NULL, sql_preview TEXT NOT NULL, status TEXT NOT NULL, schema_version INTEGER NOT NULL DEFAULT 0, error TEXT, idempotency_key TEXT NOT NULL DEFAULT '', source_deploy_id TEXT, created_at TEXT NOT NULL, applied_at TEXT);
    CREATE TABLE IF NOT EXISTS deploy_locks (branch_id TEXT PRIMARY KEY REFERENCES branches(id), deploy_id TEXT NOT NULL UNIQUE REFERENCES deploy_requests(id), started_at TEXT NOT NULL);
    """)
    columns = (
        [row["column_name"] for row in c.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name='branches'"
        ).fetchall()]
        if c.postgres
        else [row["name"] for row in c.execute("PRAGMA table_info(branches)").fetchall()]
    )
    if "host_id" not in columns:
        c.execute("ALTER TABLE branches ADD COLUMN host_id TEXT NOT NULL DEFAULT 'local'")
    tenant_columns = (
        [row["column_name"] for row in c.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name='tenants'"
        ).fetchall()]
        if c.postgres
        else [row["name"] for row in c.execute("PRAGMA table_info(tenants)").fetchall()]
    )
    if "origin" not in tenant_columns:
        c.execute("ALTER TABLE tenants ADD COLUMN origin TEXT NOT NULL DEFAULT 'local'")
    replica_columns = (
        [row["column_name"] for row in c.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name='replicas'"
        ).fetchall()]
        if c.postgres
        else [row["name"] for row in c.execute("PRAGMA table_info(replicas)").fetchall()]
    )
    if "slot_name" not in replica_columns:
        c.execute("ALTER TABLE replicas ADD COLUMN slot_name TEXT NOT NULL DEFAULT ''")
    for column, definition in (
        ("attempts", "INTEGER NOT NULL DEFAULT 0"),
        ("next_attempt_at", "TEXT"),
        ("last_error", "TEXT"),
    ):
        if column not in replica_columns:
            c.execute(f"ALTER TABLE replicas ADD COLUMN {column} {definition}")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS usage_idempotency ON usage_events(tenant_id,idempotency_key) WHERE idempotency_key <> ''")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS deploy_idempotency ON deploy_requests(tenant_id,idempotency_key) WHERE idempotency_key <> ''")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS branches_port_unique ON branches(port)")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS replicas_port_unique ON replicas(port)")
    c.commit()


def cipher() -> Fernet:
    if not CREDENTIAL_ENCRYPTION_KEY:
        raise RuntimeError("MOSAIC_CREDENTIAL_ENCRYPTION_KEY is required")
    return Fernet(CREDENTIAL_ENCRYPTION_KEY.encode())


CommandRunner = Callable[[list[str], dict[str, str] | None], Any]


def command_environment(overlay: dict[str, str] | None = None) -> dict[str, str] | None:
    return {**os.environ, **overlay} if overlay else None


class BranchEngine(Protocol):
    def create_database(self, path: Path, password: str, port: int, host_id: str = "local") -> None: ...
    def clone(self, parent: Path, target: Path, *, parent_port: int | None = None, parent_password: str | None = None, target_port: int | None = None, parent_host_id: str = "local", target_host_id: str = "local") -> None: ...
    def destroy(self, path: Path) -> None: ...
    def prepare_standby(self, path: Path, *, is_stopped: Callable[[Path], bool] | None = None) -> None: ...


class ZfsCommandError(RuntimeError):
    def __init__(self, argv: list[str], cause: subprocess.CalledProcessError):
        details = [f"command {argv!r} failed"]
        for label, output in (("stderr", cause.stderr), ("stdout", cause.stdout)):
            if output:
                details.append(f"{label}: {str(output).strip()}")
        super().__init__(redact_error("; ".join(details)))
        self.argv = argv
        self.cause = cause
        self.stderr = cause.stderr
        self.stdout = cause.stdout


class ZfsBranchEngine:
    def __init__(self, pool: str | None = None, runner: CommandRunner | None = None):
        self.pool = pool or os.getenv("MOSAIC_ZFS_POOL", "rpool/mosaic")
        self.run = runner or (
            lambda argv, env=None: subprocess.run(
                argv, check=True, capture_output=True, text=True,
                env=command_environment(env),
            )
        )

    def _dataset(self, path: Path) -> str:
        try:
            relative = path.resolve().relative_to(BRANCH_ROOT.resolve())
        except ValueError:
            relative = Path(path.parent.name) / path.name
        return "/".join((self.pool, *relative.parts))

    def _run_zfs(self, argv: list[str]):
        try:
            return self.run(argv)
        except subprocess.CalledProcessError as exc:
            raise ZfsCommandError(argv, exc) from exc

    def _lazy_unmount(self, path: Path) -> None:
        root = BRANCH_ROOT.resolve()
        target = path.resolve()
        if target == root or root not in target.parents:
            raise RuntimeError(
                f"refusing lazy unmount outside MOSAIC_BRANCH_ROOT: {target}"
            )
        logger.warning("lazy-detaching ZFS standby mountpoint %s", target)
        self.run(["mosaic-umount", "-l", str(target)])

    def create_database(self, path: Path, password: str, port: int, host_id: str = "local"):
        self._run_zfs(["zfs", "create", "-p", "-o", f"mountpoint={path.resolve()}", self._dataset(path)])
        _initdb(path, password, port, self.run, host_id)

    def clone(self, parent: Path, target: Path, *, parent_port: int | None = None, parent_password: str | None = None, target_port: int | None = None, parent_host_id: str = "local", target_host_id: str = "local"):
        snap = f"{self._dataset(parent)}@branch-{target.name}"
        if parent_port:
            _checkpoint(parent_host_id, parent_port, parent_password)
        self._run_zfs(["zfs", "snapshot", snap])
        self._run_zfs(["zfs", "clone", "-o", f"mountpoint={target.resolve()}", snap, self._dataset(target)])
        _clear_cloned_runtime_state(target)
        if target_port is not None:
            _rewrite_postgres_config(target, target_port, target_host_id)

    def destroy(self, path: Path):
        self._run_zfs(["zfs", "destroy", "-r", self._dataset(path)])

    def prepare_standby(self, path: Path, *, is_stopped: Callable[[Path], bool] | None = None):
        dataset = self._dataset(path)
        try:
            self._run_zfs(["zfs", "list", "-H", "-o", "name", dataset])
        except ZfsCommandError as exc:
            detail = " ".join(
                part for part in (exc.stdout or "", exc.stderr or "", str(exc))
                if part
            ).lower()
            if "does not exist" not in detail and "dataset not found" not in detail:
                raise
            if path.exists():
                shutil.rmtree(path)
        else:
            try:
                self._run_zfs(["zfs", "destroy", "-r", dataset])
            except ZfsCommandError as exc:
                detail = str(exc).lower()
                if not any(marker in detail for marker in ("busy", "unmount failed", "umount failed")):
                    raise
                if is_stopped is None or not is_stopped(path):
                    raise RuntimeError(
                        f"cannot safely remove busy standby target {path}: "
                        "postmaster could not be proven stopped"
                    ) from exc
                try:
                    self._run_zfs(["zfs", "unmount", "-f", dataset])
                    self._run_zfs(["zfs", "destroy", "-r", dataset])
                except ZfsCommandError as unmount_error:
                    detail = str(unmount_error).lower()
                    if not any(
                        marker in detail
                        for marker in ("busy", "unmount failed", "umount failed")
                    ):
                        raise
                    self._lazy_unmount(path)
                    self._run_zfs(["zfs", "destroy", "-r", dataset])
        self._run_zfs(["zfs", "create", "-p", "-o", f"mountpoint={path.resolve()}", dataset])


class CopyBranchEngine:
    """CI engine: pg_basebackup is consistent; cp -a of a running PG dir is not."""
    def __init__(self, runner: CommandRunner | None = None):
        self.run = runner or (
            lambda argv, env=None: subprocess.run(
                argv, check=True, env=command_environment(env),
            )
        )

    def create_database(self, path: Path, password: str, port: int, host_id: str = "local"):
        _initdb(path, password, port, self.run, host_id)

    def clone(self, parent: Path, target: Path, *, parent_port: int | None = None, parent_password: str | None = None, target_port: int | None = None, parent_host_id: str = "local", target_host_id: str = "local"):
        target.parent.mkdir(parents=True, exist_ok=True)
        if parent_port:
            _checkpoint(parent_host_id, parent_port, parent_password)
            argv = [pg_bin("pg_basebackup"), "-D", str(target), "-h", node_address(parent_host_id), "-p", str(parent_port), "-U", "postgres", "-Fp", "-X", "stream", "-R"]
            self.run(
                argv,
                env={"PGPASSWORD": parent_password} if parent_password else None,
            )
        else:
            shutil.copytree(parent, target)
        _clear_cloned_runtime_state(target)
        if target_port is not None:
            _clear_standby_configuration(target, target_port, target_host_id)

    def destroy(self, path: Path):
        shutil.rmtree(path, ignore_errors=True)

    def prepare_standby(self, path: Path, *, is_stopped: Callable[[Path], bool] | None = None):
        shutil.rmtree(path, ignore_errors=True)


def engine() -> BranchEngine:
    return ZfsBranchEngine() if BRANCH_ENGINE_NAME == "zfs" else CopyBranchEngine()


def _initdb(path: Path, password: str, port: int, run: CommandRunner, host_id: str = "local"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", prefix="mosaic-pw-", delete=False) as pwfile:
        pwfile.write(password)
        pwfile_path = Path(pwfile.name)
    try:
        pwfile_path.chmod(0o600)
        run([pg_bin("initdb"), "-D", str(path), "-U", "postgres", "--auth=scram-sha-256", "--pwfile", str(pwfile_path)])
    finally:
        pwfile_path.unlink(missing_ok=True)
    _rewrite_postgres_config(path, port, host_id)


def _rewrite_postgres_config(
    path: Path,
    port: int,
    host_id: str = "local",
    *,
    replication_user: str | None = None,
    replication_addresses: list[str] | None = None,
    standby: bool = False,
):
    config = path / "postgresql.conf"
    if not config.exists():
        return
    listen_address = node_address(host_id)
    lines = config.read_text().splitlines()
    settings = re.compile(r"^\s*(?:port|listen_addresses|unix_socket_directories|max_slot_wal_keep_size|synchronous_standby_names|hot_standby)\s*=")
    retained = [line for line in lines if not settings.match(line)]
    retained.extend([
        f"port = {port}",
        f"listen_addresses = '{listen_address}'",
        f"unix_socket_directories = '{path.resolve()}'",
        "synchronous_standby_names = ''",
        f"hot_standby = {'off' if standby else 'on'}",
    ])
    if replication_user:
        retained.append(f"max_slot_wal_keep_size = {REPLICATION_WAL_RETENTION_BYTES}B")
    config.write_text("\n".join(retained) + "\n")
    if listen_address not in {"127.0.0.1", "::1"}:
        addresses = node_private_addresses()
        if set(node_ids()) - set(addresses):
            raise RuntimeError("MOSAIC_NODE_PRIVATE_ADDRESSES must map every configured node for multi-host deployment")
        hba = path / "pg_hba.conf"
        hba_lines = hba.read_text().splitlines() if hba.exists() else []
        begin = "# BEGIN MOSAIC DATABASE PEERS"
        end = "# END MOSAIC DATABASE PEERS"
        try:
            start = hba_lines.index(begin)
            finish = hba_lines.index(end, start)
            hba_lines = hba_lines[:start] + hba_lines[finish + 1:]
        except ValueError:
            pass
        managed = [begin, *(
            f"host all postgres {address}/32 scram-sha-256"
            for address in addresses.values()
        ), end]
        hba_lines = hba_lines + managed
        replication_begin = "# BEGIN MOSAIC DATABASE REPLICATION"
        replication_end = "# END MOSAIC DATABASE REPLICATION"
        try:
            start = hba_lines.index(replication_begin)
            finish = hba_lines.index(replication_end, start)
            hba_lines = hba_lines[:start] + hba_lines[finish + 1:]
        except ValueError:
            pass
        if replication_user and replication_addresses:
            hba_lines.extend([
                replication_begin,
                *(
                    f"host replication {replication_user} {address}/32 scram-sha-256"
                    for address in replication_addresses
                ),
                replication_end,
            ])
        hba.write_text("\n".join(hba_lines) + "\n")


def _clear_standby_configuration(path: Path, port: int, host_id: str):
    auto_conf = path / "postgresql.auto.conf"
    if auto_conf.exists():
        lines = auto_conf.read_text().splitlines()
        auto_conf.write_text(
            "\n".join(
                line for line in lines
                if not re.match(r"^\s*(?:primary_conninfo|primary_slot_name)\s*=", line)
            ) + ("\n" if lines else "")
        )
    (path / "standby.signal").unlink(missing_ok=True)
    _rewrite_postgres_config(path, port, host_id, standby=False)


def _clear_cloned_runtime_state(path: Path):
    for name in ("postmaster.pid", "postmaster.opts"):
        (path / name).unlink(missing_ok=True)


def _postmaster_pidfile_matches_path(path: Path) -> bool | None:
    try:
        lines = (path / "postmaster.pid").read_text().splitlines()
        if len(lines) < 2 or not lines[1].strip():
            return None
        return Path(lines[1]).resolve() == path.resolve()
    except (OSError, ValueError):
        return None


def _remove_foreign_postmaster_pidfile(path: Path):
    pidfile = path / "postmaster.pid"
    if not pidfile.exists():
        return
    if _postmaster_pidfile_matches_path(path) is False:
        pidfile.unlink()


def _checkpoint(host_id: str, port: int, password: str | None):
    if psycopg is None or not password:
        return
    with psycopg.connect(host=node_address(host_id), port=port, user="postgres", password=password, dbname="postgres", connect_timeout=5) as connection:
        connection.execute("CHECKPOINT")


def alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def branch_start_payload(c: Conn, row) -> dict:
    try:
        password = cipher().decrypt(row["credential_encrypted"].encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError(f"branch {row['id']} credentials cannot be decrypted") from exc
    parent_passwords = []
    if row["parent_id"]:
        parent = c.execute("SELECT credential_encrypted FROM branches WHERE id=?", (row["parent_id"],)).fetchone()
        if parent:
            try:
                parent_passwords.append(cipher().decrypt(parent["credential_encrypted"].encode()).decode())
            except InvalidToken as exc:
                raise RuntimeError(f"parent credentials for branch {row['id']} cannot be decrypted") from exc
    return {
        "branch_id": row["id"],
        "path": row["path"],
        "port": row["port"],
        "pid": row["pid"],
        "status": row["status"],
        "host_id": row["host_id"],
        "password": password,
        "parent_passwords": parent_passwords,
    }


def record_stop(c: Conn, row, result: dict):
    c.execute("UPDATE branches SET status=?,pid=? WHERE id=?", (result["status"], result["pid"], row["id"]))
    c.commit()


class Supervisor:
    def allocate_port(self, c: Conn) -> int:
        used = {int(row["port"]) for row in c.execute(
            "SELECT port FROM branches UNION ALL SELECT port FROM replicas "
            "UNION ALL SELECT port FROM abandoned_clusters"
        ).fetchall()}
        port = PORT_MIN
        while port in used:
            port += 1
        return port

    def start_local(self, payload: dict):
        path = Path(payload["path"])
        branch_id = payload["branch_id"]
        port = int(payload["port"])
        host_id = payload["host_id"]
        if payload.get("status") == "running" and alive(payload.get("pid")):
            return {"status": "running", "pid": payload["pid"]}
        if not (path / "PG_VERSION").exists():
            raise RuntimeError(f"branch {branch_id} has no PostgreSQL cluster at {path}")
        if psycopg is None:
            raise RuntimeError("psycopg is required to supervise PostgreSQL branches")
        branch_password = payload["password"]
        if not self._cluster_is_running(str(path)):
            _remove_foreign_postmaster_pidfile(path)
            subprocess.run([pg_bin("pg_ctl"), "-D", str(path), "-o", f"-p {port}", "-l", str(path / "postgres.log"), "-w", "start"], check=True, capture_output=True)
        self._reconcile_password(
            path,
            port,
            host_id,
            branch_id,
            branch_password,
            payload.get("parent_passwords", []),
        )
        pid = int((path / "postmaster.pid").read_text().splitlines()[0])
        return {"status": "running", "pid": pid}

    def _reconcile_password(
        self,
        path: Path,
        port: int,
        host_id: str,
        branch_id: str,
        branch_password: str,
        parent_passwords: list[str],
    ) -> None:
        try:
            with psycopg.connect(host=node_address(host_id), port=port, user="postgres", password=branch_password, dbname="postgres", connect_timeout=5):
                return
        except Exception:
            pass
        for candidate in parent_passwords:
            try:
                with psycopg.connect(host=node_address(host_id), port=port, user="postgres", password=candidate, dbname="postgres", connect_timeout=5) as connection:
                    connection.execute(psycopg_sql.SQL("ALTER ROLE postgres PASSWORD {}").format(psycopg_sql.Literal(branch_password)))
                    connection.commit()
                return
            except Exception:
                continue
        raise RuntimeError(f"unable to set password for branch {branch_id}")

    def _cluster_is_running(self, path: str, require_path: bool = False) -> bool:
        cluster_path = Path(path)
        if not cluster_path.exists():
            if require_path:
                raise RuntimeError(
                    f"cannot verify PostgreSQL cluster at {path}: data directory is absent"
                )
            return False
        if (cluster_path / "postmaster.pid").exists():
            pidfile_matches = _postmaster_pidfile_matches_path(cluster_path)
            if pidfile_matches is False:
                return False
        status_argv = [pg_bin("pg_ctl"), "-D", path, "status"]
        try:
            subprocess.run(status_argv, check=True, capture_output=True, text=True)
            return True
        except subprocess.CalledProcessError as exc:
            detail = " ".join(
                part for part in (exc.stdout or "", exc.stderr or "", str(exc))
                if part
            ).lower()
            if (
                "no server running" in detail
                or "not running" in detail
                or "does not exist" in detail
            ):
                return False
            if "not a database cluster directory" in detail:
                if require_path:
                    raise RuntimeError(
                        f"cannot verify PostgreSQL cluster at {path}: "
                        f"data directory is not a usable cluster ({_command_error_detail(exc)})"
                    ) from exc
                return False
            else:
                raise RuntimeError(
                    f"cannot verify PostgreSQL cluster at {path} is stopped: "
                    f"{_command_error_detail(exc)}"
                ) from exc

    def stop_local(self, payload: dict):
        require_path = bool(payload.get("require_path"))
        running = self._cluster_is_running(payload["path"], require_path=require_path)
        if running:
            subprocess.run(
                [pg_bin("pg_ctl"), "-D", payload["path"], "-m", "fast", "-w", "stop"],
                check=False,
                capture_output=True,
            )
            running = self._cluster_is_running(payload["path"], require_path=require_path)
            if running:
                raise RuntimeError(
                    f"PostgreSQL cluster at {payload['path']} is still running after stop"
                )
        return {"status": "stopped", "pid": None}

    def start(self, row, c: Conn):
        payload = branch_start_payload(c, row)
        result = self.start_local(payload)
        c.execute("UPDATE branches SET status=?,pid=? WHERE id=?", (result["status"], result["pid"], row["id"]))
        c.commit()
        return result

    def stop(self, row, c: Conn):
        result = self.stop_local({"path": row["path"], "pid": row["pid"]})
        record_stop(c, row, result)
        return result

    def reap(self, c: Conn, idle_seconds: int | None = None) -> int:
        if idle_seconds is None:
            idle_seconds = int(os.getenv("MOSAIC_BRANCH_IDLE_SECONDS", str(IDLE_REAPER_SECONDS)))
        cutoff = time.time() - idle_seconds
        count = 0
        for row in c.execute(
            "SELECT b.* FROM branches b "
            "WHERE b.status='running' "
            "AND NOT EXISTS (SELECT 1 FROM deploy_locks l WHERE l.branch_id=b.id) "
            "AND NOT EXISTS ("
            "SELECT 1 FROM replicas r WHERE r.primary_branch_id=b.id"
            ")"
        ).fetchall():
            if datetime.fromisoformat(row["last_query_at"]).timestamp() < cutoff:
                self.stop(row, c)
                count += 1
        return count


class NodeAgent:
    def __init__(self, runner: CommandRunner | None = None):
        self.run = runner or (
            lambda argv, env=None: subprocess.run(
                argv, check=True, capture_output=True, text=True,
                env=command_environment(env),
            )
        )
        self._standby_jobs: dict[Path, dict[str, str]] = {}
        self._standby_jobs_lock = threading.Lock()

    def _standby_status(self, target: Path) -> dict:
        with self._standby_jobs_lock:
            job = self._standby_jobs.get(target)
            if job and job.get("status") in {"building", "failed"}:
                return dict(job)
        if not (target / "postmaster.pid").exists():
            return {"status": "failed", "error": "standby postmaster is not running"}
        try:
            self.run([pg_bin("pg_ctl"), "-D", str(target), "status"])
        except Exception as exc:
            return {"status": "failed", "error": _command_error_detail(exc)}
        return {"status": "ready"}

    def _standby_status_is_not_running(self, target: Path) -> bool:
        if not target.exists():
            return True
        if (
            not (target / "PG_VERSION").exists()
            and not (target / "postmaster.pid").exists()
        ):
            return True
        try:
            self.run([pg_bin("pg_ctl"), "-D", str(target), "status"])
        except Exception as exc:
            detail = _command_error_detail(exc)
            normalized = detail.lower()
            if isinstance(exc, subprocess.CalledProcessError):
                if (
                    "not a database cluster directory" in normalized
                    or "does not exist" in normalized
                ):
                    return True
            if "no server running" in normalized or "not running" in normalized:
                return True
            pid = None
            try:
                pid = int((target / "postmaster.pid").read_text().splitlines()[0])
            except FileNotFoundError:
                return True
            except (ValueError, IndexError):
                return True
            except OSError as read_error:
                raise RuntimeError(
                    f"cannot remove standby target {target}: "
                    f"postmaster status could not be verified: "
                    f"{_command_error_detail(read_error)}"
                ) from read_error
            if not alive(pid):
                return True
            if _pid_owns_postgres_directory(pid, target):
                return False
            return True
        return False

    def _is_in_recovery(self, target: Path, payload: dict) -> bool:
        result = self.run([pg_bin("pg_controldata"), "-D", str(target)])
        output = getattr(result, "stdout", result)
        if isinstance(output, bytes):
            output = output.decode()
        state = None
        for line in str(output).splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip() == "Database cluster state":
                state = value.strip().lower()
                break
        if state == "in production":
            return False
        if state and "recovery" in state:
            return True
        signal_state = "present" if (target / "standby.signal").exists() else "absent"
        if state is None:
            raise RuntimeError(
                f"could not determine PostgreSQL recovery state from {target} "
                f"(standby.signal {signal_state})"
            )
        raise RuntimeError(
            f"unsupported PostgreSQL cluster state {state!r} at {target} "
            f"(standby.signal {signal_state})"
        )

    def promote_standby(self, target: Path, payload: dict) -> dict:
        with self._standby_jobs_lock:
            self._standby_jobs.pop(target, None)
        recovery = self._is_in_recovery(target, payload)
        if recovery:
            self.run([
                pg_bin("pg_ctl"), "-D", str(target), "promote",
            ])
            deadline = time.monotonic() + float(payload.get("promotion_timeout", 30))
            while time.monotonic() < deadline:
                if not self._is_in_recovery(target, payload):
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError("standby promotion did not leave recovery")
        _clear_standby_configuration(
            target,
            int(payload["target_port"]),
            payload["target_host_id"],
        )
        self.run([pg_bin("pg_ctl"), "-D", str(target), "reload"])
        pid = int((target / "postmaster.pid").read_text().splitlines()[0])
        return {
            "status": "promoted",
            "pid": pid,
            "port": int(payload["target_port"]),
        }

    def _run_standby_build(self, target: Path, payload: dict):
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                postmaster_pid = None
                pid_file = target / "postmaster.pid"
                if (target / "postmaster.pid").exists():
                    try:
                        postmaster_pid = int(pid_file.read_text().splitlines()[0])
                    except (OSError, ValueError, IndexError):
                        if not self._standby_status_is_not_running(target):
                            raise RuntimeError(
                                f"cannot remove standby target {target}: "
                                "postmaster is still running"
                            )
                        postmaster_pid = None
                    try:
                        self.run([
                            pg_bin("pg_ctl"), "-D", str(target),
                            "-m", "immediate", "stop",
                        ])
                    except Exception as exc:
                        stop_error = exc
                    else:
                        stop_error = None
                    if pid_file.exists() and alive(postmaster_pid):
                        detail = (
                            f"; stop error: {_command_error_detail(stop_error)}"
                            if stop_error else ""
                        )
                        raise RuntimeError(
                            f"cannot remove standby target {target}: "
                            f"postmaster pid {postmaster_pid} is still alive{detail}"
                        )
                engine().prepare_standby(
                    target,
                    is_stopped=self._standby_status_is_not_running,
                )
            else:
                engine().prepare_standby(
                    target,
                    is_stopped=self._standby_status_is_not_running,
                )
            slot = payload.get("replication_slot")
            if slot:
                self._reset_replication_slot(payload, slot)
            argv = [
                pg_bin("pg_basebackup"), "-D", str(target),
                "-h", payload["primary_address"], "-p", str(payload["primary_port"]),
                "-U", payload["replication_user"], "-Fp", "-X", "stream", "-R",
            ]
            if slot:
                argv.extend(["-C", "-S", slot])
            self.run(
                argv,
                env={"PGPASSWORD": payload["replication_password"]},
            )
            _rewrite_postgres_config(
                target,
                int(payload["target_port"]),
                payload["target_host_id"],
                standby=True,
            )
            self.run([
                pg_bin("pg_ctl"), "-D", str(target),
                "-l", str(target / "postgres.log"), "start",
            ])
            self.run([pg_bin("pg_ctl"), "-D", str(target), "status"])
            result = {"status": "ready"}
        except Exception as exc:
            result = {"status": "failed", "error": _command_error_detail(exc)}
        with self._standby_jobs_lock:
            job = self._standby_jobs.get(target)
            if job and job.get("superseded"):
                self._standby_jobs[target] = {
                    "status": "failed",
                    "error": "standby build superseded by forced rebuild",
                }
            else:
                self._standby_jobs[target] = result

    def _reset_replication_slot(self, payload: dict, slot: str):
        if not payload.get("primary_password"):
            raise RuntimeError(
                "primary password is required to reset replication slot before standby rebuild"
            )
        if psycopg is None:
            raise RuntimeError("psycopg is required to reset replication slots")
        with psycopg.connect(
            host=payload["primary_address"],
            port=payload["primary_port"],
            user="postgres",
            password=payload["primary_password"],
            dbname="postgres",
            connect_timeout=5,
        ) as connection:
            active = False
            active_pid = None
            for _ in range(REPLICATION_SLOT_INACTIVE_POLLS):
                row = connection.execute(
                    "SELECT active, active_pid FROM pg_replication_slots WHERE slot_name=%s",
                    (slot,),
                ).fetchone()
                if row is None:
                    connection.commit()
                    return
                if isinstance(row, dict):
                    active, active_pid = row["active"], row["active_pid"]
                else:
                    active, active_pid = row[0], row[1]
                if not active:
                    break
                time.sleep(REPLICATION_SLOT_INACTIVE_POLL_SECONDS)
            if active:
                if active_pid is None:
                    raise RuntimeError(
                        f"replication slot {slot} remained active without a backend pid"
                    )
                connection.execute(
                    "SELECT pg_terminate_backend(%s)",
                    (active_pid,),
                )
                connection.commit()
                for _ in range(REPLICATION_SLOT_INACTIVE_POLLS):
                    row = connection.execute(
                        "SELECT active, active_pid FROM pg_replication_slots WHERE slot_name=%s",
                        (slot,),
                    ).fetchone()
                    if row is None:
                        active = False
                        break
                    if isinstance(row, dict):
                        active, active_pid = row["active"], row["active_pid"]
                    else:
                        active, active_pid = row[0], row[1]
                    if not active:
                        break
                    time.sleep(REPLICATION_SLOT_INACTIVE_POLL_SECONDS)
                if active:
                    raise RuntimeError(
                        f"replication slot {slot} remained active after terminating backend"
                    )
            try:
                connection.execute(
                    "SELECT pg_drop_replication_slot(%s)",
                    (slot,),
                )
            except Exception as exc:
                detail = _command_error_detail(exc).lower()
                if "does not exist" not in detail and "undefined object" not in detail:
                    raise
                connection.rollback()
            connection.commit()

    def _start_standby_build(self, target: Path, payload: dict) -> dict:
        force_rebuild = bool(payload.get("force_rebuild"))
        if force_rebuild:
            with self._standby_jobs_lock:
                job = self._standby_jobs.get(target)
                if job and job["status"] == "building":
                    job["superseded"] = True
                    return {"status": "building", "superseded": True}
                self._standby_jobs.pop(target, None)
                self._standby_jobs[target] = {"status": "building"}
        else:
            with self._standby_jobs_lock:
                job = self._standby_jobs.get(target)
                if job and job["status"] == "building":
                    return {"status": "building"}
            existing = self._standby_status(target)
            if existing["status"] == "ready":
                return existing
            with self._standby_jobs_lock:
                job = self._standby_jobs.get(target)
                if job and job["status"] == "building":
                    return {"status": "building"}
                self._standby_jobs[target] = {"status": "building"}
        threading.Thread(
            target=self._run_standby_build,
            args=(target, dict(payload)),
            daemon=True,
        ).start()
        return {"status": "building"}

    def handle(self, operation: str, payload: dict):
        if operation not in {
            "provision", "clone", "build_standby", "prepare_primary",
            "inspect_replication", "inspect_standby", "promote_standby",
            "start", "stop", "inspect", "destroy",
        }:
            raise RuntimeError(f"unknown node operation {operation}")
        root = BRANCH_ROOT.resolve()

        def confined(value: str, field: str) -> Path:
            path = Path(value).resolve()
            if path == root or root not in path.parents:
                raise RuntimeError(f"{field} must be under MOSAIC_BRANCH_ROOT")
            return path

        if operation == "provision":
            engine().create_database(
                confined(payload["path"], "path"),
                payload["password"],
                int(payload["port"]),
                payload.get("host_id", current_node_id()),
            )
            return {"status": "provisioned"}
        if operation == "clone":
            engine().clone(
                confined(payload["parent"], "parent"),
                confined(payload["target"], "target"),
                parent_port=payload.get("parent_port"),
                parent_password=payload.get("parent_password"),
                target_port=payload.get("target_port"),
                parent_host_id=payload.get("parent_host_id", current_node_id()),
                target_host_id=payload.get("target_host_id", current_node_id()),
            )
            return {"status": "cloned"}
        if operation == "build_standby":
            target = confined(payload["target_path"], "target_path")
            return self._start_standby_build(target, payload)
        if operation == "inspect_standby":
            return self._standby_status(confined(payload["target_path"], "target_path"))
        if operation == "promote_standby":
            return self.promote_standby(
                confined(payload["target_path"], "target_path"),
                payload,
            )
        if operation == "prepare_primary":
            if psycopg is None:
                raise RuntimeError("psycopg is required for replication setup")
            primary_path = confined(payload["path"], "path")
            config_text = (primary_path / "postgresql.conf").read_text()
            listen_setting = re.search(
                r"^\s*listen_addresses\s*=\s*'([^']*)'",
                config_text,
                re.MULTILINE,
            )
            requires_restart = (
                listen_setting is not None
                and listen_setting.group(1) != node_address(payload["host_id"])
            )
            was_running = supervisor._cluster_is_running(str(primary_path))
            _rewrite_postgres_config(
                primary_path,
                int(payload["port"]),
                payload["host_id"],
                replication_user=payload["replication_user"],
                replication_addresses=payload["replication_addresses"],
            )
            result = supervisor.start_local({
                "branch_id": payload["branch_id"],
                "path": str(primary_path),
                "port": payload["port"],
                "pid": payload.get("pid"),
                "status": payload.get("status", "stopped"),
                "host_id": payload["host_id"],
                "password": payload["postgres_password"],
                "parent_passwords": [],
            })
            with psycopg.connect(
                host=node_address(payload["host_id"]),
                port=payload["port"],
                user="postgres",
                password=payload["postgres_password"],
                dbname="postgres",
                connect_timeout=5,
            ) as connection:
                role = connection.execute(
                    "SELECT 1 FROM pg_roles WHERE rolname=%s",
                    (payload["replication_user"],),
                ).fetchone()
                if role:
                    connection.execute(
                        psycopg_sql.SQL(
                            "ALTER ROLE {} WITH REPLICATION LOGIN PASSWORD {}"
                        ).format(
                            psycopg_sql.Identifier(payload["replication_user"]),
                            psycopg_sql.Literal(payload["replication_password"]),
                        )
                    )
                else:
                    connection.execute(
                        psycopg_sql.SQL(
                            "CREATE ROLE {} WITH REPLICATION LOGIN PASSWORD {}"
                        ).format(
                            psycopg_sql.Identifier(payload["replication_user"]),
                            psycopg_sql.Literal(payload["replication_password"]),
                        )
                    )
                connection.commit()
            if requires_restart and was_running:
                self.run([
                    pg_bin("pg_ctl"), "-D", str(primary_path),
                    "-m", "fast", "-w", "restart",
                ])
                result = {**result, "pid": int((primary_path / "postmaster.pid").read_text().splitlines()[0])}
            else:
                self.run([pg_bin("pg_ctl"), "-D", str(primary_path), "reload"])
            return result
        if operation == "inspect_replication":
            if psycopg is None:
                raise RuntimeError("psycopg is required for replication inspection")
            with psycopg.connect(
                host=node_address(payload["primary_host_id"]),
                port=payload["primary_port"],
                user="postgres",
                password=payload["postgres_password"],
                dbname="postgres",
                connect_timeout=5,
                row_factory=dict_row,
            ) as connection:
                rows = connection.execute(
                    "SELECT host(client_addr) AS client_addr, application_name, "
                    "COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn), 0)::bigint AS lag_bytes "
                    "FROM pg_stat_replication"
                ).fetchall()
                slots = connection.execute(
                    "SELECT slot_name, wal_status FROM pg_replication_slots "
                    "WHERE slot_type='physical'"
                ).fetchall()
            return {
                "sampled_at": now(),
                "replicas": [dict(row) for row in rows],
                "invalid_slots": [
                    row["slot_name"] for row in slots if row["wal_status"] == "lost"
                ],
            }
        if operation == "start":
            return supervisor.start_local({**payload, "path": str(confined(payload["path"], "path"))})
        if operation == "stop":
            return supervisor.stop_local({**payload, "path": str(confined(payload["path"], "path"))})
        if operation == "inspect":
            return {"status": payload.get("status"), "pid": payload.get("pid"), "alive": alive(payload.get("pid"))}
        if operation == "destroy":
            engine().destroy(confined(payload["path"], "path"))
            return {"status": "destroyed"}
        raise RuntimeError(f"unknown node operation {operation}")


def current_node_id() -> str:
    configured = os.getenv("MOSAIC_NODE_ID")
    if configured is not None:
        return configured
    nodes = configured_nodes()
    if len(nodes) == 1 and not nodes[0][1]:
        return nodes[0][0]
    return NODE_ID


def validate_node_identity():
    configured = os.getenv("MOSAIC_NODE_ID")
    if configured is None:
        return
    nodes = node_ids()
    if configured not in nodes:
        raise RuntimeError(
            f"MOSAIC_NODE_ID={configured!r} is not present in MOSAIC_NODE_HOSTS"
        )


class NodeTransport:
    def __init__(self, agent: NodeAgent):
        self.agent = agent

    def call(self, node_id: str, operation: str, payload: dict):
        if node_id not in node_ids():
            raise RuntimeError(f"unknown database node {node_id}")
        if node_id == current_node_id():
            return self.agent.handle(operation, payload)
        base_url = node_url(node_id)
        if not base_url:
            raise RuntimeError(f"no node agent URL configured for {node_id}")
        body = json.dumps(payload).encode()
        request = urllib.request.Request(
            f"{base_url.rstrip('/')}/internal/node/{operation}",
            data=body,
            headers={"Content-Type": "application/json", "X-Mosaic-Node-Token": os.getenv("MOSAIC_NODE_AGENT_TOKEN", NODE_AGENT_TOKEN)},
            method="POST",
        )
        try:
            if base_url.startswith("http://") and not ALLOW_PLAINTEXT_NODE_AGENT:
                raise RuntimeError("plaintext node-agent transport requires MOSAIC_ALLOW_PLAINTEXT_NODE_AGENT=true")
            context = None
            if base_url.startswith("https://"):
                context = ssl.create_default_context(cafile=NODE_AGENT_CA_BUNDLE or None)
            with urllib.request.urlopen(request, timeout=15, context=context) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, urllib.error.HTTPError) as exc:
            raise RuntimeError(f"node agent {node_id} unavailable: {exc}") from exc


def replica_nodes(primary_host_id: str) -> list[str]:
    return [node_id for node_id in node_ids() if node_id != primary_host_id]


def replica_root(main_path: str | Path) -> Path:
    path = Path(main_path)
    return path.parent.parent if path.parent.name == ".replicas" else path.parent


def create_replicas(
    c: Conn,
    database_id: str,
    main_row,
    postgres_password: str,
    status: str = "pending",
):
    peers = replica_nodes(main_row["host_id"])
    if not peers:
        return
    replication_user = REPLICATION_USER_PREFIX + replication_identifier(database_id)[7:31]
    replication_password = secrets.token_urlsafe(24)
    slots = {
        node_id: replication_identifier(database_id, node_id)
        for node_id in peers
    }
    c.execute(
        "INSERT INTO replication_credentials(database_id,username,credential_encrypted,created_at) VALUES(?,?,?,?)",
        (database_id, replication_user, cipher().encrypt(replication_password.encode()).decode(), now()),
    )
    for node_id in peers:
        replica_id = token("rep_")
        replica_port = supervisor.allocate_port(c)
        replica_path = replica_root(main_row["path"]) / ".replicas" / node_id
        c.execute(
            "INSERT INTO replicas(id,database_id,primary_branch_id,host_id,path,port,status,lag_bytes,lag_sampled_at,created_at,slot_name) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (replica_id, database_id, main_row["id"], node_id, str(replica_path), replica_port, status, None, None, now(), slots[node_id]),
        )


def redact_error(error: str, sensitive: tuple[str, ...] = ()) -> str:
    for secret in sensitive:
        if secret:
            error = error.replace(secret, "[REDACTED]")
    return error


def _is_psycopg_error(exc: Exception, *names: str) -> bool:
    if psycopg is None:
        return False
    classes = []
    errors = getattr(psycopg, "errors", None)
    for name in names:
        candidate = getattr(errors, name, None) if errors else None
        candidate = candidate or getattr(psycopg, name, None)
        if isinstance(candidate, type):
            classes.append(candidate)
    return bool(classes) and isinstance(exc, tuple(classes))


def _statement_error_detail(exc: Exception, sensitive: tuple[str, ...] = ()) -> str:
    diagnostic = getattr(exc, "diag", None)
    values = []
    for name in ("message_primary", "message_hint"):
        value = getattr(diagnostic, name, None) if diagnostic else None
        if value:
            values.append(str(value))
    position = getattr(diagnostic, "statement_position", None) if diagnostic else None
    if position:
        values.append(f"position {position}")
    if not values:
        values.append(str(exc).splitlines()[0])
    message = " ".join(" ".join(value.split()) for value in values)
    return redact_error(message, sensitive)[:500]


def _command_error_detail(exc: Exception) -> str:
    parts = [str(part).strip() for part in (
        getattr(exc, "stderr", None),
        getattr(exc, "stdout", None),
        str(exc),
    ) if part]
    return redact_error("; ".join(parts))


def _pid_process_evidence(pid: int) -> tuple[list[str], Path | None]:
    proc = Path("/proc") / str(pid)
    try:
        raw = (proc / "cmdline").read_bytes()
    except FileNotFoundError:
        return [], None
    except OSError as exc:
        raise RuntimeError(
            f"cannot inspect process {pid} while checking standby ownership: {exc}"
        ) from exc
    args = [arg.decode(errors="replace") for arg in raw.split(b"\0") if arg]
    try:
        cwd = (proc / "cwd").resolve()
    except FileNotFoundError:
        cwd = None
    except OSError as exc:
        raise RuntimeError(
            f"cannot inspect process {pid} working directory: {exc}"
        ) from exc
    return args, cwd


def _pid_owns_postgres_directory(pid: int, target: Path) -> bool:
    args, cwd = _pid_process_evidence(pid)
    resolved = str(target.resolve())
    if cwd is not None and str(cwd) == resolved:
        return True
    for index, arg in enumerate(args):
        if arg in {"-D", "--pgdata"} and index + 1 < len(args):
            return str(Path(args[index + 1]).resolve()) == resolved
        if arg.startswith("-D") and len(arg) > 2:
            return str(Path(arg[2:]).resolve()) == resolved
        if arg.startswith("--pgdata="):
            return str(Path(arg.split("=", 1)[1]).resolve()) == resolved
    if not args and cwd is None:
        raise RuntimeError(
            f"cannot determine whether process {pid} owns standby target {target}"
        )
    return False


def _retry_replica(c: Conn, replica, exc: Exception, sensitive: tuple[str, ...] = ()):
    attempts = int(replica["attempts"]) + 1
    delay = min(300, 5 * (2 ** min(attempts - 1, 6)))
    next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay)
    error = redact_error(str(exc), sensitive)
    c.execute(
        "UPDATE replicas SET status=?,attempts=?,next_attempt_at=?,last_error=? WHERE id=?",
        (
            "rebuild_required" if replica["status"] == "rebuild_required" else "retryable",
            attempts,
            next_attempt.isoformat(),
            error[:500],
            replica["id"],
        ),
    )


def _ensure_primary_running(
    c: Conn,
    *,
    branch_id: str,
    path: str,
    port: int,
    pid: int | None,
    status: str,
    host_id: str,
    password: str,
) -> dict:
    if status == "running":
        return {"status": status, "pid": pid}
    result = node_transport.call(host_id, "start", {
        "branch_id": branch_id,
        "path": path,
        "port": port,
        "pid": pid,
        "status": status,
        "host_id": host_id,
        "password": password,
        "parent_passwords": [],
    })
    c.execute(
        "UPDATE branches SET status=?,pid=? WHERE id=?",
        (result["status"], result["pid"], branch_id),
    )
    return result


def _standby_is_verifiably_stopped(result: dict) -> bool:
    if result.get("status") != "failed":
        return False
    error = str(result.get("error", "")).lower()
    return (
        "standby postmaster is not running" in error
        or "no server running" in error
        or "not running" in error
        or "not a database cluster directory" in error
    )


def _reconcile_database_replicas(c: Conn, due: list):
    primary = due[0]
    postgres_password = ""
    replication_password = ""
    all_replicas = c.execute(
        "SELECT host_id FROM replicas WHERE database_id=?",
        (primary["database_id"],),
    ).fetchall()
    pending = [
        row for row in due
        if row["status"] in ("pending", "retryable", "rebuild_required")
    ]
    try:
        postgres_password = cipher().decrypt(primary["credential_encrypted"].encode()).decode()
        replication_password = cipher().decrypt(primary["replication_credential"].encode()).decode()
        _ensure_primary_running(
            c,
            branch_id=primary["branch_id"],
            path=primary["primary_path"],
            port=primary["primary_port"],
            pid=primary["primary_pid"],
            status=primary["primary_status"],
            host_id=primary["primary_host_id"],
            password=postgres_password,
        )
    except Exception as exc:
        for row in due:
            if row["status"] != "ready":
                _retry_replica(c, row, exc, (postgres_password, replication_password))
        return
    if pending:
        try:
            prepared = node_transport.call(primary["primary_host_id"], "prepare_primary", {
                "branch_id": primary["branch_id"],
                "path": primary["primary_path"],
                "port": primary["primary_port"],
                "pid": primary["primary_pid"],
                "status": primary["primary_status"],
                "host_id": primary["primary_host_id"],
                "postgres_password": postgres_password,
                "replication_user": primary["username"],
                "replication_password": replication_password,
                "replication_addresses": [node_address(row["host_id"]) for row in all_replicas],
            })
            c.execute(
                "UPDATE branches SET status=?,pid=? WHERE id=?",
                (prepared["status"], prepared["pid"], primary["branch_id"]),
            )
        except Exception as exc:
            for row in pending:
                _retry_replica(c, row, exc, (postgres_password, replication_password))
            return
    for replica in due:
        if replica["status"] == "ready":
            try:
                result = node_transport.call(replica["host_id"], "inspect_standby", {
                    "target_path": replica["path"],
                })
            except Exception:
                continue
            if _standby_is_verifiably_stopped(result):
                c.execute(
                    "UPDATE replicas SET status='rebuild_required',"
                    "lag_bytes=NULL,lag_sampled_at=NULL,next_attempt_at=NULL,"
                    "last_error=NULL WHERE id=?",
                    (replica["id"],),
                )
            continue
        try:
            if replica["status"] == "building":
                result = node_transport.call(replica["host_id"], "inspect_standby", {
                    "target_path": replica["path"],
                })
            else:
                result = node_transport.call(replica["host_id"], "build_standby", {
                    "target_path": replica["path"],
                    "target_port": replica["port"],
                    "target_host_id": replica["host_id"],
                    "primary_address": node_address(replica["primary_host_id"]),
                    "primary_port": replica["primary_port"],
                    "replication_user": primary["username"],
                    "replication_password": replication_password,
                    "primary_password": postgres_password,
                    "replication_slot": replica["slot_name"],
                    "force_rebuild": replica["status"] == "rebuild_required",
                })
            status = result.get("status")
            if status == "ready":
                c.execute(
                    "UPDATE replicas SET status='ready',next_attempt_at=NULL,last_error=NULL WHERE id=?",
                    (replica["id"],),
                )
            elif status == "building":
                if not result.get("superseded"):
                    c.execute(
                        "UPDATE replicas SET status='building',next_attempt_at=NULL,last_error=NULL WHERE id=?",
                        (replica["id"],),
                    )
            elif status == "failed":
                raise RuntimeError(result.get("error", "standby build failed"))
            else:
                raise RuntimeError(f"unexpected standby status {status!r}")
        except Exception as exc:
            _retry_replica(c, replica, exc, (postgres_password, replication_password))


def reconcile_replicas(c: Conn):
    rows = c.execute(
        "SELECT r.*, b.id AS branch_id, b.path AS primary_path, b.port AS primary_port, "
        "b.pid AS primary_pid, b.status AS primary_status, b.host_id AS primary_host_id, "
        "b.credential_encrypted, rc.username, rc.credential_encrypted AS replication_credential "
        "FROM replicas r JOIN branches b ON b.id=r.primary_branch_id "
        "JOIN replication_credentials rc ON rc.database_id=r.database_id"
    ).fetchall()
    due = []
    for row in rows:
        if row["status"] != "building" and row["next_attempt_at"]:
            if datetime.fromisoformat(row["next_attempt_at"]) > datetime.now(timezone.utc):
                continue
        due.append(row)
    grouped = {}
    for row in due:
        grouped.setdefault(row["database_id"], []).append(row)
    for database_rows in grouped.values():
        try:
            _reconcile_database_replicas(c, database_rows)
        except Exception as exc:
            postgres_password = ""
            replication_password = ""
            try:
                postgres_password = cipher().decrypt(
                    database_rows[0]["credential_encrypted"].encode()
                ).decode()
                replication_password = cipher().decrypt(
                    database_rows[0]["replication_credential"].encode()
                ).decode()
            except Exception:
                pass
            for row in database_rows:
                current = c.execute(
                    "SELECT status FROM replicas WHERE id=?", (row["id"],)
                ).fetchone()
                if current and current["status"] != "ready":
                    _retry_replica(
                        c, row, exc, (postgres_password, replication_password)
                    )
    c.commit()


def refresh_replica_lag(c: Conn, database_id: str):
    main_row = c.execute(
        "SELECT * FROM branches WHERE database_id=? AND name='main'",
        (database_id,),
    ).fetchone()
    credential = c.execute(
        "SELECT username,credential_encrypted FROM replication_credentials WHERE database_id=?",
        (database_id,),
    ).fetchone()
    if not main_row or not credential:
        return {"error": "replication lag sampling unavailable"}
    try:
        postgres_password = cipher().decrypt(main_row["credential_encrypted"].encode()).decode()
        _ensure_primary_running(
            c,
            branch_id=main_row["id"],
            path=main_row["path"],
            port=main_row["port"],
            pid=main_row["pid"],
            status=main_row["status"],
            host_id=main_row["host_id"],
            password=postgres_password,
        )
        sampled = node_transport.call(main_row["host_id"], "inspect_replication", {
            "primary_host_id": main_row["host_id"],
            "primary_port": main_row["port"],
            "postgres_password": postgres_password,
        })
    except Exception:
        return {"error": "replication lag sampling failed"}
    by_address = {}
    for row in c.execute(
        "SELECT id,host_id FROM replicas WHERE database_id=?", (database_id,)
    ).fetchall():
        try:
            by_address[node_address(row["host_id"])] = row
        except Exception as exc:
            c.execute(
                "UPDATE replicas SET last_error=? WHERE id=?",
                (f"replica host unavailable: {exc}"[:500], row["id"]),
            )
    for replica in sampled.get("replicas", []):
        client_addr = str(replica.get("client_addr") or "").split("/", 1)[0]
        row = by_address.get(client_addr)
        if row:
            c.execute(
                "UPDATE replicas SET lag_bytes=?,lag_sampled_at=?,last_error=NULL "
                "WHERE database_id=? AND host_id=?",
                (
                    int(replica.get("lag_bytes", 0)),
                    sampled["sampled_at"],
                    database_id,
                    row["host_id"],
                ),
            )
    if sampled.get("invalid_slots"):
        placeholders = ",".join("?" for _ in sampled["invalid_slots"])
        c.execute(
            f"UPDATE replicas SET status='rebuild_required' "
            f"WHERE database_id=? AND slot_name IN ({placeholders})",
            (database_id, *sampled["invalid_slots"]),
        )
    c.commit()
    return {"sampled_at": sampled["sampled_at"]}


supervisor = Supervisor()
node_agent = NodeAgent()
node_transport = NodeTransport(node_agent)
app = FastAPI(title="Mosaic Database", version="0.1.0")
_reaper_task: asyncio.Task | None = None
_replication_task: asyncio.Task | None = None
_branch_mutation_lock = threading.Lock()
_deploy_lock = threading.Lock()


async def _reaper_loop():
    while True:
        try:
            await asyncio.sleep(background_interval("MOSAIC_BRANCH_REAPER_INTERVAL", 60))
            await asyncio.to_thread(_run_reaper_sweep)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("branch reaper iteration failed")


async def _replication_loop():
    while True:
        try:
            await asyncio.sleep(background_interval("MOSAIC_REPLICATION_RETRY_INTERVAL", 10))
            await asyncio.to_thread(_run_replication_sweep)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("replication loop iteration failed")


def _run_reaper_sweep():
    c = db()
    try:
        try:
            reconcile_deploy_locks(c)
        except Exception:
            logger.exception("deploy lease reconciliation failed")
        reap_branches(c)
    except Exception:
        logger.exception("branch reaper sweep failed")
    finally:
        c.close()


def _run_replication_sweep():
    c = db()
    try:
        reconcile_replicas(c)
    except Exception:
        logger.exception("replica reconciliation failed")
    finally:
        c.close()


def reap_branches(c: Conn) -> int:
    cutoff = time.time() - int(os.getenv("MOSAIC_BRANCH_IDLE_SECONDS", str(IDLE_REAPER_SECONDS)))
    count = 0
    for row in c.execute(
        "SELECT b.* FROM branches b "
        "WHERE b.status='running' "
        "AND NOT EXISTS (SELECT 1 FROM deploy_locks l WHERE l.branch_id=b.id) "
        "AND NOT EXISTS ("
        "SELECT 1 FROM replicas r WHERE r.primary_branch_id=b.id"
        ")"
    ).fetchall():
        if datetime.fromisoformat(row["last_query_at"]).timestamp() >= cutoff:
            continue
        try:
            result = node_transport.call(row["host_id"], "stop", {"path": row["path"], "pid": row["pid"]})
        except (RuntimeError, OSError):
            continue
        record_stop(c, row, result)
        count += 1
    return count


@app.on_event("startup")
async def startup():
    global _reaper_task, _replication_task
    validate_node_identity()
    if not CREDENTIAL_ENCRYPTION_KEY:
        if os.getenv("MOSAIC_ALLOW_EPHEMERAL_CREDENTIAL_KEY", "").lower() == "true":
            key_path = BRANCH_ROOT / ".credential.key"
            key_path.parent.mkdir(parents=True, exist_ok=True)
            if key_path.exists():
                globals()["CREDENTIAL_ENCRYPTION_KEY"] = key_path.read_text().strip()
            else:
                globals()["CREDENTIAL_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
                key_path.write_text(CREDENTIAL_ENCRYPTION_KEY)
                key_path.chmod(0o600)
        else:
            raise RuntimeError("MOSAIC_CREDENTIAL_ENCRYPTION_KEY is required; set MOSAIC_ALLOW_EPHEMERAL_CREDENTIAL_KEY=true only for development")
    c = db()
    try:
        initialize_schema(c)
        reconcile_deploy_locks(c)
        BRANCH_ROOT.mkdir(parents=True, exist_ok=True)
    finally:
        c.close()
    _reaper_task = asyncio.create_task(_reaper_loop())
    _replication_task = asyncio.create_task(_replication_loop())


@app.on_event("shutdown")
async def shutdown():
    global _reaper_task, _replication_task
    for task_name in ("_reaper_task", "_replication_task"):
        task = globals()[task_name]
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            globals()[task_name] = None


@app.middleware("http")
async def headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


def require_admin(x_admin_key: str | None = Header(default=None, alias="X-Admin-Key")):
    if not ADMIN_KEY or not secrets.compare_digest(x_admin_key or "", ADMIN_KEY):
        raise HTTPException(401, "admin authentication required")


def _required_database_scope(method: str) -> str:
    return "database:read" if method.upper() == "GET" else "database:write"


def _key_from_headers(x_api_key: str | None, authorization: str | None) -> str:
    return x_api_key or (authorization or "").removeprefix("Bearer ").strip()


def _mosaic_tenant(c: Conn, identity: dict, *, create: bool = True):
    organization_id = identity["organization_id"]
    mapping = c.execute(
        "SELECT t.* FROM mosaic_organization_tenants m "
        "JOIN tenants t ON t.id=m.tenant_id WHERE m.organization_id=?",
        (organization_id,),
    ).fetchone()
    if mapping:
        return mapping
    if not create:
        raise HTTPException(401, "Mosaic identity is not mapped to a tenant")
    tenant_id = token("ten_")
    created = now()
    tenant_name = f"Mosaic workspace {organization_id[:12]}"
    try:
        c.execute(
            "INSERT INTO tenants(id,name,plan,api_key_hash,status,created_at,origin) "
            "VALUES(?,?,?,?,?,?,?)",
            (tenant_id, tenant_name, "shared", "", "active", created, "sandbox"),
        )
        c.execute(
            "INSERT INTO mosaic_organization_tenants(organization_id,tenant_id,created_at) "
            "VALUES(?,?,?)",
            (organization_id, tenant_id, created),
        )
        audit(c, tenant_id, "mosaic_tenant.provisioned", {
            "organization_id": organization_id,
            "origin": "sandbox",
        }, actor="mosaic")
        c.commit()
    except Exception as exc:
        if not is_unique_violation(exc):
            raise
        c.rollback()
        mapping = c.execute(
            "SELECT t.* FROM mosaic_organization_tenants m "
            "JOIN tenants t ON t.id=m.tenant_id WHERE m.organization_id=?",
            (organization_id,),
        ).fetchone()
        if not mapping:
            raise
        return mapping
    return c.execute("SELECT * FROM tenants WHERE id=?", (tenant_id,)).fetchone()


def authenticate_api_key(
    c: Conn,
    key: str,
    *,
    tid: str | None = None,
    method: str = "GET",
    required_scope: str | None = None,
    provision: bool = True,
):
    url = os.getenv("MOSAIC_INTROSPECTION_URL", MOSAIC_INTROSPECTION_URL)
    if key.startswith("msk_live_") and url:
        identity = introspect_mosaic_key(key)
        scope = required_scope or _required_database_scope(method)
        if scope not in identity["scopes"]:
            raise HTTPException(403, f"required scope {scope}")
        tenant = _mosaic_tenant(c, identity, create=provision)
        if not tenant or tenant["status"] != "active":
            raise HTTPException(401, "invalid tenant API key")
        if tid is not None and tenant["id"] != tid:
            raise HTTPException(401, "invalid tenant API key")
        check_rate_limit(tenant["id"])
        return tenant, identity
    if tid is None:
        tenant = c.execute(
            "SELECT * FROM tenants WHERE api_key_hash=? AND status='active'",
            (digest(key),),
        ).fetchone()
    else:
        tenant = c.execute(
            "SELECT * FROM tenants WHERE id=? AND status='active'",
            (tid,),
        ).fetchone()
        if not tenant or not key or not secrets.compare_digest(tenant["api_key_hash"], digest(key)):
            raise HTTPException(401, "invalid tenant API key")
    if not tenant:
        raise HTTPException(401, "invalid tenant API key")
    check_rate_limit(tenant["id"])
    return tenant, None


def tenant_auth(
    tid: str,
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None),
):
    key = _key_from_headers(x_api_key, authorization)
    c = db()
    try:
        row, _ = authenticate_api_key(c, key, tid=tid, method=request.method)
        return row
    finally:
        c.close()


def check_rate_limit(tid: str, limit: int | None = None):
    global _rate_last_sweep
    limit = RATE_LIMIT_REQUESTS if limit is None else limit
    current = time.time()
    with _rate_lock:
        if (
            len(_rate) >= RATE_LIMIT_SWEEP_THRESHOLD
            and current - _rate_last_sweep >= RATE_LIMIT_SWEEP_INTERVAL_SECONDS
        ):
            cutoff = current - 60
            for key, timestamps in list(_rate.items()):
                if not any(timestamp > cutoff for timestamp in timestamps):
                    _rate.pop(key, None)
            _rate_last_sweep = current
        values = [x for x in _rate.get(tid, []) if x > current - 60]
        if not values:
            _rate.pop(tid, None)
        if len(values) >= limit:
            raise HTTPException(429, "rate limit exceeded")
        _rate[tid] = values + [current]


def public_signup_client_ip(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    if TRUST_CLOUDFLARE_IP:
        try:
            peer_ip = ipaddress.ip_address(peer)
        except ValueError:
            peer_ip = None
        if peer_ip and (peer_ip.is_loopback or peer_ip.is_private):
            try:
                forwarded = ipaddress.ip_address(
                    request.headers.get("CF-Connecting-IP", "").strip()
                )
            except ValueError:
                forwarded = None
            if forwarded:
                return str(forwarded)
    return peer


class TenantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    plan: str = "shared"


class PublicSignupCreate(BaseModel):
    email: str = Field(pattern=r"^[^@\s]{1,80}@[^@\s]{1,120}\.[^@\s]{2,24}$", max_length=220)
    tenant_name: str = Field(default="", max_length=100)
    key_name: str = Field(default="", max_length=100)
    plan: str = "shared"


class DatabaseCreate(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,48}$")


class BranchCreate(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,48}$")
    parent: str = "main"


class PromotionRequest(BaseModel):
    host_id: str = Field(min_length=1, max_length=100)
    force: bool = False


class Query(BaseModel):
    sql: str = Field(min_length=1, max_length=100000)
    params: list[Any] = []
    branch: str = "main"


class DeployModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DeployColumn(DeployModel):
    name: str = Field(pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
    type: str = Field(min_length=1, max_length=32)
    nullable: bool = True
    pk: bool = False
    identity: bool = False
    default: str | None = None


class CreateTableOperation(DeployModel):
    op: Literal["create_table"]
    name: str = Field(pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
    columns: list[DeployColumn] = Field(min_length=1, max_length=100)


class AddColumnOperation(DeployModel):
    op: Literal["add_column"]
    table: str = Field(pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
    column: DeployColumn


class CreateIndexOperation(DeployModel):
    op: Literal["create_index"]
    table: str = Field(pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
    columns: list[str] = Field(min_length=1, max_length=32)
    unique: bool = False


class AddConstraintOperation(DeployModel):
    op: Literal["add_constraint"]
    table: str = Field(pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
    kind: Literal["check"]
    expression: str = Field(min_length=1, max_length=1000)


class RenameColumnOperation(DeployModel):
    op: Literal["rename_column"]
    table: str = Field(pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
    from_: str = Field(alias="from", pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
    to: str = Field(pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")


class DropColumnOperation(DeployModel):
    op: Literal["drop_column"]
    table: str = Field(pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
    column: str = Field(pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
    confirm_destructive: bool = False


class DropTableOperation(DeployModel):
    op: Literal["drop_table"]
    name: str = Field(pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
    confirm_destructive: bool = False


DeployOperation = Annotated[
    CreateTableOperation
    | AddColumnOperation
    | CreateIndexOperation
    | AddConstraintOperation
    | RenameColumnOperation
    | DropColumnOperation
    | DropTableOperation,
    Field(discriminator="op"),
]


class DeployCreate(DeployModel):
    branch: str = "main"
    operations: list[DeployOperation] = Field(min_length=1, max_length=100)
    idempotency_key: str = Field(default="", max_length=200)
    source_deploy_id: str | None = Field(default=None, max_length=100)


class Usage(BaseModel):
    kind: str
    quantity: int = Field(ge=0)
    unit: str
    idempotency_key: str = ""


def audit(c: Conn, tenant_id: str | None, action: str, details: dict, actor: str = "api"):
    c.execute("INSERT INTO audit_log(tenant_id,action,actor,details,created_at) VALUES(?,?,?,?,?)", (tenant_id, action, actor, json.dumps(details), now()))


DEPLOY_TYPES = {
    "smallint",
    "integer",
    "bigint",
    "numeric",
    "real",
    "double precision",
    "boolean",
    "text",
    "varchar",
    "date",
    "timestamp",
    "timestamptz",
    "uuid",
    "json",
    "jsonb",
}
DEPLOY_DEFAULT = re.compile(r"^(?:now\(\)|current_timestamp|true|false|null|-?\d+(?:\.\d+)?|'(?:[^']|'')*')$", re.IGNORECASE)
DEPLOY_CHECK_FUNCTIONS = {
    "abs",
    "char_length",
    "jsonb_typeof",
    "length",
    "lower",
    "upper",
}
DEPLOY_CHECK_TOKEN = re.compile(
    r"\s*(?:(?P<string>'(?:[^']|'')*')|(?P<number>-?\d+(?:\.\d+)?)|"
    r"(?P<identifier>[A-Za-z_][A-Za-z0-9_]*)|(?P<operator><>|<=|>=|!=|=|<|>)|"
    r"(?P<punct>[(),]))"
)


def quote_identifier(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", value):
        raise HTTPException(400, "invalid identifier")
    return '"' + value.replace('"', '""') + '"'


def deploy_type(value: str) -> str:
    normalized = " ".join(value.strip().lower().split())
    if normalized not in DEPLOY_TYPES:
        raise HTTPException(400, f"unsupported column type: {value}")
    return normalized


def deploy_column_sql(column: DeployColumn) -> str:
    column_type = deploy_type(column.type)
    if column.identity and column.default is not None:
        raise HTTPException(400, f"identity column {column.name} cannot have a default")
    parts = [quote_identifier(column.name), column_type]
    if column.identity:
        parts.append("GENERATED BY DEFAULT AS IDENTITY")
    if not column.nullable:
        parts.append("NOT NULL")
    if column.default is not None:
        default = column.default.strip()
        if not DEPLOY_DEFAULT.fullmatch(default):
            raise HTTPException(400, f"unsupported default for column {column.name}")
        parts.extend(("DEFAULT", default))
    if column.pk:
        parts.extend(("PRIMARY", "KEY"))
    return " ".join(parts)


def _check_tokens(expression: str) -> list[tuple[str, str]]:
    tokens = []
    position = 0
    while position < len(expression):
        if not expression[position:].strip():
            break
        match = DEPLOY_CHECK_TOKEN.match(expression, position)
        if not match:
            raise HTTPException(400, "constraint expression is not a supported predicate")
        position = match.end()
        kind = "string" if match.group("string") else "number" if match.group("number") else "identifier" if match.group("identifier") else "operator" if match.group("operator") else "punct"
        value = next(value for value in match.groups() if value is not None)
        tokens.append((kind, value))
    tokens.append(("eof", ""))
    return tokens


class _CheckExpressionParser:
    def __init__(self, expression: str):
        self.tokens = _check_tokens(expression)
        self.position = 0

    def current(self) -> tuple[str, str]:
        return self.tokens[self.position]

    def take(self, value: str | None = None) -> tuple[str, str]:
        token = self.current()
        if value is not None and token[1].upper() != value:
            raise HTTPException(400, "constraint expression is not a supported predicate")
        self.position += 1
        return token

    def accept(self, value: str) -> bool:
        if self.current()[1].upper() == value:
            self.position += 1
            return True
        return False

    def parse(self) -> str:
        self.parse_or()
        if self.current()[0] != "eof":
            raise HTTPException(400, "constraint expression is not a supported predicate")
        rendered = []
        previous = None
        for token in self.tokens:
            if token[0] == "eof":
                break
            separator = ""
            if previous is not None:
                previous_kind, previous_value = previous
                current_kind, current_value = token
                tight_after = previous_kind == "punct" and previous_value in {"(", ","}
                tight_before = current_kind == "punct" and current_value in {"(", ",", ")"}
                if not tight_after and not tight_before:
                    separator = " "
            rendered.append(separator)
            rendered.append(token[1])
            previous = token
        return "".join(rendered)

    def parse_or(self) -> None:
        self.parse_and()
        while self.accept("OR"):
            self.parse_and()

    def parse_and(self) -> None:
        self.parse_not()
        while self.accept("AND"):
            self.parse_not()

    def parse_not(self) -> None:
        if self.accept("NOT"):
            self.parse_not()
        else:
            self.parse_primary()

    def parse_primary(self) -> None:
        if self.accept("("):
            self.parse_or()
            self.take(")")
            return
        self.parse_predicate()

    def parse_predicate(self) -> None:
        self.parse_value(allow_literal=False)
        if self.accept("IS"):
            self.accept("NOT")
            self.take("NULL")
            return
        if self.accept("IN"):
            self.take("(")
            self.parse_literal()
            while self.accept(","):
                self.parse_literal()
            self.take(")")
            return
        if self.accept("BETWEEN"):
            self.parse_literal()
            self.take("AND")
            self.parse_literal()
            return
        if self.current()[0] != "operator":
            raise HTTPException(400, "constraint expression is not a supported predicate")
        self.take()
        self.parse_literal()

    def parse_value(self, *, allow_literal: bool) -> None:
        kind, value = self.current()
        if kind != "identifier":
            if allow_literal:
                self.parse_literal()
                return
            raise HTTPException(400, "constraint expression is not a supported predicate")
        self.take()
        if self.accept("("):
            if value.lower() not in DEPLOY_CHECK_FUNCTIONS:
                raise HTTPException(400, f"constraint function is not allowed: {value}")
            self.parse_value(allow_literal=False)
            self.take(")")

    def parse_literal(self) -> None:
        kind, value = self.current()
        if kind in {"string", "number"} or (kind == "identifier" and value.lower() in {"false", "null", "true"}):
            self.position += 1
            return
        raise HTTPException(400, "constraint expression requires a literal")


def validate_check_expression(expression: str) -> str:
    return _CheckExpressionParser(expression).parse()


def compile_deploy_operations(operations: list[DeployOperation]) -> list[str]:
    compiled = []
    for operation in operations:
        if isinstance(operation, CreateTableOperation):
            columns = [deploy_column_sql(column) for column in operation.columns]
            if len({column.name.lower() for column in operation.columns}) != len(operation.columns):
                raise HTTPException(400, "duplicate column in create_table")
            if sum(column.pk for column in operation.columns) > 1:
                raise HTTPException(400, "create_table supports one primary key column")
            compiled.append(f"CREATE TABLE {quote_identifier(operation.name)} ({', '.join(columns)})")
        elif isinstance(operation, AddColumnOperation):
            compiled.append(f"ALTER TABLE {quote_identifier(operation.table)} ADD COLUMN {deploy_column_sql(operation.column)}")
        elif isinstance(operation, CreateIndexOperation):
            columns = [quote_identifier(column) for column in operation.columns]
            index_name = f"idx_{operation.table}_{'_'.join(operation.columns)}"[:63]
            compiled.append(
                f"CREATE {'UNIQUE ' if operation.unique else ''}INDEX {quote_identifier(index_name)} "
                f"ON {quote_identifier(operation.table)} ({', '.join(columns)})"
            )
        elif isinstance(operation, AddConstraintOperation):
            rendered_expression = validate_check_expression(operation.expression)
            suffix = hashlib.sha256(operation.expression.encode()).hexdigest()[:10]
            name = f"ck_{operation.table}_{suffix}"[:63]
            compiled.append(
                f"ALTER TABLE {quote_identifier(operation.table)} ADD CONSTRAINT {quote_identifier(name)} "
                f"CHECK ({rendered_expression})"
            )
        elif isinstance(operation, RenameColumnOperation):
            compiled.append(
                f"ALTER TABLE {quote_identifier(operation.table)} RENAME COLUMN "
                f"{quote_identifier(operation.from_)} TO {quote_identifier(operation.to)}"
            )
        elif isinstance(operation, DropColumnOperation):
            if not operation.confirm_destructive:
                raise HTTPException(400, "drop_column requires confirm_destructive=true")
            compiled.append(f"ALTER TABLE {quote_identifier(operation.table)} DROP COLUMN {quote_identifier(operation.column)}")
        elif isinstance(operation, DropTableOperation):
            if not operation.confirm_destructive:
                raise HTTPException(400, "drop_table requires confirm_destructive=true")
            compiled.append(f"DROP TABLE {quote_identifier(operation.name)}")
        else:
            raise HTTPException(400, "unsupported deploy operation")
    return compiled


def deploy_is_destructive(operations: list[DeployOperation]) -> bool:
    return any(isinstance(operation, (DropColumnOperation, DropTableOperation)) for operation in operations)


def deploy_operations_json(operations: list[DeployOperation]) -> str:
    return json.dumps(
        [operation.model_dump(by_alias=True, mode="json") for operation in operations],
        sort_keys=True,
        separators=(",", ":"),
    )


def is_unique_violation(exc: Exception) -> bool:
    return isinstance(exc, sqlite3.IntegrityError) or (
        psycopg is not None and isinstance(exc, psycopg.errors.UniqueViolation)
    )


def refuse_existing_signup(c: Conn, email: str):
    signup = c.execute(
        "SELECT * FROM public_signups WHERE email=?",
        (email,),
    ).fetchone()
    if not signup:
        raise HTTPException(500, "signup could not be completed")
    tenant_id = signup["tenant_id"]
    tenant = c.execute(
        "SELECT * FROM tenants WHERE id=?",
        (tenant_id,),
    ).fetchone()
    if not tenant:
        raise HTTPException(500, "signup record is missing its tenant")
    audit(c, tenant_id, "public_signup.refused_existing", {
        "reason": "email already has a tenant",
    }, actor=email)
    c.commit()
    raise HTTPException(
        409,
        "an account already exists for that email; use your existing key or contact Mosaic",
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


def require_node_agent_token(token: str | None):
    expected = os.getenv("MOSAIC_NODE_AGENT_TOKEN", NODE_AGENT_TOKEN)
    if not expected:
        raise HTTPException(503, "node agent token is not configured")
    if not token or not secrets.compare_digest(token, expected):
        raise HTTPException(401, "invalid node agent token")


@app.post("/internal/node/{operation}")
def internal_node(request: Request, operation: str, payload: dict, x_node_token: str | None = Header(default=None, alias="X-Mosaic-Node-Token")):
    if PUBLIC_LISTENER:
        raise HTTPException(404, "not found")
    require_node_agent_token(x_node_token)
    allowed = {"127.0.0.1", "::1", *node_private_addresses().values()}
    if not request.client or request.client.host not in allowed:
        raise HTTPException(403, "node agent traffic must use the configured private network")
    try:
        return node_agent.handle(operation, payload)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc


@app.get("/readyz")
def readyz():
    c = None
    try:
        c = db()
        c.execute("SELECT 1")
        return {"status": "ready"}
    except Exception as exc:
        raise HTTPException(503, f"control plane unavailable: {exc}")
    finally:
        if c:
            c.close()


@app.get("/v1/plans")
def plans():
    return {"plans": PLANS}


@app.get("/.well-known/mcp.json")
def mcp_manifest():
    return {"name": "mosaic-database", "version": "0.1.0", "endpoint": "/mcp", "protocolVersion": MCP_PROTOCOL_VERSION, "tools": MCP_TOOLS}


@app.get("/mcp")
def mcp_get():
    raise HTTPException(405, "MCP streaming is disabled; use POST", headers={"Allow": "POST"})


@app.post("/mcp")
def mcp(payload: dict, request: Request, response: Response, x_api_key: str | None = Header(default=None, alias="X-API-Key"), authorization: str | None = Header(default=None)):
    if len(json.dumps(payload)) > 1000000:
        raise HTTPException(413, "MCP payload too large")
    response.headers["MCP-Protocol-Version"] = MCP_PROTOCOL_VERSION
    if payload.get("method") == "initialize":
        client_ip = public_signup_client_ip(request)
        check_rate_limit(f"public-mcp-ip:{client_ip}", PUBLIC_SIGNUP_RATE_LIMIT_REQUESTS)
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "mosaic-database", "version": "0.1.0"}}}
    key = _key_from_headers(x_api_key, authorization)
    c = db()
    try:
        mosaic = key.startswith("msk_live_") and os.getenv(
            "MOSAIC_INTROSPECTION_URL", MOSAIC_INTROSPECTION_URL
        )
        if mosaic:
            tool_name = payload.get("params", {}).get("name")
            read_tools = {"inspect_schema", "get_deploy", "list_branches"}
            required_scope = "database:read" if (
                payload.get("method") == "tools/list" or tool_name in read_tools
            ) else "database:write"
            tenant, _ = authenticate_api_key(
                c,
                key,
                method="GET" if required_scope == "database:read" else "POST",
                required_scope=required_scope,
            )
        else:
            tenant = c.execute("SELECT * FROM tenants WHERE api_key_hash=? AND status='active'", (digest(key),)).fetchone()
            if not tenant:
                raise HTTPException(401, "valid tenant API key required")
            check_rate_limit(tenant["id"])
        if payload.get("method") == "tools/list":
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"tools": MCP_TOOLS}}
        args, name = payload.get("params", {}).get("arguments", {}), payload.get("params", {}).get("name")
        if name == "inspect_schema":
            result = database_schema(tenant["id"], args["database_id"], args.get("branch", "main"), tenant)
        elif name == "query":
            result = execute_query(tenant["id"], args["database_id"], Query(sql=args["sql"], params=args.get("params", []), branch=args.get("branch", "main")), tenant)
        elif name == "deploy":
            result = create_deploy_request(
                c,
                tenant["id"],
                args["database_id"],
                DeployCreate(
                    branch=args.get("branch", "main"),
                    operations=args["operations"],
                    idempotency_key=args.get("idempotency_key", ""),
                    source_deploy_id=args.get("source_deploy_id"),
                ),
                tenant,
            )
        elif name == "get_deploy":
            row = deploy_row(c, args["deploy_id"], tenant["id"])
            if row["database_id"] != args["database_id"]:
                raise HTTPException(404, "deploy request not found")
            result = deploy_response(row)
        elif name == "create_branch":
            result = _create_branch(c, tenant["id"], args["database_id"], BranchCreate(name=args["name"], parent=args.get("parent", "main")), tenant)
        elif name == "list_branches":
            result = list_branches(tenant["id"], args["database_id"], tenant)
        else:
            raise HTTPException(400, "unknown MCP tool")
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"content": [{"type": "text", "text": json.dumps(result)}]}}
    finally:
        c.close()


@app.post("/v1/tenants/discover")
def discover_tenant(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None),
):
    key = _key_from_headers(x_api_key, authorization)
    c = db()
    try:
        mosaic = key.startswith("msk_live_") and os.getenv(
            "MOSAIC_INTROSPECTION_URL", MOSAIC_INTROSPECTION_URL
        )
        tenant, identity = authenticate_api_key(c, key, method=request.method)
        if mosaic and identity:
            check_rate_limit(
                f"mosaic-discovery-org:{identity['organization_id']}",
                PUBLIC_SIGNUP_RATE_LIMIT_REQUESTS,
            )
        return {
            "tenant_id": tenant["id"],
            "tenant_name": tenant["name"],
            "plan": tenant["plan"],
            "origin": tenant["origin"],
        }
    finally:
        c.close()


@app.post("/v1/tenants", dependencies=[Depends(require_admin)])
def create_tenant(payload: TenantCreate):
    if payload.plan not in PLANS:
        raise HTTPException(400, "unknown plan")
    tid, key = token("ten_"), token("mdb_live_")
    c = db()
    try:
        c.execute(
            "INSERT INTO tenants(id,name,plan,api_key_hash,status,created_at,origin) "
            "VALUES(?,?,?,?,?,?,?)",
            (tid, payload.name, payload.plan, digest(key), "active", now(), "local"),
        )
        audit(c, tid, "tenant.created", {"plan": payload.plan})
        c.commit()
        return {"tenant_id": tid, "api_key": key, "plan": payload.plan}
    finally:
        c.close()


@app.post("/v1/public/signup")
def public_signup(payload: PublicSignupCreate, request: Request):
    email = normalize_email(payload.email)
    client_ip = public_signup_client_ip(request)
    check_rate_limit(f"public-signup-ip:{client_ip}", PUBLIC_SIGNUP_RATE_LIMIT_REQUESTS)
    check_rate_limit(f"public-signup-email:{email}", PUBLIC_SIGNUP_RATE_LIMIT_REQUESTS)
    if payload.plan != "shared":
        raise HTTPException(400, "dedicated plans require you to get in touch with Mosaic")
    tenant_name = derive_tenant_name(email, payload.tenant_name)
    key_name = payload.key_name.strip() or "Self-serve key"
    c = db()
    try:
        signup = c.execute(
            "SELECT * FROM public_signups WHERE email=?",
            (email,),
        ).fetchone()
        if signup:
            refuse_existing_signup(c, email)
        else:
            api_key = token("mdb_live_")
            created = now()
            tenant_id = token("ten_")
            effective_name = tenant_name
            try:
                c.execute(
                    "INSERT INTO tenants(id,name,plan,api_key_hash,status,created_at,origin) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (tenant_id, effective_name, "shared", digest(api_key), "active", created, "local"),
                )
                c.execute(
                    "INSERT INTO public_signups VALUES(?,?,?,?,?,?)",
                    (email, tenant_id, effective_name, created, created, created),
                )
            except Exception as exc:
                if not is_unique_violation(exc):
                    raise
                c.rollback()
                refuse_existing_signup(c, email)
            status_text = "created"
        audit(c, tenant_id, f"public_signup.{status_text}", {
            "plan": "shared",
            "key_name": key_name,
        }, actor=email)
        c.commit()
    finally:
        c.close()
    return {
        "status": status_text,
        "tenant_id": tenant_id,
        "tenant_name": effective_name,
        "plan": "shared",
        "key_name": key_name,
        "api_key": api_key,
        "token_prefix": api_key[:12],
        "quickstart": {
            "endpoint": MOSAIC_PUBLIC_ENDPOINT,
            "command": (
                f"export MOSAIC_ENDPOINT={MOSAIC_PUBLIC_ENDPOINT}\n"
                f"export MOSAIC_TENANT_ID={tenant_id}\n"
                f"export MOSAIC_API_KEY={api_key}\n\n"
                "DB_ID=$(curl -fsS -X POST "
                "\"$MOSAIC_ENDPOINT/v1/tenants/$MOSAIC_TENANT_ID/databases\" "
                "-H \"X-API-Key: $MOSAIC_API_KEY\" "
                "-H \"Content-Type: application/json\" "
                "-d '{\"name\":\"events\"}' | jq -r .id)\n"
                "curl -fsS -X POST "
                "\"$MOSAIC_ENDPOINT/v1/tenants/$MOSAIC_TENANT_ID/databases/$DB_ID/query\" "
                "-H \"X-API-Key: $MOSAIC_API_KEY\" "
                "-H \"Content-Type: application/json\" "
                "-d '{\"sql\":\"SELECT 1 AS ok\"}'"
            ),
            "docs_path": "/docs/",
            "signup_path": "/start/",
        },
    }


def promotion_lag_is_acceptable(replica) -> bool:
    if replica["lag_bytes"] is None or not replica["lag_sampled_at"]:
        return False
    try:
        sampled_at = datetime.fromisoformat(replica["lag_sampled_at"])
    except ValueError:
        return False
    age = (datetime.now(timezone.utc) - sampled_at).total_seconds()
    return (
        age <= int(os.getenv(
            "MOSAIC_PROMOTION_MAX_LAG_AGE_SECONDS",
            str(PROMOTION_MAX_LAG_AGE_SECONDS),
        ))
        and int(replica["lag_bytes"]) <= int(os.getenv(
            "MOSAIC_PROMOTION_MAX_LAG_BYTES",
            str(PROMOTION_MAX_LAG_BYTES),
        ))
    )


@app.post("/v1/admin/databases/{database_id}/promote")
def promote_database(
    database_id: str,
    payload: PromotionRequest,
    _: None = Depends(require_admin),
):
    with _branch_mutation_lock:
        return _promote_database_locked(database_id, payload)


def _promote_database_locked(database_id: str, payload: PromotionRequest):
    c = db()
    try:
        main_row = c.execute(
            "SELECT * FROM branches WHERE database_id=? AND name='main'",
            (database_id,),
        ).fetchone()
        if not main_row:
            raise HTTPException(404, "database not found")
        if main_row["host_id"] == payload.host_id:
            try:
                postgres_password = cipher().decrypt(
                    main_row["credential_encrypted"].encode()
                ).decode()
            except InvalidToken as exc:
                raise HTTPException(503, "primary credentials cannot be decrypted") from exc
            try:
                result = node_transport.call(payload.host_id, "promote_standby", {
                    "target_path": main_row["path"],
                    "target_port": main_row["port"],
                    "target_host_id": payload.host_id,
                    "postgres_password": postgres_password,
                })
            except Exception as exc:
                error = redact_error(str(exc), (postgres_password,))
                raise HTTPException(503, f"promotion failed: {error[:500]}") from exc
            audit(
                c,
                None,
                "database.promoted",
                {
                    "database_id": database_id,
                    "promoted_host": payload.host_id,
                    "fence": "already primary",
                    "lag_bytes": None,
                    "force": payload.force,
                },
                actor="admin",
            )
            c.commit()
            return {
                "status": result["status"],
                "host_id": payload.host_id,
                "pid": result["pid"],
                "port": result["port"],
                "lag_bytes": None,
            }
        replica = c.execute(
            "SELECT * FROM replicas WHERE database_id=? AND host_id=?",
            (database_id, payload.host_id),
        ).fetchone()
        if not replica:
            raise HTTPException(404, "promotion target is not a replica")
        if replica["status"] != "ready":
            raise HTTPException(409, "promotion target replica is not ready")
        if not promotion_lag_is_acceptable(replica) and not payload.force:
            raise HTTPException(
                409,
                "promotion target lag sample is missing, stale, or beyond the configured threshold",
            )
        try:
            postgres_password = cipher().decrypt(
                main_row["credential_encrypted"].encode()
            ).decode()
        except InvalidToken as exc:
            raise HTTPException(503, "primary credentials cannot be decrypted") from exc

        old_primary = {
            "host_id": main_row["host_id"],
            "path": main_row["path"],
            "port": main_row["port"],
        }
        fence_outcome = "reachable and stopped"
        abandoned = None
        try:
            node_transport.call(main_row["host_id"], "stop", {
                "path": main_row["path"],
                "pid": main_row["pid"],
                "require_path": True,
            })
        except Exception as exc:
            if not payload.force:
                raise HTTPException(
                    409,
                    "old primary is unreachable; set force=true only after asserting it is dead",
                ) from exc
            fence_outcome = f"unreachable; force asserted: {type(exc).__name__}"
            abandoned = {
                **old_primary,
                "reason": "old primary unreachable during forced promotion",
            }
        c.execute(
            "UPDATE branches SET status='stopped',pid=NULL WHERE id=?",
            (main_row["id"],),
        )
        if abandoned:
            c.execute(
                "INSERT INTO abandoned_clusters(id,database_id,host_id,path,port,created_at,reason) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    token("abn_"),
                    database_id,
                    abandoned["host_id"],
                    abandoned["path"],
                    abandoned["port"],
                    now(),
                    abandoned["reason"],
                ),
            )
        audit(
            c,
            None,
            "database.promotion_fenced",
            {
                "database_id": database_id,
                "fence": fence_outcome,
                "old_primary_host": old_primary["host_id"],
                "old_primary_path": old_primary["path"],
                "old_primary_port": old_primary["port"],
                "force": payload.force,
                "abandoned": abandoned,
            },
            actor="admin",
        )
        c.commit()
        try:
            promoted = node_transport.call(payload.host_id, "promote_standby", {
                "target_path": replica["path"],
                "target_port": replica["port"],
                "target_host_id": payload.host_id,
                "postgres_password": postgres_password,
            })
        except Exception as exc:
            audit(
                c,
                None,
                "database.promotion_failed",
                {
                    "database_id": database_id,
                    "fence": fence_outcome,
                    "promoted_host": payload.host_id,
                    "error": type(exc).__name__,
                    "old_primary_host": old_primary["host_id"],
                    "old_primary_path": old_primary["path"],
                    "old_primary_port": old_primary["port"],
                    "abandoned": abandoned,
                },
                actor="admin",
            )
            c.commit()
            error = redact_error(str(exc), (postgres_password,))
            raise HTTPException(503, f"promotion failed: {error[:500]}") from exc

        cleanup = "destroyed"
        cleanup_error = None
        if not abandoned:
            try:
                node_transport.call(old_primary["host_id"], "destroy", {
                    "path": old_primary["path"],
                })
            except Exception as exc:
                cleanup = "failed"
                cleanup_error = type(exc).__name__
                abandoned = {
                    **old_primary,
                    "reason": "old primary cleanup failed after promotion",
                }
                c.execute(
                    "INSERT INTO abandoned_clusters(id,database_id,host_id,path,port,created_at,reason) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        token("abn_"),
                        database_id,
                        abandoned["host_id"],
                        abandoned["path"],
                        abandoned["port"],
                        now(),
                        abandoned["reason"],
                    ),
                )

        c.execute(
            "UPDATE branches SET host_id=?,path=?,port=?,status='running',pid=? WHERE id=?",
            (
                replica["host_id"],
                replica["path"],
                promoted["port"],
                promoted["pid"],
                main_row["id"],
            ),
        )
        c.execute("DELETE FROM replicas WHERE database_id=?", (database_id,))
        c.execute(
            "DELETE FROM replication_credentials WHERE database_id=?",
            (database_id,),
        )
        new_main = c.execute(
            "SELECT * FROM branches WHERE id=?", (main_row["id"],)
        ).fetchone()
        create_replicas(
            c,
            database_id,
            new_main,
            postgres_password,
            status="rebuild_required",
        )
        audit(
            c,
            None,
            "database.promoted",
            {
                "database_id": database_id,
                "fence": fence_outcome,
                "promoted_host": payload.host_id,
                "lag_bytes": replica["lag_bytes"],
                "lag_sampled_at": replica["lag_sampled_at"],
                "force": payload.force,
                "old_primary_host": old_primary["host_id"],
                "old_primary_path": old_primary["path"],
                "old_primary_port": old_primary["port"],
                "old_primary_cleanup": cleanup,
                "old_primary_cleanup_error": cleanup_error,
                "abandoned": abandoned,
            },
            actor="admin",
        )
        c.commit()
        return {
            "status": promoted["status"],
            "host_id": payload.host_id,
            "pid": promoted["pid"],
            "port": promoted["port"],
            "lag_bytes": replica["lag_bytes"],
        }
    finally:
        c.close()


@app.post("/v1/tenants/{tid}/api-key")
def rotate_key(tid: str, tenant=Depends(tenant_auth)):
    key = token("mdb_live_")
    c = db()
    try:
        c.execute("UPDATE tenants SET api_key_hash=? WHERE id=?", (digest(key), tid))
        audit(c, tid, "api_key.rotated", {})
        c.commit()
        return {"api_key": key}
    finally:
        c.close()


@app.delete("/v1/tenants/{tid}/api-key")
def revoke_key(tid: str, tenant=Depends(tenant_auth)):
    c = db()
    try:
        c.execute("UPDATE tenants SET api_key_hash='' WHERE id=?", (tid,))
        audit(c, tid, "api_key.revoked", {})
        c.commit()
        return {"status": "key_revoked"}
    finally:
        c.close()


def database(c: Conn, tid: str, did: str):
    row = c.execute("SELECT * FROM databases WHERE id=? AND tenant_id=?", (did, tid)).fetchone()
    if not row:
        raise HTTPException(404, "database not found")
    return row


def branch(c: Conn, did: str, name: str):
    row = c.execute("SELECT * FROM branches WHERE database_id=? AND (id=? OR name=?)", (did, name, name)).fetchone()
    if not row:
        raise HTTPException(404, "branch not found")
    return row


@app.post("/v1/tenants/{tid}/databases")
def create_database(tid: str, payload: DatabaseCreate, tenant=Depends(tenant_auth)):
    c = db()
    try:
        existing = c.execute("SELECT * FROM databases WHERE tenant_id=? AND name=?", (tid, payload.name)).fetchone()
        if existing:
            return {"id": existing["id"], "name": existing["name"], "status": existing["status"], "reused": True}
        count = c.execute("SELECT COUNT(*) AS n FROM databases WHERE tenant_id=?", (tid,)).fetchone()
        if count["n"] >= PLANS[tenant["plan"]]["max_databases"]:
            raise HTTPException(403, "database limit exceeded")
        did, root = token("db_"), BRANCH_ROOT / token("cluster_")
        password, bid = secrets.token_urlsafe(24), token("br_")
        with _branch_mutation_lock:
            total = c.execute("SELECT COUNT(*) AS n FROM databases").fetchone()
            if total["n"] >= MAX_DATABASES_TOTAL:
                audit(c, tid, "database.creation_refused_capacity", {
                    "limit": MAX_DATABASES_TOTAL,
                })
                c.commit()
                raise HTTPException(503, "Mosaic Database is at capacity; please try again later")
            main_port = supervisor.allocate_port(c)
            host_id = placement_node(did)
            node_transport.call(host_id, "provision", {
                "path": str(root / "main"),
                "password": password,
                "port": main_port,
                "host_id": host_id,
            })
            c.execute("INSERT INTO databases VALUES(?,?,?,?,?,?)", (did, tid, payload.name, str(root), "ready", now()))
            c.execute("INSERT INTO branches(id,database_id,name,parent_id,path,port,pid,status,credential_encrypted,last_query_at,created_at,host_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (bid, did, "main", None, str(root / "main"), main_port, None, "stopped", cipher().encrypt(password.encode()).decode(), now(), now(), host_id))
            main_row = c.execute("SELECT * FROM branches WHERE id=?", (bid,)).fetchone()
            create_replicas(c, did, main_row, password)
            audit(c, tid, "database.created", {"database_id": did})
            c.commit()
        return {"id": did, "name": payload.name, "status": "ready", "main_branch": {"id": bid, "name": "main", "password": password}}
    finally:
        c.close()


@app.get("/v1/tenants/{tid}/databases")
def get_databases(tid: str, tenant=Depends(tenant_auth)):
    c = db()
    try:
        return {"databases": [dict(row) for row in c.execute("SELECT id,name,status,created_at FROM databases WHERE tenant_id=?", (tid,)).fetchall()]}
    finally:
        c.close()


@app.get("/v1/tenants/{tid}/databases/{did}")
def get_database(tid: str, did: str, tenant=Depends(tenant_auth)):
    c = db()
    try:
        row = database(c, tid, did)
        return {key: row[key] for key in ("id", "name", "status", "created_at")}
    finally:
        c.close()


def _create_branch(c: Conn, tid: str, did: str, payload: BranchCreate, tenant):
    parent_db, parent = database(c, tid, did), branch(c, did, payload.parent)
    if payload.name in RESERVED_BRANCH_NAMES:
        raise HTTPException(400, "branch name is reserved")
    count = c.execute("SELECT COUNT(*) AS n FROM branches WHERE database_id=?", (did,)).fetchone()
    if count["n"] >= PLANS[tenant["plan"]]["max_branches"]:
        raise HTTPException(403, "branch limit exceeded")
    if c.execute("SELECT 1 FROM branches WHERE database_id=? AND name=?", (did, payload.name)).fetchone():
        raise HTTPException(409, "branch already exists")
    bid, path = token("br_"), Path(parent_db["root_path"]) / payload.name
    password = secrets.token_urlsafe(24)
    with _branch_mutation_lock:
        port = supervisor.allocate_port(c)
        parent_password = cipher().decrypt(parent["credential_encrypted"].encode()).decode()
        node_transport.call(parent["host_id"], "clone", {
            "parent": str(parent["path"]),
            "target": str(path),
            "parent_port": parent["port"] if parent["status"] == "running" else None,
            "parent_password": parent_password,
            "target_port": port,
            "parent_host_id": parent["host_id"],
            "target_host_id": parent["host_id"],
        })
        c.execute("INSERT INTO branches(id,database_id,name,parent_id,path,port,pid,status,credential_encrypted,last_query_at,created_at,host_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (bid, did, payload.name, parent["id"], str(path), port, None, "stopped", cipher().encrypt(password.encode()).decode(), now(), now(), parent["host_id"]))
    audit(c, tid, "branch.created", {"branch_id": bid, "parent": parent["id"]})
    c.commit()
    return {"id": bid, "name": payload.name, "parent": parent["name"], "status": "stopped", "password": password, "host_id": parent["host_id"]}


@app.post("/v1/tenants/{tid}/databases/{did}/branches")
def create_branch(tid: str, did: str, payload: BranchCreate, tenant=Depends(tenant_auth)):
    c = db()
    try:
        return _create_branch(c, tid, did, payload, tenant)
    finally:
        c.close()


def list_branches(tid: str, did: str, tenant):
    c = db()
    try:
        database(c, tid, did)
        return {"branches": [dict(row) for row in c.execute("SELECT id,name,parent_id,status,port,host_id,last_query_at,created_at FROM branches WHERE database_id=?", (did,)).fetchall()]}
    finally:
        c.close()


@app.get("/v1/tenants/{tid}/databases/{did}/branches")
def branches_get(tid: str, did: str, tenant=Depends(tenant_auth)):
    return list_branches(tid, did, tenant)


@app.get("/v1/tenants/{tid}/databases/{did}/replicas")
def replicas_get(tid: str, did: str, tenant=Depends(tenant_auth)):
    c = db()
    try:
        database(c, tid, did)
        sampling = refresh_replica_lag(c, did)
        rows = c.execute(
            "SELECT id,host_id,path,port,status,lag_bytes,lag_sampled_at,created_at,last_error "
            "FROM replicas WHERE database_id=? ORDER BY host_id",
            (did,),
        ).fetchall()
        return {
            "replicas": [dict(row) for row in rows],
            "lag_unit": "bytes behind primary WAL replay position",
            "lag_sample_error": sampling.get("error"),
            "lag_sampled_at": sampling.get("sampled_at"),
        }
    finally:
        c.close()


@app.delete("/v1/tenants/{tid}/databases/{did}/branches/{bid}")
def delete_branch(tid: str, did: str, bid: str, tenant=Depends(tenant_auth)):
    c = db()
    try:
        database(c, tid, did)
        row = branch(c, did, bid)
        if row["name"] == "main":
            raise HTTPException(400, "main branch is protected")
        node_transport.call(row["host_id"], "stop", {"path": row["path"], "pid": row["pid"]})
        node_transport.call(row["host_id"], "destroy", {"path": row["path"]})
        c.execute("DELETE FROM branches WHERE id=?", (bid,))
        audit(c, tid, "branch.deleted", {"branch_id": bid})
        c.commit()
        return {"status": "deleted"}
    finally:
        c.close()


def _sql_without_comments_or_literals(sql: str) -> str:
    output, index, quote = [], 0, None
    while index < len(sql):
        if quote:
            if sql[index] == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    output.extend("  ")
                    index += 2
                    continue
                quote = None
            output.append(" ")
            index += 1
            continue
        if sql.startswith("--", index):
            newline = sql.find("\n", index)
            index = len(sql) if newline == -1 else newline
            output.append(" ")
            continue
        if sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            index = len(sql) if end == -1 else end + 2
            output.append(" ")
            continue
        if sql[index] in ("'", '"'):
            quote = sql[index]
            output.append(" ")
        else:
            output.append(sql[index])
        index += 1
    return "".join(output)


def forbidden_sql(sql: str) -> str | None:
    normalized = re.sub(r"\s+", " ", _sql_without_comments_or_literals(sql).strip().lower())
    if ";" in normalized.rstrip(";"):
        return "exactly one SQL statement is required"
    if re.match(r"^(create|alter|drop|truncate|grant|revoke|comment|vacuum|reindex|analyze|copy|do|call|prepare|execute|listen|notify|unlisten)\b", normalized):
        return "DDL and server-side commands are not accepted on the query endpoint"
    blocked = [r"\bpg_read_file\s*\(", r"\bpg_read_binary_file\s*\(", r"\bpg_ls_dir\s*\(", r"\bdblink(?:_[a-z]+)?\s*\(", r"\bpostgres_fdw\b", r"\blo_import\s*\(", r"\blo_export\s*\(", r"\bcopy\b.*\bprogram\b", r"\bset\s+role\b", r"\bset\s+session_authorization\b", r"\bpg_terminate_backend\b", r"\bpg_cancel_backend\b", r"\bpg_reload_conf\b"]
    if any(re.search(pattern, normalized) for pattern in blocked):
        return "statement uses a blocked superuser, filesystem, foreign-server, or process capability"
    if not re.match(r"^(select|insert|update|delete|with|values|show)\b", normalized):
        return "only parameterized DML and read queries are accepted"
    return None


def execute_query(tid: str, did: str, payload: Query, tenant):
    if (error := forbidden_sql(payload.sql)):
        raise HTTPException(400, error)
    c = db()
    try:
        database(c, tid, did)
        row = branch(c, did, payload.branch)
        try:
            start_result = node_transport.call(row["host_id"], "start", branch_start_payload(c, row))
            c.execute("UPDATE branches SET status=?,pid=? WHERE id=?", (start_result["status"], start_result["pid"], row["id"]))
            c.commit()
        except RuntimeError as exc:
            raise HTTPException(503, f"branch unavailable: {exc}") from exc
        if psycopg is None:
            raise HTTPException(503, "PostgreSQL driver unavailable")
        try:
            password = cipher().decrypt(row["credential_encrypted"].encode()).decode()
        except InvalidToken as exc:
            raise HTTPException(503, "branch credentials cannot be decrypted") from exc
        try:
            conn = psycopg.connect(host=node_address(row["host_id"]), port=row["port"], user="postgres", password=password, dbname="postgres", connect_timeout=5)
        except Exception as exc:
            if _is_psycopg_error(exc, "OperationalError", "InterfaceError", "InternalError"):
                raise HTTPException(503, "database unavailable") from exc
            raise
        try:
            try:
                conn.execute(f"SET statement_timeout = {PLANS[tenant['plan']]['statement_timeout_ms']}")
                try:
                    cur = conn.execute(payload.sql, payload.params)
                except Exception as exc:
                    if _is_psycopg_error(exc, "DataError", "IntegrityError", "ProgrammingError", "NotSupportedError"):
                        sensitive = (
                            password,
                            str(row["path"]),
                            node_address(row["host_id"]),
                            str(row["port"]),
                        )
                        raise HTTPException(400, _statement_error_detail(exc, sensitive)) from exc
                    raise
                max_rows = PLANS[tenant["plan"]]["max_rows"]
                rows = cur.fetchmany(max_rows + 1) if cur.description else []
                if len(rows) > max_rows:
                    raise HTTPException(413, "row limit exceeded")
                result = {"rows": [list(x) for x in rows], "columns": [x.name for x in (cur.description or [])], "row_count": len(rows)}
                conn.commit()
            except HTTPException:
                raise
            except Exception as exc:
                if _is_psycopg_error(exc, "OperationalError", "InterfaceError", "InternalError"):
                    raise HTTPException(503, "database unavailable") from exc
                raise
        finally:
            conn.close()
        c.execute("UPDATE branches SET last_query_at=? WHERE id=?", (now(), row["id"]))
        c.execute("INSERT INTO usage_events(tenant_id,kind,quantity,unit,occurred_at,metadata,idempotency_key) VALUES(?,?,?,?,?,?,?)", (tid, "query_rows", result["row_count"], "rows", now(), json.dumps({"branch_id": row["id"]}), ""))
        audit(c, tid, "query.executed", {"branch_id": row["id"], "rows": result["row_count"]})
        c.commit()
        return result
    finally:
        c.close()


@app.post("/v1/tenants/{tid}/databases/{did}/query")
def query_database(tid: str, did: str, payload: Query, tenant=Depends(tenant_auth)):
    return execute_query(tid, did, payload, tenant)


def database_schema(tid: str, did: str, branch_name: str, tenant):
    return execute_query(tid, did, Query(sql="SELECT table_schema, table_name, column_name, data_type FROM information_schema.columns WHERE table_schema NOT IN ('pg_catalog','information_schema') ORDER BY table_schema, table_name, ordinal_position", branch=branch_name), tenant)


@app.get("/v1/tenants/{tid}/databases/{did}/schema")
def schema(tid: str, did: str, branch: str = "main", tenant=Depends(tenant_auth)):
    return database_schema(tid, did, branch, tenant)


def deploy_response(row, *, duplicate: bool = False):
    result = {
        "id": row["id"],
        "database_id": row["database_id"],
        "branch": row["branch_name"],
        "status": row["status"],
        "operations": json.loads(row["operations"]),
        "sql_preview": json.loads(row["sql_preview"]),
        "schema_version": row["schema_version"],
        "error": row["error"],
        "source_deploy_id": row["source_deploy_id"],
        "created_at": row["created_at"],
        "applied_at": row["applied_at"],
    }
    if duplicate:
        result["duplicate"] = True
    return result


def deploy_row(c: Conn, deploy_id: str, tid: str):
    row = c.execute(
        "SELECT r.*, b.name AS branch_name "
        "FROM deploy_requests r JOIN branches b ON b.id=r.branch_id "
        "WHERE r.id=? AND r.tenant_id=?",
        (deploy_id, tid),
    ).fetchone()
    if not row:
        raise HTTPException(404, "deploy request not found")
    return row


def create_deploy_request(c: Conn, tid: str, did: str, payload: DeployCreate, tenant):
    database_row = database(c, tid, did)
    branch_row = branch(c, did, payload.branch)
    operations_json = deploy_operations_json(payload.operations)
    sql_preview = compile_deploy_operations(payload.operations)
    plan = PLANS[tenant["plan"]]
    if len(payload.operations) > plan["max_deploy_operations"]:
        raise HTTPException(403, "deploy operation limit exceeded")
    if payload.idempotency_key:
        existing = c.execute(
            "SELECT r.*, b.name AS branch_name FROM deploy_requests r JOIN branches b ON b.id=r.branch_id "
            "WHERE r.tenant_id=? AND r.idempotency_key=?",
            (tid, payload.idempotency_key),
        ).fetchone()
        if existing:
            return deploy_response(existing, duplicate=True)
    if branch_row["name"] == "main":
        if deploy_is_destructive(payload.operations):
            raise HTTPException(400, "destructive deploys are not allowed on main")
        if not payload.source_deploy_id:
            raise HTTPException(400, "main deploy requires a successful branch deploy reference")
        source = c.execute(
            "SELECT * FROM deploy_requests WHERE id=? AND tenant_id=? AND database_id=?",
            (payload.source_deploy_id, tid, did),
        ).fetchone()
        if (
            not source
            or source["status"] != "applied"
            or source["branch_id"] == branch_row["id"]
            or source["operations"] != operations_json
        ):
            raise HTTPException(400, "main deploy must reference a matching successful branch deploy")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    recent = c.execute(
        "SELECT COUNT(*) AS n FROM deploy_requests WHERE tenant_id=? AND created_at>=?",
        (tid, cutoff),
    ).fetchone()
    if recent["n"] >= plan["max_deploys_per_day"]:
        raise HTTPException(403, "daily deploy limit exceeded")
    deploy_id = token("dep_")
    created_at = now()
    try:
        c.execute(
            "INSERT INTO deploy_requests(id,tenant_id,database_id,branch_id,operations,sql_preview,status,schema_version,error,idempotency_key,source_deploy_id,created_at,applied_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (deploy_id, tid, did, branch_row["id"], operations_json, json.dumps(sql_preview), "pending", 0, None, payload.idempotency_key, payload.source_deploy_id, created_at, None),
        )
        audit(c, tid, "deploy.created", {"deploy_id": deploy_id, "database_id": did, "branch_id": branch_row["id"]})
        c.commit()
    except Exception as exc:
        if not is_unique_violation(exc):
            raise
        c.rollback()
        if payload.idempotency_key:
            existing = c.execute(
                "SELECT r.*, b.name AS branch_name FROM deploy_requests r JOIN branches b ON b.id=r.branch_id "
                "WHERE r.tenant_id=? AND r.idempotency_key=?",
                (tid, payload.idempotency_key),
            ).fetchone()
            if existing:
                return deploy_response(existing, duplicate=True)
        raise
    return deploy_response(c.execute(
        "SELECT r.*, b.name AS branch_name FROM deploy_requests r JOIN branches b ON b.id=r.branch_id WHERE r.id=?",
        (deploy_id,),
    ).fetchone())


def _begin_deploy(c: Conn, tid: str, deploy_id: str):
    with _deploy_lock:
        row = deploy_row(c, deploy_id, tid)
        if row["status"] != "pending":
            return row, False
        active = c.execute(
            "SELECT 1 FROM deploy_requests WHERE database_id=? AND status='applying' AND id<>?",
            (row["database_id"], deploy_id),
        ).fetchone()
        if active:
            raise HTTPException(409, "another deploy is already applying for this database")
        c.execute("UPDATE deploy_requests SET status='applying' WHERE id=?", (deploy_id,))
        c.execute(
            "INSERT INTO deploy_locks(branch_id,deploy_id,started_at) VALUES(?,?,?)",
            (row["branch_id"], deploy_id, now()),
        )
        audit(c, tid, "deploy.applying", {"deploy_id": deploy_id, "database_id": row["database_id"], "branch_id": row["branch_id"]})
        c.commit()
        return deploy_row(c, deploy_id, tid), True


def _finish_deploy(c: Conn, row, status: str, schema_version: int, error: str | None = None):
    c.execute(
        "UPDATE deploy_requests SET status=?,schema_version=?,error=?,applied_at=? WHERE id=?",
        (status, schema_version, error, now() if status == "applied" else None, row["id"]),
    )
    c.execute("DELETE FROM deploy_locks WHERE deploy_id=?", (row["id"],))
    audit(c, row["tenant_id"], f"deploy.{status}", {
        "deploy_id": row["id"],
        "database_id": row["database_id"],
        "branch_id": row["branch_id"],
        "schema_version": schema_version,
        "error": error,
    })
    c.commit()


def deploy_lock_lease_seconds() -> int:
    return max(1, int(os.getenv("MOSAIC_DEPLOY_LOCK_LEASE_SECONDS", "900")))


def reconcile_deploy_locks(c: Conn) -> int:
    cutoff = time.time() - deploy_lock_lease_seconds()
    recovered = 0
    rows = c.execute(
        "SELECT r.*, l.started_at FROM deploy_requests r "
        "LEFT JOIN deploy_locks l ON l.deploy_id=r.id "
        "WHERE r.status='applying'"
    ).fetchall()
    for row in rows:
        stale = not row["started_at"]
        if row["started_at"]:
            try:
                stale = datetime.fromisoformat(row["started_at"]).timestamp() < cutoff
            except ValueError:
                stale = True
        if stale:
            _finish_deploy(
                c,
                row,
                "failed",
                row["schema_version"],
                "deploy interrupted before completion",
            )
            recovered += 1
    return recovered


def _apply_deploy(deploy_id: str, tid: str):
    c = db()
    conn = None
    password = ""
    try:
        row = deploy_row(c, deploy_id, tid)
        branch_row = c.execute("SELECT * FROM branches WHERE id=?", (row["branch_id"],)).fetchone()
        if row["status"] != "applying":
            return
        try:
            start_result = node_transport.call(branch_row["host_id"], "start", branch_start_payload(c, branch_row))
            c.execute("UPDATE branches SET status=?,pid=? WHERE id=?", (start_result["status"], start_result["pid"], branch_row["id"]))
            c.commit()
            password = cipher().decrypt(branch_row["credential_encrypted"].encode()).decode()
            if psycopg is None:
                raise RuntimeError("PostgreSQL driver unavailable")
            conn = psycopg.connect(
                host=node_address(branch_row["host_id"]),
                port=branch_row["port"],
                user="postgres",
                password=password,
                dbname="postgres",
                connect_timeout=5,
            )
            timeout = PLANS[c.execute("SELECT plan FROM tenants WHERE id=?", (tid,)).fetchone()["plan"]]["statement_timeout_ms"]
            conn.execute(f"SET statement_timeout = {timeout}")
            conn.execute("SET lock_timeout = 2000")
            for statement in json.loads(row["sql_preview"]):
                conn.execute(statement)
            conn.commit()
            database_row = c.execute(
                "SELECT COALESCE(MAX(schema_version),0) AS schema_version FROM deploy_requests "
                "WHERE branch_id=? AND status='applied'",
                (row["branch_id"],),
            ).fetchone()
            schema_version = database_row["schema_version"] + 1
            _finish_deploy(c, row, "applied", schema_version)
        except HTTPException:
            raise
        except Exception as exc:
            if _is_psycopg_error(exc, "DataError", "IntegrityError", "ProgrammingError", "NotSupportedError"):
                sensitive = (
                    password,
                    str(branch_row["path"]),
                    node_address(branch_row["host_id"]),
                    str(branch_row["port"]),
                )
                error = _statement_error_detail(exc, sensitive)
            elif _is_psycopg_error(exc, "OperationalError", "InterfaceError", "InternalError"):
                error = "database unavailable"
            elif isinstance(exc, RuntimeError):
                error = "branch unavailable"
            else:
                error = redact_error(str(exc), (str(branch_row["path"]), str(branch_row["port"])))
            if conn is not None:
                try:
                    conn.rollback()
                except Exception:
                    pass
            _finish_deploy(c, row, "failed", row["schema_version"], error)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    logger.warning("failed to close deploy connection for %s", deploy_id)
    except Exception:
        logger.exception("deploy apply failed for %s", deploy_id)
        row = deploy_row(c, deploy_id, tid)
        if row["status"] == "applying":
            _finish_deploy(c, row, "failed", row["schema_version"], "deploy failed")
    finally:
        c.close()


@app.post("/v1/tenants/{tid}/databases/{did}/deploys", status_code=201)
def create_deploy(tid: str, did: str, payload: DeployCreate, response: Response, tenant=Depends(tenant_auth)):
    c = db()
    try:
        result = create_deploy_request(c, tid, did, payload, tenant)
        if result.get("duplicate"):
            response.status_code = 200
        return result
    finally:
        c.close()


@app.post("/v1/tenants/{tid}/databases/{did}/deploys/{deploy_id}/apply")
def apply_deploy(tid: str, did: str, deploy_id: str, response: Response, background_tasks: BackgroundTasks, tenant=Depends(tenant_auth)):
    c = db()
    try:
        row = deploy_row(c, deploy_id, tid)
        if row["database_id"] != did:
            raise HTTPException(404, "deploy request not found")
        row, transitioned = _begin_deploy(c, tid, deploy_id)
        if row["status"] in {"applied", "failed"}:
            raise HTTPException(409, f"deploy request is already {row['status']}")
        response.status_code = 202
        if transitioned:
            background_tasks.add_task(_apply_deploy, deploy_id, tid)
        return deploy_response(row)
    finally:
        c.close()


@app.get("/v1/tenants/{tid}/databases/{did}/deploys/{deploy_id}")
def get_deploy(tid: str, did: str, deploy_id: str, tenant=Depends(tenant_auth)):
    c = db()
    try:
        row = deploy_row(c, deploy_id, tid)
        if row["database_id"] != did:
            raise HTTPException(404, "deploy request not found")
        return deploy_response(row)
    finally:
        c.close()


@app.get("/v1/tenants/{tid}/databases/{did}/deploys")
def list_deploys(tid: str, did: str, tenant=Depends(tenant_auth)):
    c = db()
    try:
        database(c, tid, did)
        rows = c.execute(
            "SELECT r.*, b.name AS branch_name FROM deploy_requests r JOIN branches b ON b.id=r.branch_id "
            "WHERE r.tenant_id=? AND r.database_id=? ORDER BY r.created_at DESC",
            (tid, did),
        ).fetchall()
        return {"deploys": [deploy_response(row) for row in rows]}
    finally:
        c.close()


@app.post("/v1/tenants/{tid}/usage")
def usage_post(tid: str, payload: Usage, tenant=Depends(tenant_auth)):
    c = db()
    try:
        if payload.idempotency_key and c.execute("SELECT 1 FROM usage_events WHERE tenant_id=? AND idempotency_key=?", (tid, payload.idempotency_key)).fetchone():
            return {"duplicate": True}
        c.execute("INSERT INTO usage_events(tenant_id,kind,quantity,unit,occurred_at,metadata,idempotency_key) VALUES(?,?,?,?,?,?,?)", (tid, payload.kind, payload.quantity, payload.unit, now(), "{}", payload.idempotency_key))
        audit(c, tid, "usage.recorded", {"kind": payload.kind})
        c.commit()
        return {"recorded": True}
    finally:
        c.close()


@app.get("/v1/tenants/{tid}/usage")
def usage_get(tid: str, tenant=Depends(tenant_auth)):
    c = db()
    try:
        return {"usage": [dict(row) for row in c.execute("SELECT kind,quantity,unit,occurred_at FROM usage_events WHERE tenant_id=? ORDER BY id DESC", (tid,)).fetchall()]}
    finally:
        c.close()
