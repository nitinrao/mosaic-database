from __future__ import annotations

import hashlib
import asyncio
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request
from glob import glob
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field

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
NODE_ID = os.getenv("MOSAIC_NODE_ID", "local")
NODE_AGENT_TOKEN = os.getenv("MOSAIC_NODE_AGENT_TOKEN", "")
PLANS = {
    "shared": {"monthly_cents": 10000, "max_databases": 5, "max_branches": 20, "max_rows": 10000, "max_bytes": 1000000, "statement_timeout_ms": 5000},
    "dedicated": {"monthly_cents": 50000, "max_databases": 20, "max_branches": 100, "max_rows": 100000, "max_bytes": 10000000, "statement_timeout_ms": 30000},
}
MCP_PROTOCOL_VERSION = "2025-03-26"
MCP_TOOLS = [{"name": n, "description": d, "inputSchema": {"type": "object"}} for n, d in (
    ("inspect_schema", "Inspect branch schema"), ("query", "Execute one governed statement"),
    ("create_branch", "Create a branch"), ("list_branches", "List branches"))]
_rate: dict[str, list[float]] = {}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def token(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(18)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


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
    nodes = node_ids()
    if len(nodes) == 1:
        return "127.0.0.1"
    address = node_private_addresses().get(node_id)
    if not address:
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
    CREATE TABLE IF NOT EXISTS tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL, plan TEXT NOT NULL, api_key_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS databases (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), name TEXT NOT NULL, root_path TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(tenant_id,name));
    CREATE TABLE IF NOT EXISTS branches (id TEXT PRIMARY KEY, database_id TEXT NOT NULL REFERENCES databases(id), name TEXT NOT NULL, parent_id TEXT, path TEXT NOT NULL, port INTEGER NOT NULL, pid INTEGER, status TEXT NOT NULL, credential_encrypted TEXT NOT NULL, last_query_at TEXT NOT NULL, created_at TEXT NOT NULL, host_id TEXT NOT NULL DEFAULT 'local', UNIQUE(database_id,name));
    CREATE TABLE IF NOT EXISTS usage_events (id {integer}, tenant_id TEXT NOT NULL REFERENCES tenants(id), kind TEXT NOT NULL, quantity INTEGER NOT NULL, unit TEXT NOT NULL, occurred_at TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{{}}', idempotency_key TEXT NOT NULL DEFAULT '');
    CREATE TABLE IF NOT EXISTS audit_log (id {integer}, tenant_id TEXT, action TEXT NOT NULL, actor TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{{}}', created_at TEXT NOT NULL);
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
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS usage_idempotency ON usage_events(tenant_id,idempotency_key) WHERE idempotency_key <> ''")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS branches_port_unique ON branches(port)")
    c.commit()


def cipher() -> Fernet:
    if not CREDENTIAL_ENCRYPTION_KEY:
        raise RuntimeError("MOSAIC_CREDENTIAL_ENCRYPTION_KEY is required")
    return Fernet(CREDENTIAL_ENCRYPTION_KEY.encode())


CommandRunner = Callable[[list[str]], Any]


class BranchEngine(Protocol):
    def create_database(self, path: Path, password: str, port: int, host_id: str = "local") -> None: ...
    def clone(self, parent: Path, target: Path, *, parent_port: int | None = None, parent_password: str | None = None, target_port: int | None = None, parent_host_id: str = "local", target_host_id: str = "local") -> None: ...
    def destroy(self, path: Path) -> None: ...


class ZfsBranchEngine:
    def __init__(self, pool: str | None = None, runner: CommandRunner | None = None):
        self.pool = pool or os.getenv("MOSAIC_ZFS_POOL", "rpool/mosaic")
        self.run = runner or (lambda argv: subprocess.run(argv, check=True, capture_output=True, text=True))

    def _dataset(self, path: Path) -> str:
        try:
            relative = path.resolve().relative_to(BRANCH_ROOT.resolve())
        except ValueError:
            relative = Path(path.parent.name) / path.name
        return "/".join((self.pool, *relative.parts))

    def create_database(self, path: Path, password: str, port: int, host_id: str = "local"):
        self.run(["zfs", "create", "-p", "-o", f"mountpoint={path.resolve()}", self._dataset(path)])
        _initdb(path, password, port, self.run, host_id)

    def clone(self, parent: Path, target: Path, *, parent_port: int | None = None, parent_password: str | None = None, target_port: int | None = None, parent_host_id: str = "local", target_host_id: str = "local"):
        snap = f"{self._dataset(parent)}@branch-{target.name}"
        if parent_port:
            _checkpoint(parent_host_id, parent_port, parent_password)
        self.run(["zfs", "snapshot", snap])
        self.run(["zfs", "clone", "-o", f"mountpoint={target.resolve()}", snap, self._dataset(target)])
        if target_port is not None:
            _rewrite_postgres_config(target, target_port, target_host_id)

    def destroy(self, path: Path):
        self.run(["zfs", "destroy", "-r", self._dataset(path)])


class CopyBranchEngine:
    """CI engine: pg_basebackup is consistent; cp -a of a running PG dir is not."""
    def __init__(self, runner: CommandRunner | None = None):
        self.run = runner or (lambda argv: subprocess.run(argv, check=True))

    def create_database(self, path: Path, password: str, port: int, host_id: str = "local"):
        _initdb(path, password, port, self.run, host_id)

    def clone(self, parent: Path, target: Path, *, parent_port: int | None = None, parent_password: str | None = None, target_port: int | None = None, parent_host_id: str = "local", target_host_id: str = "local"):
        target.parent.mkdir(parents=True, exist_ok=True)
        if parent_port:
            _checkpoint(parent_host_id, parent_port, parent_password)
            argv = [pg_bin("pg_basebackup"), "-D", str(target), "-h", node_address(parent_host_id), "-p", str(parent_port), "-U", "postgres", "-Fp", "-X", "stream", "-R"]
            old_password = os.environ.get("PGPASSWORD")
            if parent_password:
                os.environ["PGPASSWORD"] = parent_password
            try:
                self.run(argv)
            finally:
                if old_password is None:
                    os.environ.pop("PGPASSWORD", None)
                else:
                    os.environ["PGPASSWORD"] = old_password
        else:
            shutil.copytree(parent, target)
        if target_port is not None:
            _rewrite_postgres_config(target, target_port, target_host_id)

    def destroy(self, path: Path):
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


def _rewrite_postgres_config(path: Path, port: int, host_id: str = "local"):
    config = path / "postgresql.conf"
    if not config.exists():
        return
    listen_address = node_address(host_id)
    lines = config.read_text().splitlines()
    settings = re.compile(r"^\s*(?:port|listen_addresses|unix_socket_directories)\s*=")
    retained = [line for line in lines if not settings.match(line)]
    retained.extend([
        f"port = {port}",
        f"listen_addresses = '{listen_address}'",
        f"unix_socket_directories = '{path.resolve()}'",
    ])
    config.write_text("\n".join(retained) + "\n")
    if len(node_ids()) > 1:
        addresses = node_private_addresses()
        if set(node_ids()) - set(addresses):
            raise RuntimeError("MOSAIC_NODE_PRIVATE_ADDRESSES must map every configured node for multi-host deployment")
        hba = path / "pg_hba.conf"
        hba_lines = hba.read_text().splitlines() if hba.exists() else []
        marker = "# mosaic-database peer access"
        hba_lines = [line for line in hba_lines if not line.startswith(marker)]
        hba_lines.append(marker)
        hba_lines.extend(f"host all postgres {address}/32 scram-sha-256" for address in addresses.values())
        hba.write_text("\n".join(hba_lines) + "\n")


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


class Supervisor:
    def allocate_port(self, c: Conn) -> int:
        used = {int(row["port"]) for row in c.execute("SELECT port FROM branches").fetchall()}
        port = PORT_MIN
        while port in used:
            port += 1
        return port

    def start(self, row, c: Conn):
        if row["status"] == "running" and alive(row["pid"]):
            return
        path = Path(row["path"])
        if not (path / "PG_VERSION").exists():
            raise RuntimeError(f"branch {row['id']} has no PostgreSQL cluster at {path}")
        if psycopg is None:
            raise RuntimeError("psycopg is required to supervise PostgreSQL branches")
        subprocess.run([pg_bin("pg_ctl"), "-D", str(path), "-o", f"-p {row['port']}", "-l", str(path / "postgres.log"), "-w", "start"], check=True, capture_output=True)
        if (path / "standby.signal").exists():
            subprocess.run([pg_bin("pg_ctl"), "-D", str(path), "promote", "-w"], check=True, capture_output=True)
        try:
            branch_password = cipher().decrypt(row["credential_encrypted"].encode()).decode()
        except InvalidToken as exc:
            raise RuntimeError(f"branch {row['id']} credentials cannot be decrypted") from exc
        passwords = [branch_password]
        if row["parent_id"]:
            parent = c.execute("SELECT credential_encrypted FROM branches WHERE id=?", (row["parent_id"],)).fetchone()
            if parent:
                try:
                    passwords.append(cipher().decrypt(parent["credential_encrypted"].encode()).decode())
                except InvalidToken as exc:
                    raise RuntimeError(f"parent credentials for branch {row['id']} cannot be decrypted") from exc
        for candidate in passwords:
            try:
                with psycopg.connect(host=node_address(row["host_id"]), port=row["port"], user="postgres", password=candidate, dbname="postgres", connect_timeout=5) as connection:
                    connection.execute(psycopg_sql.SQL("ALTER ROLE postgres PASSWORD {}").format(psycopg_sql.Literal(branch_password)))
                    connection.commit()
                break
            except Exception:
                continue
        else:
            raise RuntimeError(f"unable to set password for branch {row['id']}")
        pid = int((path / "postmaster.pid").read_text().splitlines()[0])
        c.execute("UPDATE branches SET status='running',pid=? WHERE id=?", (pid, row["id"]))
        c.commit()

    def stop(self, row, c: Conn):
        if alive(row["pid"]):
            subprocess.run([pg_bin("pg_ctl"), "-D", row["path"], "-m", "fast", "-w", "stop"], check=False, capture_output=True)
        c.execute("UPDATE branches SET status='stopped',pid=NULL WHERE id=?", (row["id"],))
        c.commit()

    def reap(self, c: Conn, idle_seconds: int | None = None) -> int:
        if idle_seconds is None:
            idle_seconds = int(os.getenv("MOSAIC_BRANCH_IDLE_SECONDS", str(IDLE_REAPER_SECONDS)))
        cutoff = time.time() - idle_seconds
        count = 0
        for row in c.execute("SELECT * FROM branches WHERE status='running'").fetchall():
            if datetime.fromisoformat(row["last_query_at"]).timestamp() < cutoff:
                self.stop(row, c)
                count += 1
        return count


class NodeAgent:
    def handle(self, operation: str, payload: dict):
        if operation == "provision":
            engine().create_database(
                Path(payload["path"]),
                payload["password"],
                int(payload["port"]),
                payload.get("host_id", current_node_id()),
            )
            return {"status": "provisioned"}
        if operation == "clone":
            engine().clone(
                Path(payload["parent"]),
                Path(payload["target"]),
                parent_port=payload.get("parent_port"),
                parent_password=payload.get("parent_password"),
                target_port=payload.get("target_port"),
                parent_host_id=payload.get("parent_host_id", current_node_id()),
                target_host_id=payload.get("target_host_id", current_node_id()),
            )
            return {"status": "cloned"}
        c = db()
        try:
            row = c.execute("SELECT * FROM branches WHERE id=?", (payload["branch_id"],)).fetchone()
            if not row:
                raise RuntimeError("branch not found on node agent")
            if operation == "start":
                supervisor.start(row, c)
                return {"status": "running"}
            if operation == "stop":
                supervisor.stop(row, c)
                return {"status": "stopped"}
            if operation == "inspect":
                return {"status": row["status"], "pid": row["pid"], "alive": alive(row["pid"])}
            if operation == "destroy":
                engine().destroy(Path(row["path"]))
                return {"status": "destroyed"}
            raise RuntimeError(f"unknown node operation {operation}")
        finally:
            c.close()


def current_node_id() -> str:
    return os.getenv("MOSAIC_NODE_ID", NODE_ID)


class NodeTransport:
    def __init__(self, agent: NodeAgent):
        self.agent = agent

    def call(self, node_id: str, operation: str, payload: dict):
        if len(node_ids()) == 1 or node_id == current_node_id():
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
            with urllib.request.urlopen(request, timeout=15) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, urllib.error.HTTPError) as exc:
            raise RuntimeError(f"node agent {node_id} unavailable: {exc}") from exc


supervisor = Supervisor()
node_agent = NodeAgent()
node_transport = NodeTransport(node_agent)
app = FastAPI(title="Mosaic Database", version="0.1.0")
_reaper_task: asyncio.Task | None = None
_branch_mutation_lock = threading.Lock()


async def _reaper_loop():
    while True:
        await asyncio.sleep(max(1, int(os.getenv("MOSAIC_BRANCH_REAPER_INTERVAL", "60"))))
        c = db()
        try:
            reap_branches(c)
        finally:
            c.close()


def reap_branches(c: Conn) -> int:
    cutoff = time.time() - int(os.getenv("MOSAIC_BRANCH_IDLE_SECONDS", str(IDLE_REAPER_SECONDS)))
    count = 0
    for row in c.execute("SELECT * FROM branches WHERE status='running'").fetchall():
        if datetime.fromisoformat(row["last_query_at"]).timestamp() >= cutoff:
            continue
        if row["host_id"] == current_node_id() or (len(node_ids()) == 1 and row["host_id"] == "local"):
            supervisor.stop(row, c)
        else:
            node_transport.call(row["host_id"], "stop", {"branch_id": row["id"]})
            c.execute("UPDATE branches SET status='stopped',pid=NULL WHERE id=?", (row["id"],))
            c.commit()
        count += 1
    return count


@app.on_event("startup")
async def startup():
    global _reaper_task
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
        BRANCH_ROOT.mkdir(parents=True, exist_ok=True)
    finally:
        c.close()
    _reaper_task = asyncio.create_task(_reaper_loop())


@app.on_event("shutdown")
async def shutdown():
    global _reaper_task
    if _reaper_task:
        _reaper_task.cancel()
        try:
            await _reaper_task
        except asyncio.CancelledError:
            pass
        _reaper_task = None


@app.middleware("http")
async def headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


def require_admin(x_admin_key: str | None = Header(default=None, alias="X-Admin-Key")):
    if not ADMIN_KEY or not secrets.compare_digest(x_admin_key or "", ADMIN_KEY):
        raise HTTPException(401, "admin authentication required")


def tenant_auth(tid: str, x_api_key: str | None = Header(default=None, alias="X-API-Key"), authorization: str | None = Header(default=None)):
    key = x_api_key or (authorization or "").removeprefix("Bearer ").strip()
    c = db()
    try:
        row = c.execute("SELECT * FROM tenants WHERE id=? AND status='active'", (tid,)).fetchone()
        if not row or not key or not secrets.compare_digest(row["api_key_hash"], digest(key)):
            raise HTTPException(401, "invalid tenant API key")
        check_rate_limit(tid)
        return row
    finally:
        c.close()


def check_rate_limit(tid: str):
    values = [x for x in _rate.get(tid, []) if x > time.time() - 60]
    if len(values) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(429, "rate limit exceeded")
    _rate[tid] = values + [time.time()]


class TenantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    plan: str = "shared"


class DatabaseCreate(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,48}$")


class BranchCreate(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,48}$")
    parent: str = "main"


class Query(BaseModel):
    sql: str = Field(min_length=1, max_length=100000)
    params: list[Any] = []
    branch: str = "main"


class Usage(BaseModel):
    kind: str
    quantity: int = Field(ge=0)
    unit: str
    idempotency_key: str = ""


def audit(c: Conn, tenant_id: str | None, action: str, details: dict):
    c.execute("INSERT INTO audit_log(tenant_id,action,actor,details,created_at) VALUES(?,?,?,?,?)", (tenant_id, action, "api", json.dumps(details), now()))


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
def internal_node(operation: str, payload: dict, x_node_token: str | None = Header(default=None, alias="X-Mosaic-Node-Token")):
    require_node_agent_token(x_node_token)
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
def mcp(payload: dict, response: Response, x_api_key: str | None = Header(default=None, alias="X-API-Key"), authorization: str | None = Header(default=None)):
    if len(json.dumps(payload)) > 1000000:
        raise HTTPException(413, "MCP payload too large")
    response.headers["MCP-Protocol-Version"] = MCP_PROTOCOL_VERSION
    if payload.get("method") == "initialize":
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "mosaic-database", "version": "0.1.0"}}}
    key = x_api_key or (authorization or "").removeprefix("Bearer ").strip()
    c = db()
    try:
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
        elif name == "create_branch":
            result = _create_branch(c, tenant["id"], args["database_id"], BranchCreate(name=args["name"], parent=args.get("parent", "main")), tenant)
        elif name == "list_branches":
            result = list_branches(tenant["id"], args["database_id"], tenant)
        else:
            raise HTTPException(400, "unknown MCP tool")
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"content": [{"type": "text", "text": json.dumps(result)}]}}
    finally:
        c.close()


@app.post("/v1/tenants", dependencies=[Depends(require_admin)])
def create_tenant(payload: TenantCreate):
    if payload.plan not in PLANS:
        raise HTTPException(400, "unknown plan")
    tid, key = token("ten_"), token("mdb_live_")
    c = db()
    try:
        c.execute("INSERT INTO tenants VALUES(?,?,?,?,?,?)", (tid, payload.name, payload.plan, digest(key), "active", now()))
        audit(c, tid, "tenant.created", {"plan": payload.plan})
        c.commit()
        return {"tenant_id": tid, "api_key": key, "plan": payload.plan}
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


@app.delete("/v1/tenants/{tid}/databases/{did}/branches/{bid}")
def delete_branch(tid: str, did: str, bid: str, tenant=Depends(tenant_auth)):
    c = db()
    try:
        database(c, tid, did)
        row = branch(c, did, bid)
        if row["name"] == "main":
            raise HTTPException(400, "main branch is protected")
        node_transport.call(row["host_id"], "stop", {"branch_id": row["id"]})
        node_transport.call(row["host_id"], "destroy", {"branch_id": row["id"]})
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
            node_transport.call(row["host_id"], "start", {"branch_id": row["id"]})
        except RuntimeError as exc:
            raise HTTPException(503, f"branch unavailable: {exc}") from exc
        if psycopg is None:
            raise HTTPException(503, "PostgreSQL driver unavailable")
        try:
            password = cipher().decrypt(row["credential_encrypted"].encode()).decode()
        except InvalidToken as exc:
            raise HTTPException(503, "branch credentials cannot be decrypted") from exc
        conn = psycopg.connect(host=node_address(row["host_id"]), port=row["port"], user="postgres", password=password, dbname="postgres", connect_timeout=5)
        try:
            conn.execute(f"SET statement_timeout = {PLANS[tenant['plan']]['statement_timeout_ms']}")
            cur = conn.execute(payload.sql, payload.params)
            max_rows = PLANS[tenant["plan"]]["max_rows"]
            rows = cur.fetchmany(max_rows + 1) if cur.description else []
            if len(rows) > max_rows:
                raise HTTPException(413, "row limit exceeded")
            result = {"rows": [list(x) for x in rows], "columns": [x.name for x in (cur.description or [])], "row_count": len(rows)}
            conn.commit()
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
