import os
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

os.environ["MOSAIC_ADMIN_KEY"] = "test-admin"
from app import main


@pytest.fixture
def client(tmp_path, monkeypatch):
    main.DB_PATH = tmp_path / "ledger.db"
    main.BRANCH_ROOT = tmp_path / "branches"
    main.CREDENTIAL_ENCRYPTION_KEY = Fernet.generate_key().decode()
    main.DATABASE_URL = ""
    main.DATABASE_URLS = []
    main._rate.clear()
    class FakeEngine:
        def create_database(self, path, password, port, host_id="local"): Path(path).mkdir(parents=True, exist_ok=True)
        def clone(self, parent, target, parent_port=None, parent_password=None, target_port=None, parent_host_id="local", target_host_id="local"): Path(target).mkdir(parents=True, exist_ok=True)
        def destroy(self, path): return None
    monkeypatch.setattr(main, "engine", lambda: FakeEngine())
    with TestClient(main.app) as test_client:
        yield test_client


def tenant(client, plan="shared"):
    response = client.post("/v1/tenants", headers={"X-Admin-Key": "test-admin"}, json={"name": "Acme", "plan": plan})
    assert response.status_code == 200
    return response.json()


def test_auth_limits_and_key_rotation(client):
    created = tenant(client)
    tid, key = created["tenant_id"], created["api_key"]
    assert key.startswith("mdb_live_") and tid.startswith("ten_")
    assert client.get(f"/v1/tenants/{tid}/usage", headers={"X-API-Key": "wrong"}).status_code == 401
    rotated = client.post(f"/v1/tenants/{tid}/api-key", headers={"X-API-Key": key}).json()["api_key"]
    assert client.get(f"/v1/tenants/{tid}/usage", headers={"X-API-Key": key}).status_code == 401
    assert client.get(f"/v1/tenants/{tid}/usage", headers={"X-API-Key": rotated}).status_code == 200


def test_revoke_key_does_not_revoke_tenant(client):
    created = tenant(client)
    tid, key = created["tenant_id"], created["api_key"]
    response = client.delete(f"/v1/tenants/{tid}/api-key", headers={"X-API-Key": key})
    assert response.json()["status"] == "key_revoked"
    c = main.db()
    try:
        row = c.execute("SELECT status,api_key_hash FROM tenants WHERE id=?", (tid,)).fetchone()
        assert (row["status"], row["api_key_hash"]) == ("active", "")
    finally:
        c.close()


def test_database_branch_lifecycle_and_main_protection(client):
    created = tenant(client)
    tid, key = created["tenant_id"], created["api_key"]
    database = client.post(f"/v1/tenants/{tid}/databases", headers={"X-API-Key": key}, json={"name": "events"}).json()
    did = database["id"]
    branch = client.post(f"/v1/tenants/{tid}/databases/{did}/branches", headers={"X-API-Key": key}, json={"name": "feature"}).json()
    assert branch["id"].startswith("br_")
    assert len(client.get(f"/v1/tenants/{tid}/databases/{did}/branches", headers={"X-API-Key": key}).json()["branches"]) == 2
    assert client.delete(f"/v1/tenants/{tid}/databases/{did}/branches/{database['main_branch']['id']}", headers={"X-API-Key": key}).status_code == 400
    assert client.delete(f"/v1/tenants/{tid}/databases/{did}/branches/{branch['id']}", headers={"X-API-Key": key}).status_code == 200


def test_cross_tenant_branch_delete_is_rejected(client):
    first, second = tenant(client), tenant(client)
    first_db = client.post(
        f"/v1/tenants/{first['tenant_id']}/databases",
        headers={"X-API-Key": first["api_key"]},
        json={"name": "firstdb"},
    ).json()
    branch = client.post(
        f"/v1/tenants/{first['tenant_id']}/databases/{first_db['id']}/branches",
        headers={"X-API-Key": first["api_key"]},
        json={"name": "feature"},
    ).json()
    response = client.delete(
        f"/v1/tenants/{second['tenant_id']}/databases/{first_db['id']}/branches/{branch['id']}",
        headers={"X-API-Key": second["api_key"]},
    )
    assert response.status_code == 404


def test_mcp_rate_limit_matches_rest(client, monkeypatch):
    created = tenant(client)
    monkeypatch.setattr(main, "RATE_LIMIT_REQUESTS", 1)
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    headers = {"X-API-Key": created["api_key"]}
    assert client.post("/mcp", headers=headers, json=payload).status_code == 200
    assert client.post("/mcp", headers=headers, json=payload).status_code == 429


def test_branch_ports_are_unique(client):
    created = tenant(client)
    database = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "ports"},
    ).json()
    c = main.db()
    try:
        main_port = c.execute("SELECT port FROM branches WHERE database_id=?", (database["id"],)).fetchone()["port"]
        with pytest.raises(Exception):
            c.execute(
                "INSERT INTO branches VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                ("br_duplicate", database["id"], "other", None, "/tmp/other", main_port, None, "stopped", "x", main.now(), main.now(), "local"),
            )
    finally:
        c.close()


@pytest.mark.parametrize("sql", [
    "CREATE TABLE x (id int)",
    "select pg_read_file('/etc/passwd')",
    "select pg_read_file/**/('/etc/passwd')",
    "select dblink_connect('host=evil')",
    "COPY x TO PROGRAM 'id'",
    "select 1; select 2",
])
def test_sql_guardrails(sql):
    assert main.forbidden_sql(sql)


def test_sql_comments_and_literals_do_not_trigger_false_positive():
    assert main.forbidden_sql("select 1 -- pg_read_file('/etc/passwd')\n") is None
    assert main.forbidden_sql("select '-- pg_read_file(/etc/passwd)'") is None


def test_zfs_engine_exact_argv(tmp_path):
    calls = []
    engine = main.ZfsBranchEngine("tank/mosaic", calls.append)
    parent, child = tmp_path / "db", tmp_path / "feature"
    engine.create_database(parent, "secret", 55432)
    engine.clone(parent, child, target_port=55433)
    engine.destroy(child)
    assert calls[0] == ["zfs", "create", "-p", "-o", f"mountpoint={parent.resolve()}", f"tank/mosaic/{tmp_path.name}/db"]
    assert calls[1][0].endswith("/initdb")
    assert calls[1][1:6] == ["-D", str(parent), "-U", "postgres", "--auth=scram-sha-256"]
    assert calls[1][6] == "--pwfile"
    assert calls[2:] == [
        [ "zfs", "snapshot", f"tank/mosaic/{tmp_path.name}/db@branch-{child.name}"],
        ["zfs", "clone", "-o", f"mountpoint={child.resolve()}", f"tank/mosaic/{tmp_path.name}/db@branch-{child.name}", f"tank/mosaic/{tmp_path.name}/{child.name}"],
        ["zfs", "destroy", "-r", f"tank/mosaic/{tmp_path.name}/{child.name}"],
    ]


def test_clone_rewrites_postgres_port_and_socket(tmp_path):
    config = tmp_path / "postgresql.conf"
    config.write_text("port = 55432\nlisten_addresses = '*'\nunix_socket_directories = '/old'\nshared_buffers = '128MB'\n")
    main._rewrite_postgres_config(tmp_path, 55433)
    text = config.read_text()
    assert "port = 55433" in text
    assert "listen_addresses = '127.0.0.1'" in text
    assert f"unix_socket_directories = '{tmp_path.resolve()}'" in text
    assert "port = 55432" not in text
    assert "unix_socket_directories = '/old'" not in text
    assert "shared_buffers = '128MB'" in text


def test_reaper_stop_cycle(tmp_path, monkeypatch):
    main.DB_PATH = tmp_path / "reaper.db"
    c = main.db()
    main.initialize_schema(c)
    c.execute("INSERT INTO tenants VALUES(?,?,?,?,?,?)", ("ten_x", "x", "shared", "h", "active", main.now()))
    c.execute("INSERT INTO databases VALUES(?,?,?,?,?,?)", ("db_x", "ten_x", "x", str(tmp_path), "ready", main.now()))
    old = "2000-01-01T00:00:00+00:00"
    c.execute("INSERT INTO branches VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", ("br_x", "db_x", "main", None, str(tmp_path), 55432, 999999, "running", "x", old, old, "local"))
    c.commit()
    stopped = main.Supervisor().reap(c, idle_seconds=1)
    assert stopped == 1
    assert c.execute("SELECT status,pid FROM branches").fetchone()["status"] == "stopped"
    c.close()


def test_placement_is_deterministic(monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "sv1,sv2,sv3")
    first = main.placement_node("db_fixed")
    assert first == main.placement_node("db_fixed")
    assert first in {"sv1", "sv2", "sv3"}


def test_unknown_branch_host_does_not_resolve_to_loopback(monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local")
    with pytest.raises(RuntimeError, match="unknown database node"):
        main.node_address("mch-sv2")


def test_hba_managed_block_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "sv1,sv2")
    monkeypatch.setenv("MOSAIC_NODE_PRIVATE_ADDRESSES", "sv1=10.0.0.1,sv2=10.0.0.2")
    (tmp_path / "postgresql.conf").write_text("")
    hba = tmp_path / "pg_hba.conf"
    hba.write_text("local all all trust\n")
    main._rewrite_postgres_config(tmp_path, 55432, "sv1")
    main._rewrite_postgres_config(tmp_path, 55432, "sv1")
    text = hba.read_text()
    assert text.count("# BEGIN MOSAIC DATABASE PEERS") == 1
    assert text.count("# END MOSAIC DATABASE PEERS") == 1
    assert text.count("host all postgres 10.0.0.1/32 scram-sha-256") == 1
    assert text.count("host all postgres 10.0.0.2/32 scram-sha-256") == 1


def test_existing_ledger_migrates_branch_host(tmp_path):
    path = tmp_path / "legacy.db"
    raw = main.sqlite3.connect(path)
    raw.execute("CREATE TABLE branches (id TEXT PRIMARY KEY, database_id TEXT NOT NULL, name TEXT NOT NULL, parent_id TEXT, path TEXT NOT NULL, port INTEGER NOT NULL, pid INTEGER, status TEXT NOT NULL, credential_encrypted TEXT NOT NULL, last_query_at TEXT NOT NULL, created_at TEXT NOT NULL)")
    raw.commit()
    raw.close()
    main.DB_PATH = path
    c = main.db()
    try:
        main.initialize_schema(c)
        columns = [row["name"] for row in c.execute("PRAGMA table_info(branches)").fetchall()]
        assert "host_id" in columns
        c.execute("INSERT INTO branches VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", ("br_legacy", "db", "main", None, "/tmp/main", 55432, None, "stopped", "x", main.now(), main.now(), "local"))
        assert c.execute("SELECT host_id FROM branches WHERE id=?", ("br_legacy",)).fetchone()["host_id"] == "local"
    finally:
        c.close()


def test_query_routes_to_non_local_branch(client, monkeypatch):
    created = tenant(client)
    database = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "remote"},
    ).json()
    c = main.db()
    c.execute("UPDATE branches SET host_id='sv2' WHERE database_id=?", (database["id"],))
    c.commit()
    c.close()
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local,sv2=http://agent.invalid")
    monkeypatch.setenv("MOSAIC_NODE_PRIVATE_ADDRESSES", "local=10.0.0.1,sv2=10.0.0.2")
    seen = []

    class FakeTransport:
        def call(self, node_id, operation, payload):
            assert node_id == "sv2"
            assert operation == "start"
            return {"status": "running", "pid": 1234}

    class Description:
        name = "answer"

    class Cursor:
        description = [Description()]
        def fetchmany(self, size):
            return [(1,)]

    class Connection:
        def execute(self, sql, params=()):
            if sql.startswith("SET statement_timeout"):
                return self
            return Cursor()
        def commit(self):
            return None
        def close(self):
            return None

    class FakePsycopg:
        def connect(self, **kwargs):
            seen.append(kwargs["host"])
            return Connection()

    monkeypatch.setattr(main, "node_transport", FakeTransport())
    monkeypatch.setattr(main, "psycopg", FakePsycopg())
    response = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/query",
        headers={"X-API-Key": created["api_key"]},
        json={"sql": "select 1"},
    )
    assert response.status_code == 200
    assert seen == ["10.0.0.2"]
