import asyncio
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


def test_local_node_private_address_is_used_for_single_explicit_node(tmp_path, monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local")
    monkeypatch.setenv("MOSAIC_NODE_PRIVATE_ADDRESSES", "local=10.0.0.1")
    (tmp_path / "postgresql.conf").write_text("")
    hba = tmp_path / "pg_hba.conf"
    hba.write_text("local all all trust\n")
    main._rewrite_postgres_config(tmp_path, 55432, "local")
    assert "listen_addresses = '10.0.0.1'" in (tmp_path / "postgresql.conf").read_text()
    assert "host all postgres 10.0.0.1/32 scram-sha-256" in hba.read_text()


def test_node_agent_rejects_paths_outside_branch_root(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    with pytest.raises(RuntimeError, match="MOSAIC_BRANCH_ROOT"):
        main.NodeAgent().handle("destroy", {"path": str(tmp_path / "outside")})


def test_transport_rejects_unknown_node_for_single_host(monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local")
    transport = main.NodeTransport(main.NodeAgent())
    with pytest.raises(RuntimeError, match="unknown database node"):
        transport.call("sv2", "stop", {"path": "/tmp/nope", "pid": None})
    with pytest.raises(RuntimeError, match="unknown database node"):
        transport.call("sv2", "destroy", {"path": "/tmp/nope"})


def test_reaper_skips_unreachable_host_and_continues(tmp_path, monkeypatch):
    main.DB_PATH = tmp_path / "reaper-unreachable.db"
    c = main.db()
    main.initialize_schema(c)
    c.execute("INSERT INTO tenants VALUES(?,?,?,?,?,?)", ("ten_r", "r", "shared", "h", "active", main.now()))
    c.execute("INSERT INTO databases VALUES(?,?,?,?,?,?)", ("db_r", "ten_r", "r", str(tmp_path), "ready", main.now()))
    old = "2000-01-01T00:00:00+00:00"
    for bid, host, port in (("br_bad", "sv2", 55432), ("br_good", "local", 55433)):
        c.execute(
            "INSERT INTO branches VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (bid, "db_r", bid, None, str(tmp_path / bid), port, 123, "running", "x", old, old, host),
        )
    c.commit()

    class FakeTransport:
        def call(self, host_id, operation, payload):
            if host_id == "sv2":
                raise RuntimeError("node unavailable")
            return {"status": "stopped", "pid": None}

    monkeypatch.setattr(main, "node_transport", FakeTransport())
    assert main.reap_branches(c) == 1
    assert c.execute("SELECT status FROM branches WHERE id='br_bad'").fetchone()["status"] == "running"
    assert c.execute("SELECT status FROM branches WHERE id='br_good'").fetchone()["status"] == "stopped"
    c.close()


def test_reaper_loop_survives_unexpected_sweep_error(tmp_path, monkeypatch):
    main.DB_PATH = tmp_path / "reaper-loop.db"
    c = main.db()
    main.initialize_schema(c)
    c.close()
    calls = {"sleep": 0, "reap": 0}

    async def fake_sleep(_):
        calls["sleep"] += 1
        if calls["sleep"] > 1:
            raise asyncio.CancelledError

    def fake_reap(connection):
        calls["reap"] += 1
        raise RuntimeError("unexpected sweep error")

    monkeypatch.setattr(main.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(main, "reap_branches", fake_reap)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(main._reaper_loop())
    assert calls["reap"] == 1


def test_reaper_loop_survives_ledger_connection_error(monkeypatch):
    calls = {"sleep": 0, "db": 0, "reap": 0}

    async def fake_sleep(_):
        calls["sleep"] += 1
        if calls["sleep"] > 2:
            raise asyncio.CancelledError

    class Connection:
        def close(self):
            return None

    def fake_db():
        calls["db"] += 1
        if calls["db"] == 1:
            raise RuntimeError("ledger unavailable")
        return Connection()

    def fake_reap(connection):
        calls["reap"] += 1

    monkeypatch.setattr(main.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(main, "db", fake_db)
    monkeypatch.setattr(main, "reap_branches", fake_reap)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(main._reaper_loop())
    assert calls["db"] == 2
    assert calls["reap"] == 1


def test_reaper_loop_invalid_interval_still_yields(monkeypatch):
    monkeypatch.setenv("MOSAIC_BRANCH_REAPER_INTERVAL", "60s")
    calls = {"sleep": 0}

    async def fake_sleep(_):
        calls["sleep"] += 1
        if calls["sleep"] > 1:
            raise asyncio.CancelledError

    def unavailable_db():
        raise RuntimeError("ledger unavailable")

    monkeypatch.setattr(main.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(main, "db", unavailable_db)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(main._reaper_loop())
    assert calls["sleep"] == 2


def test_standby_build_argv(tmp_path, monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local,sv2")
    monkeypatch.setenv("MOSAIC_NODE_PRIVATE_ADDRESSES", "local=10.0.0.1,sv2=10.0.0.2")
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    target = root / "standby"
    target.mkdir()
    (target / "postgresql.conf").write_text("")
    (target / "pg_hba.conf").write_text("")
    calls = []
    main.NodeAgent(calls.append).handle("build_standby", {
        "target_path": str(target),
        "target_port": 55433,
        "target_host_id": "sv2",
        "primary_address": "10.0.0.1",
        "primary_port": 55432,
        "replication_user": "mosaic_repl_db",
        "replication_password": "secret",
        "replication_slot": "mosaic_db_sv2",
    })
    assert calls[0] == [
        main.pg_bin("pg_basebackup"), "-D", str(target), "-h", "10.0.0.1",
        "-p", "55432", "-U", "mosaic_repl_db", "-Fp", "-X", "stream", "-R",
        "-S", "mosaic_db_sv2",
    ]
    assert calls[1] == [
        main.pg_bin("pg_ctl"), "-D", str(target), "-l",
        str(target / "postgres.log"), "-w", "start",
    ]


def test_reaper_ignores_standbys(tmp_path, monkeypatch):
    main.DB_PATH = tmp_path / "reaper-replica.db"
    c = main.db()
    main.initialize_schema(c)
    c.execute("INSERT INTO tenants VALUES(?,?,?,?,?,?)", ("ten_r", "r", "shared", "h", "active", main.now()))
    c.execute("INSERT INTO databases VALUES(?,?,?,?,?,?)", ("db_r", "ten_r", "r", str(tmp_path), "ready", main.now()))
    old = "2000-01-01T00:00:00+00:00"
    c.execute("INSERT INTO branches VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", ("br_r", "db_r", "main", None, str(tmp_path / "main"), 55432, 123, "running", "x", old, old, "local"))
    c.execute(
        "INSERT INTO replicas(id,database_id,primary_branch_id,host_id,path,port,status,lag_bytes,lag_sampled_at,created_at,slot_name) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("rep_r", "db_r", "br_r", "sv2", str(tmp_path / "standby"), 55433, "ready", 99, old, old, "slot_r"),
    )
    c.commit()
    calls = []

    class FakeTransport:
        def call(self, host_id, operation, payload):
            calls.append((host_id, operation, payload))
            return {"status": "stopped", "pid": None}

    monkeypatch.setattr(main, "node_transport", FakeTransport())
    assert main.reap_branches(c) == 1
    assert len(calls) == 1 and calls[0][1] == "stop"
    assert c.execute("SELECT status FROM replicas").fetchone()["status"] == "ready"
    c.close()


def test_replica_lag_surfaces_through_api(client, monkeypatch):
    created = tenant(client)
    database = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "lag"},
    ).json()
    c = main.db()
    main_row = c.execute("SELECT * FROM branches WHERE database_id=?", (database["id"],)).fetchone()
    c.execute("UPDATE branches SET host_id='local' WHERE id=?", (main_row["id"],))
    c.execute(
        "INSERT INTO replication_credentials VALUES(?,?,?,?)",
        (database["id"], "mosaic_repl_lag", main.cipher().encrypt(b"repl").decode(), main.now()),
    )
    c.execute(
        "INSERT INTO replicas(id,database_id,primary_branch_id,host_id,path,port,status,lag_bytes,lag_sampled_at,created_at,slot_name) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("rep_lag", database["id"], main_row["id"], "sv2", "/standby", 55433, "ready", None, None, main.now(), "slot_lag"),
    )
    c.commit()
    c.close()
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local,sv2")
    monkeypatch.setenv("MOSAIC_NODE_PRIVATE_ADDRESSES", "local=10.0.0.1,sv2=10.0.0.2")

    class FakeTransport:
        def call(self, host_id, operation, payload):
            assert operation == "inspect_replication"
            return {"sampled_at": "2025-01-01T00:00:00+00:00", "replicas": [{"client_addr": "10.0.0.2", "lag_bytes": 42}]}

    monkeypatch.setattr(main, "node_transport", FakeTransport())
    response = client.get(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/replicas",
        headers={"X-API-Key": created["api_key"]},
    )
    assert response.status_code == 200
    assert response.json()["replicas"][0]["lag_bytes"] == 42
    assert response.json()["lag_unit"] == "bytes behind primary WAL replay position"


def test_plaintext_remote_transport_requires_opt_out(monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local,sv2=http://10.0.0.2:8000")
    monkeypatch.setattr(main, "ALLOW_PLAINTEXT_NODE_AGENT", False)
    with pytest.raises(RuntimeError, match="plaintext node-agent transport"):
        main.NodeTransport(main.NodeAgent()).call("sv2", "inspect", {})


def test_peer_down_replica_is_retryable_without_blocking_database(client, monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local,sv2,sv3")
    monkeypatch.setenv(
        "MOSAIC_NODE_PRIVATE_ADDRESSES",
        "local=10.0.0.1,sv2=10.0.0.2,sv3=10.0.0.3",
    )
    created = tenant(client)

    class FakeTransport:
        def call(self, host_id, operation, payload):
            if operation == "provision":
                return {"status": "provisioned"}
            if operation == "prepare_primary":
                return {"status": "running", "pid": 123}
            raise RuntimeError("peer unavailable")

    monkeypatch.setattr(main, "node_transport", FakeTransport())
    response = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "degraded"},
    )
    assert response.status_code == 200
    database_id = response.json()["id"]
    c = main.db()
    rows = c.execute(
        "SELECT status,last_error FROM replicas WHERE database_id=?",
        (database_id,),
    ).fetchall()
    assert rows and all(row["status"] == "pending" for row in rows)
    c.close()
    main.reconcile_replicas(main.db())
    c = main.db()
    rows = c.execute(
        "SELECT status,last_error FROM replicas WHERE database_id=?",
        (database_id,),
    ).fetchall()
    assert rows and all(row["status"] == "retryable" for row in rows)
    assert all(row["last_error"] == "peer unavailable" for row in rows)
    assert c.execute("SELECT status FROM databases WHERE id=?", (database_id,)).fetchone()["status"] == "ready"
    c.close()


def test_replica_reconciliation_isolated_per_database(client, monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local,sv2,sv3")
    monkeypatch.setenv(
        "MOSAIC_NODE_PRIVATE_ADDRESSES",
        "local=10.0.0.1,sv2=10.0.0.2,sv3=10.0.0.3",
    )
    created = tenant(client)
    calls = []

    class FakeTransport:
        def call(self, host_id, operation, payload):
            if operation == "provision":
                return {"status": "provisioned"}
            if operation == "prepare_primary":
                calls.append(("prepare", payload["path"], payload["replication_user"], payload["replication_password"]))
                return {"status": "running", "pid": 123}
            if operation == "build_standby":
                calls.append(("build", payload["target_path"], payload["replication_user"], payload["replication_password"]))
                return {"status": "ready"}
            raise AssertionError(operation)

    monkeypatch.setattr(main, "node_transport", FakeTransport())
    databases = []
    for name in ("first", "second"):
        response = client.post(
            f"/v1/tenants/{created['tenant_id']}/databases",
            headers={"X-API-Key": created["api_key"]},
            json={"name": name},
        )
        assert response.status_code == 200
        databases.append(response.json()["id"])
    c = main.db()
    main.reconcile_replicas(c)
    prepared = {
        path: (username, password)
        for kind, path, username, password in calls
        if kind == "prepare"
    }
    builds = [
        (path, username, password)
        for kind, path, username, password in calls
        if kind == "build"
    ]
    assert len(prepared) == 2
    assert len(builds) == 4
    for path, username, password in builds:
        primary_path = str(Path(path).parents[1] / "main")
        assert (username, password) == prepared[primary_path]
    assert all(
        row["status"] == "ready"
        for row in c.execute("SELECT status FROM replicas").fetchall()
    )
    c.close()


def test_replication_loop_survives_reconciliation_error(tmp_path, monkeypatch):
    main.DB_PATH = tmp_path / "replication-loop.db"
    c = main.db()
    main.initialize_schema(c)
    c.close()
    calls = {"sleep": 0, "reconcile": 0}

    async def fake_sleep(_):
        calls["sleep"] += 1
        if calls["sleep"] > 1:
            raise asyncio.CancelledError

    def fake_reconcile(connection):
        calls["reconcile"] += 1
        raise RuntimeError("peer unavailable")

    monkeypatch.setattr(main.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(main, "reconcile_replicas", fake_reconcile)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(main._replication_loop())
    assert calls["reconcile"] == 1


def test_repeated_primary_preparation_is_idempotent(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    primary = root / "primary"
    primary.mkdir()
    config = primary / "postgresql.conf"
    config.write_text("listen_addresses = '127.0.0.1'\n")
    calls = []

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, query, params=None):
            calls.append(str(query))
            if "FROM pg_roles" in str(query):
                return type("Result", (), {"fetchone": lambda self: {"?column?": 1}})()
            return self

        def fetchall(self):
            return []

        def commit(self):
            return None

    class FakePsycopg:
        def connect(self, **kwargs):
            return FakeConnection()

    monkeypatch.setattr(main, "psycopg", FakePsycopg())
    monkeypatch.setattr(main.supervisor, "start_local", lambda payload: {"status": "running", "pid": 123})
    monkeypatch.setattr(main, "alive", lambda pid: False)
    agent = main.NodeAgent(lambda argv: calls.append(" ".join(argv)))
    payload = {
        "path": str(primary),
        "port": 55432,
        "host_id": "local",
        "branch_id": "br",
        "pid": None,
        "status": "stopped",
        "postgres_password": "postgres",
        "replication_user": "mosaic_repl",
        "replication_password": "secret",
        "replication_addresses": [],
        "replication_slots": [],
    }
    agent.handle("prepare_primary", payload)
    agent.handle("prepare_primary", payload)
    assert sum("ALTER ROLE" in query for query in calls) == 2
    assert not any("CREATE ROLE" in query for query in calls)


def test_failed_lag_sample_is_visible(client, monkeypatch):
    created = tenant(client)
    database = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "lag-failure"},
    ).json()
    c = main.db()
    main_row = c.execute("SELECT * FROM branches WHERE database_id=?", (database["id"],)).fetchone()
    c.execute(
        "INSERT INTO replication_credentials VALUES(?,?,?,?)",
        (database["id"], "mosaic_repl_lag_failure", main.cipher().encrypt(b"repl").decode(), main.now()),
    )
    c.execute(
        "INSERT INTO replicas(id,database_id,primary_branch_id,host_id,path,port,status,lag_bytes,lag_sampled_at,created_at,slot_name) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("rep_lag_failure", database["id"], main_row["id"], "sv2", "/standby", 55433, "ready", 0, main.now(), main.now(), "slot_lag_failure"),
    )
    c.commit()
    c.close()

    class FailedTransport:
        def call(self, *args, **kwargs):
            raise RuntimeError("primary unavailable")

    monkeypatch.setattr(main, "node_transport", FailedTransport())
    response = client.get(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/replicas",
        headers={"X-API-Key": created["api_key"]},
    )
    assert response.status_code == 200
    assert response.json()["lag_sample_error"] == "replication lag sampling failed"


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
