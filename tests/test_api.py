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
        def create_database(self, path): Path(path).mkdir(parents=True, exist_ok=True)
        def clone(self, parent, target, parent_port=None): Path(target).mkdir(parents=True, exist_ok=True)
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


@pytest.mark.parametrize("sql", [
    "CREATE TABLE x (id int)",
    "select pg_read_file('/etc/passwd')",
    "select dblink_connect('host=evil')",
    "COPY x TO PROGRAM 'id'",
    "select 1; select 2",
])
def test_sql_guardrails(sql):
    assert main.forbidden_sql(sql)


def test_zfs_engine_exact_argv():
    calls = []
    engine = main.ZfsBranchEngine("tank/mosaic", calls.append)
    engine.create_database(Path("/srv/db"))
    engine.clone(Path("/srv/db"), Path("/srv/feature"))
    engine.destroy(Path("/srv/feature"))
    assert calls == [
        ["zfs", "create", "-p", "tank/mosaic/db"],
        ["zfs", "snapshot", "tank/mosaic/db@branch-feature"],
        ["zfs", "clone", "tank/mosaic/db@branch-feature", "tank/mosaic/feature"],
        ["zfs", "destroy", "-r", "tank/mosaic/feature"],
    ]


def test_reaper_stop_cycle(tmp_path, monkeypatch):
    main.DB_PATH = tmp_path / "reaper.db"
    c = main.db()
    main.initialize_schema(c)
    c.execute("INSERT INTO tenants VALUES(?,?,?,?,?,?)", ("ten_x", "x", "shared", "h", "active", main.now()))
    c.execute("INSERT INTO databases VALUES(?,?,?,?,?,?)", ("db_x", "ten_x", "x", str(tmp_path), "ready", main.now()))
    old = "2000-01-01T00:00:00+00:00"
    c.execute("INSERT INTO branches VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("br_x", "db_x", "main", None, str(tmp_path), 55432, 999999, "running", "x", old, old))
    c.commit()
    stopped = main.Supervisor().reap(c, idle_seconds=1)
    assert stopped == 1
    assert c.execute("SELECT status,pid FROM branches").fetchone()[0] == "stopped"
    c.close()
