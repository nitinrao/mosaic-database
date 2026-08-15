"""Drive the Mosaic Database control plane against local PostgreSQL clusters."""

import os
import shutil
import sys
import tempfile
from pathlib import Path

import psycopg
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    missing = [
        name for name in ("initdb", "pg_ctl", "pg_basebackup")
        if shutil.which(name) is None
        and not list(Path("/usr/lib/postgresql").glob(f"*/bin/{name}"))
    ]
    if missing:
        print("SKIP: PostgreSQL binaries unavailable: " + ", ".join(missing))
        return

    os.environ["MOSAIC_ADMIN_KEY"] = "e2e-admin"
    os.environ["MOSAIC_BRANCH_ENGINE"] = "copy"
    os.environ["MOSAIC_DB_PATH"] = str(Path(tempfile.mkdtemp(prefix="mosaic-db-ledger-")) / "ledger.db")
    os.environ["MOSAIC_BRANCH_ROOT"] = tempfile.mkdtemp(prefix="mosaic-db-data-")
    os.environ["MOSAIC_POSTGRES_PORT_MIN"] = "57432"

    from app import main as service

    service.DB_PATH = Path(os.environ["MOSAIC_DB_PATH"])
    service.BRANCH_ROOT = Path(os.environ["MOSAIC_BRANCH_ROOT"])
    service.BRANCH_ENGINE_NAME = "copy"
    service.PORT_MIN = 57432
    service.CREDENTIAL_ENCRYPTION_KEY = service.Fernet.generate_key().decode()

    with TestClient(service.app) as client:
        print("phase: tenant")
        tenant = client.post(
            "/v1/tenants",
            headers={"X-Admin-Key": "e2e-admin"},
            json={"name": "E2E"},
        ).json()
        auth = {"X-API-Key": tenant["api_key"]}
        tid = tenant["tenant_id"]
        database = client.post(
            f"/v1/tenants/{tid}/databases",
            headers=auth,
            json={"name": "events"},
        ).json()
        print("phase: database")
        did = database["id"]
        main_branch = database["main_branch"]
        branches = client.get(
            f"/v1/tenants/{tid}/databases/{did}/branches",
            headers=auth,
        ).json()["branches"]
        main_port = next(row["port"] for row in branches if row["name"] == "main")
        ledger = service.db()
        try:
            main_row = ledger.execute("SELECT * FROM branches WHERE name='main' AND database_id=?", (did,)).fetchone()
            service.supervisor.start(main_row, ledger)
        finally:
            ledger.close()
        print("phase: main-started")

        with psycopg.connect(
            host="127.0.0.1",
            port=main_port,
            user="postgres",
            password=main_branch["password"],
            dbname="postgres",
            connect_timeout=5,
        ) as conn:
            conn.execute("CREATE TABLE events (side text, value integer)")
            conn.commit()
        query_url = f"/v1/tenants/{tid}/databases/{did}/query"
        client.post(
            query_url,
            headers=auth,
            json={"sql": "INSERT INTO events VALUES (%s, %s)", "params": ["main", 1]},
        ).raise_for_status()
        print("phase: main-write")

        branch = client.post(
            f"/v1/tenants/{tid}/databases/{did}/branches",
            headers=auth,
            json={"name": "feature"},
        ).json()
        print("phase: branch-created")
        client.post(
            query_url,
            headers=auth,
            json={
                "sql": "INSERT INTO events VALUES (%s, %s)",
                "params": ["branch", 2],
                "branch": "feature",
            },
        ).raise_for_status()
        print("phase: branch-write")
        main_rows = client.post(
            query_url,
            headers=auth,
            json={"sql": "SELECT side,value FROM events ORDER BY value"},
        ).json()["rows"]
        branch_rows = client.post(
            query_url,
            headers=auth,
            json={"sql": "SELECT side,value FROM events ORDER BY value", "branch": "feature"},
        ).json()["rows"]
        assert main_rows == [["main", 1]]
        assert branch_rows == [["main", 1], ["branch", 2]]
        print("phase: isolated")

        client.post(
            query_url,
            headers=auth,
            json={"sql": "INSERT INTO events VALUES (%s, %s)", "params": ["main", 3]},
        ).raise_for_status()
        branch_rows = client.post(
            query_url,
            headers=auth,
            json={"sql": "SELECT side,value FROM events ORDER BY value", "branch": "feature"},
        ).json()["rows"]
        assert branch_rows == [["main", 1], ["branch", 2]]
        print("phase: bidirectional-isolated")

        ledger = service.db()
        try:
            service.supervisor.reap(ledger, idle_seconds=-1)
        finally:
            ledger.close()
        print("phase: reaped")
        restarted = client.post(
            query_url,
            headers=auth,
            json={"sql": "SELECT side,value FROM events ORDER BY value", "branch": "feature"},
        ).json()["rows"]
        assert restarted == [["main", 1], ["branch", 2]]
        print("phase: restarted")

        assert client.delete(
            f"/v1/tenants/{tid}/databases/{did}/branches/{branch['id']}",
            headers=auth,
        ).status_code == 200
        assert client.delete(
            f"/v1/tenants/{tid}/databases/{did}/branches/{main_branch['id']}",
            headers=auth,
        ).status_code == 400
        print(f"e2e ok: main={main_rows} branch={restarted} reaper=stopped-and-restarted")


if __name__ == "__main__":
    main()
