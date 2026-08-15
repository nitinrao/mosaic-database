import asyncio
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
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
    main._rate_last_sweep = 0.0
    main._mosaic_identity_cache.clear()
    class FakeEngine:
        def create_database(self, path, password, port, host_id="local"): Path(path).mkdir(parents=True, exist_ok=True)
        def clone(self, parent, target, parent_port=None, parent_password=None, target_port=None, parent_host_id="local", target_host_id="local"): Path(target).mkdir(parents=True, exist_ok=True)
        def destroy(self, path): return None
    monkeypatch.setattr(main, "engine", lambda: FakeEngine())
    with TestClient(main.app, client=("127.0.0.1", 12345)) as test_client:
        yield test_client


def tenant(client, plan="shared"):
    response = client.post("/v1/tenants", headers={"X-Admin-Key": "test-admin"}, json={"name": "Acme", "plan": plan})
    assert response.status_code == 200
    return response.json()


def test_public_signup_authenticates_and_refuses_existing_email(client, monkeypatch):
    monkeypatch.setattr(main, "MOSAIC_PUBLIC_ENDPOINT", "https://database-api.test")
    first = client.post(
        "/v1/public/signup",
        json={"email": "Ops@Example.com", "tenant_name": "Ops Database", "key_name": "primary"},
    )
    assert first.status_code == 200
    body = first.json()
    assert body["status"] == "created"
    assert body["plan"] == "shared"
    assert body["token_prefix"] == body["api_key"][:12]
    assert body["quickstart"]["endpoint"] == "https://database-api.test"
    assert "/databases/$DB_ID/query" in body["quickstart"]["command"]
    tenant_id, old_key = body["tenant_id"], body["api_key"]
    assert client.get(
        f"/v1/tenants/{tenant_id}/usage",
        headers={"X-API-Key": old_key},
    ).status_code == 200

    c = main.db()
    try:
        before = c.execute(
            "SELECT api_key_hash,name,status FROM tenants WHERE id=?",
            (tenant_id,),
        ).fetchone()
        before_signup = c.execute(
            "SELECT tenant_name,last_key_created_at,updated_at FROM public_signups WHERE email=?",
            ("ops@example.com",),
        ).fetchone()
    finally:
        c.close()

    second = client.post(
        "/v1/public/signup",
        json={"email": "ops@example.com", "tenant_name": "Ops Database"},
    )
    assert second.status_code == 409
    assert "already exists" in second.json()["detail"]
    assert client.get(
        f"/v1/tenants/{tenant_id}/usage",
        headers={"X-API-Key": old_key},
    ).status_code == 200
    c = main.db()
    try:
        assert c.execute("SELECT COUNT(*) AS n FROM tenants").fetchone()["n"] == 1
        after = c.execute(
            "SELECT api_key_hash,name,status FROM tenants WHERE id=?",
            (tenant_id,),
        ).fetchone()
        after_signup = c.execute(
            "SELECT tenant_name,last_key_created_at,updated_at FROM public_signups WHERE email=?",
            ("ops@example.com",),
        ).fetchone()
        assert tuple(after) == tuple(before)
        assert tuple(after_signup) == tuple(before_signup)
        actions = [
            row["action"]
            for row in c.execute(
                "SELECT action FROM audit_log WHERE tenant_id=? ORDER BY created_at",
                (tenant_id,),
            ).fetchall()
        ]
        assert actions == ["public_signup.created", "public_signup.refused_existing"]
    finally:
        c.close()


def test_public_signup_insert_collision_refuses_existing_email(client, monkeypatch):
    competing_key = "mdb_live_competing"
    injected = False
    original_execute = main.Conn.execute

    def inject_competing_signup(conn, sql, params=()):
        nonlocal injected
        result = original_execute(conn, sql, params)
        if not injected and "SELECT * FROM public_signups WHERE email=?" in sql:
            injected = True
            competing = main.db()
            try:
                competing_tenant_id = "ten_competing"
                created = main.now()
                competing.execute(
                    "INSERT INTO tenants(id,name,plan,api_key_hash,status,created_at) VALUES(?,?,?,?,?,?)",
                    (
                        competing_tenant_id,
                        "Competing workspace",
                        "shared",
                        main.digest(competing_key),
                        "active",
                        created,
                    ),
                )
                competing.execute(
                    "INSERT INTO public_signups VALUES(?,?,?,?,?,?)",
                    (
                        "collision@example.com",
                        competing_tenant_id,
                        "Competing workspace",
                        created,
                        created,
                        created,
                    ),
                )
                competing.commit()
            finally:
                competing.close()
        return result

    monkeypatch.setattr(main.Conn, "execute", inject_competing_signup)
    response = client.post(
        "/v1/public/signup",
        json={"email": "collision@example.com"},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == (
        "an account already exists for that email; use your existing key or contact Mosaic"
    )
    c = main.db()
    try:
        assert c.execute("SELECT COUNT(*) AS n FROM tenants").fetchone()["n"] == 1
        assert c.execute("SELECT COUNT(*) AS n FROM public_signups").fetchone()["n"] == 1
        assert c.execute(
            "SELECT action FROM audit_log WHERE tenant_id=?",
            ("ten_competing",),
        ).fetchone()["action"] == "public_signup.refused_existing"
    finally:
        c.close()


def test_public_signup_rejects_dedicated_plan(client):
    response = client.post(
        "/v1/public/signup",
        json={"email": "dedicated@example.com", "plan": "dedicated"},
    )
    assert response.status_code == 400
    assert "get in touch" in response.json()["detail"]


def test_public_signup_has_tighter_rate_limit(client, monkeypatch):
    monkeypatch.setattr(main, "PUBLIC_SIGNUP_RATE_LIMIT_REQUESTS", 1)
    first = client.post("/v1/public/signup", json={"email": "first@example.com"})
    second = client.post("/v1/public/signup", json={"email": "second@example.com"})
    assert first.status_code == 200
    assert second.status_code == 429


def test_public_signup_ignores_forwarded_ip_by_default(client, monkeypatch):
    monkeypatch.setattr(main, "PUBLIC_SIGNUP_RATE_LIMIT_REQUESTS", 1)
    first = client.post(
        "/v1/public/signup",
        headers={"CF-Connecting-IP": "198.51.100.10"},
        json={"email": "socket-first@example.com"},
    )
    second = client.post(
        "/v1/public/signup",
        headers={"CF-Connecting-IP": "198.51.100.11"},
        json={"email": "socket-second@example.com"},
    )
    assert first.status_code == 200
    assert second.status_code == 429


def test_public_signup_honors_forwarded_ip_when_trusted(client, monkeypatch):
    monkeypatch.setattr(main, "PUBLIC_SIGNUP_RATE_LIMIT_REQUESTS", 1)
    monkeypatch.setattr(main, "TRUST_CLOUDFLARE_IP", True)
    first = client.post(
        "/v1/public/signup",
        headers={"CF-Connecting-IP": "198.51.100.20"},
        json={"email": "forwarded-first@example.com"},
    )
    second = client.post(
        "/v1/public/signup",
        headers={"CF-Connecting-IP": "198.51.100.21"},
        json={"email": "forwarded-second@example.com"},
    )
    limited = client.post(
        "/v1/public/signup",
        headers={"CF-Connecting-IP": "198.51.100.20"},
        json={"email": "forwarded-third@example.com"},
    )
    assert first.status_code == 200
    assert second.status_code == 200
    assert limited.status_code == 429


def test_public_signup_rejects_forwarded_ip_from_untrusted_peer():
    request = main.Request({
        "type": "http",
        "method": "POST",
        "path": "/v1/public/signup",
        "headers": [(b"cf-connecting-ip", b"198.51.100.20")],
        "client": ("8.8.8.8", 443),
        "scheme": "http",
        "server": ("control-plane", 80),
    })
    old = main.TRUST_CLOUDFLARE_IP
    main.TRUST_CLOUDFLARE_IP = True
    try:
        assert main.public_signup_client_ip(request) == "8.8.8.8"
    finally:
        main.TRUST_CLOUDFLARE_IP = old


def test_rate_limit_sweeps_unrelated_expired_buckets(client, monkeypatch):
    monkeypatch.setattr(main, "RATE_LIMIT_SWEEP_THRESHOLD", 2)
    now = time.time()
    main._rate["expired-unrelated"] = [now - 61]
    main._rate["live-unrelated"] = [now]
    main._rate_last_sweep = 0.0
    main.check_rate_limit("current", 2)
    assert "expired-unrelated" not in main._rate
    assert "live-unrelated" in main._rate


def test_database_capacity_ceiling_applies_to_all_callers(client, monkeypatch):
    first = tenant(client)
    created = client.post(
        f"/v1/tenants/{first['tenant_id']}/databases",
        headers={"X-API-Key": first["api_key"]},
        json={"name": "first"},
    )
    assert created.status_code == 200
    monkeypatch.setattr(main, "MAX_DATABASES_TOTAL", 1)
    second = tenant(client)
    refused = client.post(
        f"/v1/tenants/{second['tenant_id']}/databases",
        headers={"X-API-Key": second["api_key"]},
        json={"name": "second"},
    )
    assert refused.status_code == 503
    assert "at capacity" in refused.json()["detail"]
    c = main.db()
    try:
        row = c.execute(
            "SELECT action FROM audit_log WHERE tenant_id=? ORDER BY created_at DESC LIMIT 1",
            (second["tenant_id"],),
        ).fetchone()
        assert row["action"] == "database.creation_refused_capacity"
    finally:
        c.close()


def test_database_provisioning_failure_does_not_commit_database(client, monkeypatch):
    created = tenant(client)

    def fail_provision(*args, **kwargs):
        raise RuntimeError("provision failed")

    monkeypatch.setattr(main.node_transport, "call", fail_provision)
    with pytest.raises(RuntimeError, match="provision failed"):
        client.post(
            f"/v1/tenants/{created['tenant_id']}/databases",
            headers={"X-API-Key": created["api_key"]},
            json={"name": "failed"},
        )
    c = main.db()
    try:
        assert c.execute("SELECT COUNT(*) AS n FROM databases").fetchone()["n"] == 0
    finally:
        c.close()


def promotion_database(client, monkeypatch, replica_status="ready", lag_bytes=42):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local")
    monkeypatch.delenv("MOSAIC_NODE_PRIVATE_ADDRESSES", raising=False)
    created = tenant(client)
    database = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "promotion-db"},
    ).json()
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local,sv2,sv3")
    monkeypatch.setenv(
        "MOSAIC_NODE_PRIVATE_ADDRESSES",
        "local=10.0.0.1,sv2=10.0.0.2,sv3=10.0.0.3",
    )
    c = main.db()
    main_row = c.execute(
        "SELECT * FROM branches WHERE database_id=?", (database["id"],)
    ).fetchone()
    c.execute(
        "UPDATE branches SET status='running',pid=111 WHERE id=?",
        (main_row["id"],),
    )
    c.execute(
        "INSERT INTO replication_credentials VALUES(?,?,?,?)",
        (
            database["id"],
            "mosaic_repl_promotion",
            main.cipher().encrypt(b"repl-secret").decode(),
            main.now(),
        ),
    )
    sampled = main.now()
    ports = [main.Supervisor().allocate_port(c)]
    used = {int(row["port"]) for row in c.execute(
        "SELECT port FROM branches UNION ALL SELECT port FROM replicas"
    ).fetchall()}
    ports.append(ports[0] + 1)
    while ports[1] in used:
        ports[1] += 1
    for host_id, status, port in (
        ("sv2", replica_status, ports[0]),
        ("sv3", "ready", ports[1]),
    ):
        c.execute(
            "INSERT INTO replicas(id,database_id,primary_branch_id,host_id,path,port,status,lag_bytes,lag_sampled_at,created_at,slot_name) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                f"rep_{host_id}_{database['id']}",
                database["id"],
                main_row["id"],
                host_id,
                str(Path(main_row["path"]).parent / ".replicas" / host_id),
                port,
                status,
                lag_bytes,
                sampled,
                sampled,
                f"slot_{host_id}",
            ),
        )
    c.commit()
    c.close()
    return created, database


def test_auth_limits_and_key_rotation(client):
    created = tenant(client)
    tid, key = created["tenant_id"], created["api_key"]
    assert key.startswith("mdb_live_") and tid.startswith("ten_")
    assert client.get(f"/v1/tenants/{tid}/usage", headers={"X-API-Key": "wrong"}).status_code == 401
    rotated = client.post(f"/v1/tenants/{tid}/api-key", headers={"X-API-Key": key}).json()["api_key"]
    assert client.get(f"/v1/tenants/{tid}/usage", headers={"X-API-Key": key}).status_code == 401
    assert client.get(f"/v1/tenants/{tid}/usage", headers={"X-API-Key": rotated}).status_code == 200


def request_with_client(client_ip, forwarded_ip=None):
    headers = []
    if forwarded_ip:
        headers.append((b"cf-connecting-ip", forwarded_ip.encode()))
    return main.Request({
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": headers,
        "client": (client_ip, 443),
        "scheme": "https",
        "server": ("public-api", 443),
    })


def test_public_listener_hides_internal_node_route(client, monkeypatch):
    monkeypatch.setattr(main, "NODE_AGENT_TOKEN", "test-node-token")
    monkeypatch.setattr(main, "PUBLIC_LISTENER", True)
    request = request_with_client("127.0.0.1")
    with pytest.raises(main.HTTPException) as exc_info:
        main.internal_node(
            request,
            "destroy",
            {"path": "/var/lib/mosaic-database/example"},
            "test-node-token",
        )
    assert exc_info.value.status_code == 404


def test_internal_node_allows_loopback_when_public_listener_is_off(client, monkeypatch):
    monkeypatch.setattr(main, "NODE_AGENT_TOKEN", "test-node-token")
    monkeypatch.setattr(main, "PUBLIC_LISTENER", False)
    monkeypatch.setattr(main.node_agent, "handle", lambda operation, payload: {"operation": operation})
    request = request_with_client("127.0.0.1")
    assert main.internal_node(request, "health", {}, "test-node-token") == {"operation": "health"}


def test_mcp_initialize_uses_forwarded_ip_buckets(client, monkeypatch):
    monkeypatch.setattr(main, "PUBLIC_SIGNUP_RATE_LIMIT_REQUESTS", 1)
    monkeypatch.setattr(main, "TRUST_CLOUDFLARE_IP", True)
    payload = {"jsonrpc": "2.0", "id": 1, "method": "initialize"}

    first = main.mcp(payload, request_with_client("127.0.0.1", "198.51.100.10"), main.Response())
    second = main.mcp(payload, request_with_client("127.0.0.1", "198.51.100.11"), main.Response())
    assert first["result"]["protocolVersion"] == main.MCP_PROTOCOL_VERSION
    assert second["result"]["protocolVersion"] == main.MCP_PROTOCOL_VERSION
    with pytest.raises(main.HTTPException) as exc_info:
        main.mcp(payload, request_with_client("127.0.0.1", "198.51.100.10"), main.Response())
    assert exc_info.value.status_code == 429


def test_public_read_only_routes_remain_public(client):
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200
    assert client.get("/v1/plans").status_code == 200
    assert client.get("/.well-known/mcp.json").status_code == 200


class FakeIntrospectionResponse:
    def __init__(self, status, body):
        self.status = status
        self.body = json.dumps(body).encode() if isinstance(body, dict) else body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.body


def mosaic_urlopen(monkeypatch, responses):
    calls = []

    def urlopen(request, timeout):
        calls.append((request, timeout))
        response = responses.pop(0) if responses else FakeIntrospectionResponse(
            503, {"error": "unavailable"}
        )
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(main.urllib.request, "urlopen", urlopen)
    return calls


def test_mosaic_key_provisions_and_reuses_tenant(client, monkeypatch):
    monkeypatch.setattr(main, "MOSAIC_INTROSPECTION_URL", "https://sandbox.test/v1/introspect")
    calls = mosaic_urlopen(monkeypatch, [
        FakeIntrospectionResponse(200, {
            "organization_id": "org-123",
            "scopes": ["database:read", "database:write"],
            "resource_profile": "standard",
            "status": "active",
        }),
    ])
    key = "msk_live_test"
    first = client.post("/v1/tenants/discover", headers={"Authorization": f"Bearer {key}"})
    second = client.post("/v1/tenants/discover", headers={"Authorization": f"Bearer {key}"})
    assert first.status_code == second.status_code == 200
    assert first.json()["tenant_id"] == second.json()["tenant_id"]
    assert first.json()["origin"] == "sandbox"
    assert len(calls) == 1
    request = calls[0][0]
    assert request.get_header("Authorization") == f"Bearer {key}"
    c = main.db()
    try:
        assert c.execute("SELECT COUNT(*) AS n FROM tenants").fetchone()["n"] == 1
        assert c.execute(
            "SELECT origin FROM tenants WHERE id=?",
            (first.json()["tenant_id"],),
        ).fetchone()["origin"] == "sandbox"
    finally:
        c.close()


def test_mosaic_key_mapping_mismatch_is_refused(client, monkeypatch):
    monkeypatch.setattr(main, "MOSAIC_INTROSPECTION_URL", "https://sandbox.test/v1/introspect")
    mosaic_urlopen(monkeypatch, [FakeIntrospectionResponse(200, {
        "organization_id": "org-owner",
        "scopes": ["database:read", "database:write"],
        "resource_profile": "standard",
        "status": "active",
    })])
    key = "msk_live_owner"
    owner = client.post("/v1/tenants/discover", headers={"Authorization": f"Bearer {key}"}).json()
    other = tenant(client)
    response = client.get(
        f"/v1/tenants/{other['tenant_id']}/databases",
        headers={"Authorization": f"Bearer {key}"},
    )
    assert response.status_code == 401
    assert owner["tenant_id"] != other["tenant_id"]


@pytest.mark.parametrize(
    ("identity", "expected_status"),
    [
        (None, 401),
        ({
            "organization_id": "org-inactive",
            "scopes": ["database:read", "database:write"],
            "resource_profile": "standard",
            "status": "revoked",
        }, 401),
    ],
)
def test_mosaic_key_rejected_for_invalid_or_inactive_identity(client, monkeypatch, identity, expected_status):
    monkeypatch.setattr(main, "MOSAIC_INTROSPECTION_URL", "https://sandbox.test/v1/introspect")
    if identity is None:
        response = urllib.error.HTTPError(
            "https://sandbox.test/v1/introspect",
            401,
            "unauthorized",
            {},
            None,
        )
    else:
        response = FakeIntrospectionResponse(200, identity)
    mosaic_urlopen(monkeypatch, [response])
    result = client.post(
        "/v1/tenants/discover",
        headers={"Authorization": "Bearer msk_live_invalid"},
    )
    assert result.status_code == expected_status


def test_mosaic_key_scope_enforcement(client, monkeypatch):
    monkeypatch.setattr(main, "MOSAIC_INTROSPECTION_URL", "https://sandbox.test/v1/introspect")
    mosaic_urlopen(monkeypatch, [FakeIntrospectionResponse(200, {
        "organization_id": "org-read-only",
        "scopes": ["database:read"],
        "resource_profile": "standard",
        "status": "active",
    })])
    c = main.db()
    try:
        c.execute(
            "INSERT INTO tenants(id,name,plan,api_key_hash,status,created_at,origin) "
            "VALUES(?,?,?,?,?,?,?)",
            ("ten-read", "Read workspace", "shared", "", "active", main.now(), "sandbox"),
        )
        c.execute(
            "INSERT INTO mosaic_organization_tenants(organization_id,tenant_id,created_at) "
            "VALUES(?,?,?)",
            ("org-read-only", "ten-read", main.now()),
        )
        c.commit()
    finally:
        c.close()
    headers = {"Authorization": "Bearer msk_live_read"}
    assert client.get("/v1/tenants/ten-read/databases", headers=headers).status_code == 200
    response = client.post(
        "/v1/tenants/ten-read/databases",
        headers=headers,
        json={"name": "events"},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "required scope database:write"


def test_mosaic_introspection_outage_uses_warm_cache_but_cold_cache_fails(client, monkeypatch):
    monkeypatch.setattr(main, "MOSAIC_INTROSPECTION_URL", "https://sandbox.test/v1/introspect")
    clock = [100.0]
    monkeypatch.setattr(main.time, "time", lambda: clock[0])
    responses = [FakeIntrospectionResponse(200, {
        "organization_id": "org-warm",
        "scopes": ["database:read", "database:write"],
        "resource_profile": "standard",
        "status": "active",
    })]
    calls = mosaic_urlopen(monkeypatch, responses)
    key = "msk_live_warm"
    assert client.post("/v1/tenants/discover", headers={"Authorization": f"Bearer {key}"}).status_code == 200
    responses.append(urllib.error.URLError("offline"))
    clock[0] = 150.0
    assert client.post("/v1/tenants/discover", headers={"Authorization": f"Bearer {key}"}).status_code == 200
    main._mosaic_identity_cache.clear()
    cold = client.post(
        "/v1/tenants/discover",
        headers={"Authorization": "Bearer msk_live_cold"},
    )
    assert cold.status_code == 503
    assert cold.json()["detail"] == "identity service unavailable"
    assert len(calls) == 3


def test_mosaic_introspection_cache_ttls_and_cap(monkeypatch):
    monkeypatch.setattr(main, "MOSAIC_INTROSPECTION_URL", "https://sandbox.test/v1/introspect")
    monkeypatch.setenv("MOSAIC_INTROSPECTION_CACHE_TTL_SECONDS", "3")
    monkeypatch.setenv("MOSAIC_INTROSPECTION_NEGATIVE_TTL_SECONDS", "2")
    monkeypatch.setenv("MOSAIC_INTROSPECTION_CACHE_CAP", "2")
    clock = [100.0]
    monkeypatch.setattr(main.time, "time", lambda: clock[0])
    responses = [
        FakeIntrospectionResponse(200, {"organization_id": "org-1", "scopes": [], "status": "active"}),
        urllib.error.HTTPError("https://sandbox.test", 401, "unauthorized", {}, None),
        FakeIntrospectionResponse(200, {"organization_id": "org-2", "scopes": [], "status": "active"}),
        FakeIntrospectionResponse(200, {"organization_id": "org-3", "scopes": [], "status": "active"}),
    ]
    calls = mosaic_urlopen(monkeypatch, responses)
    assert main.introspect_mosaic_key("msk_live_one")["organization_id"] == "org-1"
    clock[0] = 102.0
    with pytest.raises(main.HTTPException) as exc_info:
        main.introspect_mosaic_key("msk_live_bad")
    assert exc_info.value.status_code == 401
    clock[0] = 103.0
    assert main.introspect_mosaic_key("msk_live_one")["organization_id"] == "org-1"
    clock[0] = 106.0
    assert main.introspect_mosaic_key("msk_live_one")["organization_id"] == "org-2"
    assert main.introspect_mosaic_key("msk_live_three")["organization_id"] == "org-3"
    assert len(main._mosaic_identity_cache) == 2
    assert len(calls) == 4


def test_mcp_accepts_mosaic_key(client, monkeypatch):
    monkeypatch.setattr(main, "MOSAIC_INTROSPECTION_URL", "https://sandbox.test/v1/introspect")
    mosaic_urlopen(monkeypatch, [FakeIntrospectionResponse(200, {
        "organization_id": "org-mcp",
        "scopes": ["database:read", "database:write"],
        "resource_profile": "standard",
        "status": "active",
    })])
    response = client.post(
        "/mcp",
        headers={"Authorization": "Bearer msk_live_mcp"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert response.status_code == 200
    assert response.json()["result"]["tools"]


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
    c = main.db()
    branch_path = c.execute(
        "SELECT path FROM branches WHERE id=?", (branch["id"],)
    ).fetchone()["path"]
    c.close()
    shutil.rmtree(branch_path)
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


def test_clone_removes_postmaster_runtime_files(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    parent = root / "parent"
    parent.mkdir(parents=True)
    (parent / "postmaster.pid").write_text("123\n")
    (parent / "postmaster.opts").write_text("postgres\n")
    zfs_target = root / "zfs-target"
    calls = []

    def run(argv, env=None):
        calls.append(argv)
        if argv[:2] == ["zfs", "clone"]:
            zfs_target.mkdir()
            (zfs_target / "postmaster.pid").write_text("123\n")
            (zfs_target / "postmaster.opts").write_text("postgres\n")

    main.ZfsBranchEngine("mosaic/db", run).clone(
        parent,
        zfs_target,
        target_port=55433,
    )
    assert not (zfs_target / "postmaster.pid").exists()
    assert not (zfs_target / "postmaster.opts").exists()

    copy_target = root / "copy-target"
    main.CopyBranchEngine(lambda argv, env=None: None).clone(
        parent,
        copy_target,
        target_port=55434,
    )
    assert not (copy_target / "postmaster.pid").exists()
    assert not (copy_target / "postmaster.opts").exists()


def test_zfs_busy_standby_destroy_unmounts_after_verified_stop_and_retries(tmp_path):
    calls = []
    destroy_attempts = 0
    standby = tmp_path / "cluster" / ".replicas" / "sv2"

    def run(argv, env=None):
        nonlocal destroy_attempts
        calls.append(argv)
        if argv[:3] == ["zfs", "destroy", "-r"]:
            destroy_attempts += 1
            if destroy_attempts == 1:
                raise subprocess.CalledProcessError(1, argv, stderr="dataset is busy")

    engine = main.ZfsBranchEngine("mosaic/db", run)
    engine.prepare_standby(standby, is_stopped=lambda path: True)
    dataset = engine._dataset(standby)
    assert ["zfs", "unmount", "-f", dataset] in calls
    assert calls.count(
        ["zfs", "destroy", "-r", dataset]
    ) == 2


def test_zfs_unmount_failed_standby_destroy_retries_after_verified_stop(tmp_path):
    calls = []
    destroy_attempts = 0
    standby = tmp_path / "cluster" / ".replicas" / "sv2"

    def run(argv, env=None):
        nonlocal destroy_attempts
        calls.append(argv)
        if argv[:3] == ["zfs", "destroy", "-r"]:
            destroy_attempts += 1
            if destroy_attempts == 1:
                raise subprocess.CalledProcessError(
                    1, argv, stderr="cannot unmount: unmount failed"
                )

    engine = main.ZfsBranchEngine("mosaic/db", run)
    engine.prepare_standby(standby, is_stopped=lambda path: True)
    dataset = engine._dataset(standby)
    assert ["zfs", "unmount", "-f", dataset] in calls
    assert calls.count(["zfs", "destroy", "-r", dataset]) == 2


def test_zfs_lazy_unmount_retries_after_forced_unmount_fails(tmp_path, monkeypatch):
    calls = []
    destroy_attempts = 0
    root = tmp_path / "branches"
    standby = root / "cluster" / ".replicas" / "sv2"
    monkeypatch.setattr(main, "BRANCH_ROOT", root)

    def run(argv, env=None):
        nonlocal destroy_attempts
        calls.append(argv)
        if argv[:3] == ["zfs", "destroy", "-r"]:
            destroy_attempts += 1
            if destroy_attempts == 1:
                raise subprocess.CalledProcessError(
                    1, argv, stderr="cannot unmount: unmount failed"
                )
        elif argv[:3] == ["zfs", "unmount", "-f"]:
            raise subprocess.CalledProcessError(
                1, argv, stderr="cannot unmount: unmount failed"
            )

    engine = main.ZfsBranchEngine("mosaic/db", run)
    engine.prepare_standby(standby, is_stopped=lambda path: True)
    dataset = engine._dataset(standby)
    assert ["zfs", "unmount", "-f", dataset] in calls
    assert ["mosaic-umount", "-l", str(standby.resolve())] in calls
    assert calls.count(["zfs", "destroy", "-r", dataset]) == 2


def test_zfs_lazy_unmount_does_not_run_when_target_is_unverified(tmp_path, monkeypatch):
    calls = []
    root = tmp_path / "branches"
    standby = root / "cluster" / ".replicas" / "sv2"
    monkeypatch.setattr(main, "BRANCH_ROOT", root)

    def run(argv, env=None):
        calls.append(argv)
        if argv[:3] == ["zfs", "destroy", "-r"]:
            raise subprocess.CalledProcessError(
                1, argv, stderr="cannot unmount: unmount failed"
            )

    engine = main.ZfsBranchEngine("mosaic/db", run)
    with pytest.raises(RuntimeError, match="could not be proven stopped"):
        engine.prepare_standby(standby, is_stopped=lambda path: False)
    assert not any(call[0] == "mosaic-umount" for call in calls)


def test_zfs_lazy_unmount_refuses_path_outside_branch_root(tmp_path, monkeypatch):
    calls = []
    root = tmp_path / "branches"
    standby = tmp_path / "outside" / "cluster" / ".replicas" / "sv2"
    monkeypatch.setattr(main, "BRANCH_ROOT", root)

    def run(argv, env=None):
        calls.append(argv)
        if argv[:3] == ["zfs", "destroy", "-r"]:
            raise subprocess.CalledProcessError(
                1, argv, stderr="cannot unmount: unmount failed"
            )
        if argv[:3] == ["zfs", "unmount", "-f"]:
            raise subprocess.CalledProcessError(
                1, argv, stderr="cannot unmount: unmount failed"
            )

    engine = main.ZfsBranchEngine("mosaic/db", run)
    with pytest.raises(RuntimeError, match="outside MOSAIC_BRANCH_ROOT"):
        engine.prepare_standby(standby, is_stopped=lambda path: True)
    assert not any(call[0] == "mosaic-umount" for call in calls)


def test_zfs_busy_standby_destroy_does_not_unmount_unverified_target(tmp_path):
    calls = []
    standby = tmp_path / "cluster" / ".replicas" / "sv2"

    def run(argv, env=None):
        calls.append(argv)
        if argv[:3] == ["zfs", "destroy", "-r"]:
            raise subprocess.CalledProcessError(
                1, argv, stderr="cannot unmount: unmount failed"
            )

    engine = main.ZfsBranchEngine("mosaic/db", run)
    with pytest.raises(RuntimeError, match="could not be proven stopped"):
        engine.prepare_standby(standby, is_stopped=lambda path: False)
    assert ["zfs", "unmount", "-f", engine._dataset(standby)] not in calls


def test_zfs_nonbusy_standby_destroy_failure_is_not_retried(tmp_path):
    calls = []
    standby = tmp_path / "cluster" / ".replicas" / "sv2"

    def run(argv, env=None):
        calls.append(argv)
        if argv[:3] == ["zfs", "destroy", "-r"]:
            raise subprocess.CalledProcessError(1, argv, stderr="permission denied")

    engine = main.ZfsBranchEngine("mosaic/db", run)
    with pytest.raises(main.ZfsCommandError, match="permission denied"):
        engine.prepare_standby(standby, is_stopped=lambda path: True)
    assert ["zfs", "unmount", "-f", engine._dataset(standby)] not in calls


def test_zfs_failure_includes_stderr_and_stdout(tmp_path):
    path = tmp_path / "cluster"
    argv = ["zfs", "destroy", "-r", f"mosaic/db/{tmp_path.name}/cluster"]

    def run(actual, env=None):
        raise subprocess.CalledProcessError(
            1,
            actual,
            output="zfs stdout detail",
            stderr="zfs stderr detail",
        )

    with pytest.raises(main.ZfsCommandError) as caught:
        main.ZfsBranchEngine("mosaic/db", run).destroy(path)
    assert "zfs stderr detail" in str(caught.value)
    assert "zfs stdout detail" in str(caught.value)


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
    c.execute("INSERT INTO tenants(id,name,plan,api_key_hash,status,created_at) VALUES(?,?,?,?,?,?)", ("ten_x", "x", "shared", "h", "active", main.now()))
    c.execute("INSERT INTO databases VALUES(?,?,?,?,?,?)", ("db_x", "ten_x", "x", str(tmp_path), "ready", main.now()))
    old = "2000-01-01T00:00:00+00:00"
    c.execute("INSERT INTO branches VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", ("br_x", "db_x", "main", None, str(tmp_path), 55432, 999999, "running", "x", old, old, "local"))
    c.commit()
    stopped = main.Supervisor().reap(c, idle_seconds=1)
    assert stopped == 1
    assert c.execute("SELECT status,pid FROM branches").fetchone()["status"] == "stopped"
    c.close()


def test_reaper_treats_missing_branch_directory_as_stopped(tmp_path):
    main.DB_PATH = tmp_path / "reaper-missing.db"
    c = main.db()
    main.initialize_schema(c)
    main_path = tmp_path / "gone"
    main_path.mkdir()
    c.execute("INSERT INTO tenants(id,name,plan,api_key_hash,status,created_at) VALUES(?,?,?,?,?,?)", ("ten_x", "x", "shared", "h", "active", main.now()))
    c.execute("INSERT INTO databases VALUES(?,?,?,?,?,?)", ("db_x", "ten_x", "x", str(tmp_path), "ready", main.now()))
    old = "2000-01-01T00:00:00+00:00"
    c.execute(
        "INSERT INTO branches VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        ("br_x", "db_x", "main", None, str(main_path), 55432, 999999, "running", "x", old, old, "local"),
    )
    main_path.rmdir()
    c.commit()
    assert main.Supervisor().reap(c, idle_seconds=1) == 1
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


def test_single_explicit_node_uses_in_process_identity(client, monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "sv1")
    monkeypatch.delenv("MOSAIC_NODE_ID", raising=False)
    created = tenant(client)
    database = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "sv1-db"},
    )
    assert database.status_code == 200
    assert main.current_node_id() == "sv1"
    did = database.json()["id"]
    branch = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{did}/branches",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "feature"},
    )
    assert branch.status_code == 200
    assert client.delete(
        f"/v1/tenants/{created['tenant_id']}/databases/{did}/branches/{branch.json()['id']}",
        headers={"X-API-Key": created["api_key"]},
    ).status_code == 200


def test_invalid_node_identity_is_rejected_at_startup(monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "sv1,sv2")
    monkeypatch.setenv("MOSAIC_NODE_ID", "stale")
    with pytest.raises(RuntimeError, match="not present in MOSAIC_NODE_HOSTS"):
        with TestClient(main.app):
            pass


def test_stale_node_id_never_dispatches_locally(monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "sv1")
    monkeypatch.delenv("MOSAIC_NODE_ID", raising=False)
    with pytest.raises(RuntimeError, match="unknown database node"):
        main.NodeTransport(main.NodeAgent()).call("stale", "inspect", {})


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
    c.execute("INSERT INTO tenants(id,name,plan,api_key_hash,status,created_at) VALUES(?,?,?,?,?,?)", ("ten_r", "r", "shared", "h", "active", main.now()))
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

    started = threading.Event()
    release = threading.Event()

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, query, params=None):
            return self

        def fetchone(self):
            return None

        def commit(self):
            pass

    class Psycopg:
        def connect(self, **kwargs):
            return Connection()

    monkeypatch.setattr(main, "psycopg", Psycopg())

    def run(argv, env=None):
        calls.append(argv)
        if argv[0] == main.pg_bin("pg_basebackup"):
            target.mkdir(parents=True, exist_ok=True)
            (target / "postgresql.conf").write_text("")
            (target / "pg_hba.conf").write_text("")
            started.set()
            release.wait(timeout=2)
        elif argv[0] == main.pg_bin("pg_ctl") and argv[-1] == "start":
            (target / "postmaster.pid").write_text("123\n")

    agent = main.NodeAgent(run)
    assert agent.handle("build_standby", {
        "target_path": str(target),
        "target_port": 55433,
        "target_host_id": "sv2",
        "primary_address": "10.0.0.1",
        "primary_port": 55432,
        "primary_password": "primary-secret",
        "replication_user": "mosaic_repl_db",
        "replication_password": "secret",
        "replication_slot": "mosaic_db_sv2",
    }) == {"status": "building"}
    assert started.wait(timeout=2)
    assert agent.handle("build_standby", {
        "target_path": str(target),
        "target_port": 55433,
        "target_host_id": "sv2",
        "primary_address": "10.0.0.1",
        "primary_port": 55432,
        "primary_password": "primary-secret",
        "replication_user": "mosaic_repl_db",
        "replication_password": "secret",
        "replication_slot": "mosaic_db_sv2",
    }) == {"status": "building"}
    release.set()
    for _ in range(100):
        result = agent.handle("inspect_standby", {"target_path": str(target)})
        if result["status"] == "ready":
            break
        time.sleep(0.01)
    assert result == {"status": "ready"}
    assert calls[0] == [
        main.pg_bin("pg_basebackup"), "-D", str(target), "-h", "10.0.0.1",
        "-p", "55432", "-U", "mosaic_repl_db", "-Fp", "-X", "stream", "-R",
        "-C", "-S", "mosaic_db_sv2",
    ]
    assert calls[1] == [
        main.pg_bin("pg_ctl"), "-D", str(target), "-l",
        str(target / "postgres.log"), "start",
    ]
    assert calls[2] == [main.pg_bin("pg_ctl"), "-D", str(target), "status"]


def test_standby_build_replaces_existing_slot_before_backup(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    target = root / "standby"
    sql = []
    events = []
    terminated = [False]
    release_polls = [2]

    class Result:
        def fetchone(self):
            if terminated[0] and release_polls[0]:
                release_polls[0] -= 1
                return (True, 123)
            return (not terminated[0], None if terminated[0] else 123)

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, query, params=None):
            sql.append((str(query), params))
            if "pg_drop_replication_slot" in str(query):
                events.append("drop")
            elif "pg_terminate_backend" in str(query):
                events.append("terminate")
                terminated[0] = True
            return Result()

        def commit(self):
            pass

        def rollback(self):
            pass

    class Psycopg:
        def connect(self, **kwargs):
            return Connection()

    monkeypatch.setattr(main, "psycopg", Psycopg())
    calls = []

    def run(argv, env=None):
        calls.append(argv)
        if argv[0] == main.pg_bin("pg_basebackup"):
            events.append("backup")
            target.mkdir(parents=True, exist_ok=True)
            (target / "postgresql.conf").write_text("")
            (target / "pg_hba.conf").write_text("")
        elif argv[0] == main.pg_bin("pg_ctl") and argv[-1] == "start":
            (target / "postmaster.pid").write_text("123\n")

    agent = main.NodeAgent(run)
    payload = {
        "target_path": str(target),
        "target_port": 55433,
        "target_host_id": "local",
        "primary_address": "127.0.0.1",
        "primary_port": 55432,
        "primary_password": "primary-secret",
        "replication_user": "mosaic_repl_db",
        "replication_password": "secret",
        "replication_slot": "mosaic_db_sv2",
    }
    assert agent.handle("build_standby", payload) == {"status": "building"}
    for _ in range(300):
        result = agent.handle("inspect_standby", {"target_path": str(target)})
        if result["status"] == "ready":
            break
        time.sleep(0.01)
    assert result == {"status": "ready"}
    assert any("pg_drop_replication_slot" in query for query, _ in sql)
    assert events == ["terminate", "drop", "backup"]
    assert calls[0][-3:] == ["-C", "-S", "mosaic_db_sv2"]


def test_standby_build_missing_slot_is_not_an_error(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    target = root / "standby"

    class Result:
        def fetchone(self):
            return None

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, query, params=None):
            return Result()

        def commit(self):
            pass

    class Psycopg:
        def connect(self, **kwargs):
            return Connection()

    monkeypatch.setattr(main, "psycopg", Psycopg())

    def run(argv, env=None):
        if argv[0] == main.pg_bin("pg_basebackup"):
            target.mkdir(parents=True, exist_ok=True)
            (target / "postgresql.conf").write_text("")
            (target / "pg_hba.conf").write_text("")
        elif argv[0] == main.pg_bin("pg_ctl") and argv[-1] == "start":
            (target / "postmaster.pid").write_text("123\n")

    agent = main.NodeAgent(run)
    payload = {
        "target_path": str(target),
        "target_port": 55433,
        "target_host_id": "local",
        "primary_address": "127.0.0.1",
        "primary_port": 55432,
        "primary_password": "primary-secret",
        "replication_user": "mosaic_repl_db",
        "replication_password": "secret",
        "replication_slot": "mosaic_db_sv2",
    }
    assert agent.handle("build_standby", payload) == {"status": "building"}
    for _ in range(100):
        result = agent.handle("inspect_standby", {"target_path": str(target)})
        if result["status"] == "ready":
            break
        time.sleep(0.01)
    assert result == {"status": "ready"}


def test_standby_build_without_primary_password_fails_before_backup(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    target = root / "standby"
    calls = []

    def run(argv, env=None):
        calls.append(argv)

    agent = main.NodeAgent(run)
    payload = {
        "target_path": str(target),
        "target_port": 55433,
        "target_host_id": "local",
        "primary_address": "127.0.0.1",
        "primary_port": 55432,
        "replication_user": "mosaic_repl_db",
        "replication_password": "secret",
        "replication_slot": "mosaic_db_sv2",
    }
    assert agent.handle("build_standby", payload) == {"status": "building"}
    for _ in range(100):
        result = agent.handle("inspect_standby", {"target_path": str(target)})
        if result["status"] == "failed":
            break
        time.sleep(0.01)
    assert result["status"] == "failed"
    assert "primary password is required" in result["error"]
    assert not any(call[0] == main.pg_bin("pg_basebackup") for call in calls)


def test_explicit_standby_rebuild_bypasses_ready_cache(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    target = root / "standby"
    target.mkdir()
    calls = []
    rebuilt = threading.Event()

    def run(argv, env=None):
        calls.append(argv)
        if argv[0] == main.pg_bin("pg_basebackup"):
            target.mkdir(parents=True, exist_ok=True)
            (target / "postgresql.conf").write_text("")
            rebuilt.set()

    agent = main.NodeAgent(run)
    agent._standby_jobs[target] = {"status": "ready"}
    payload = {
        "target_path": str(target),
        "target_port": 55433,
        "target_host_id": "local",
        "primary_address": "127.0.0.1",
        "primary_port": 55432,
        "replication_user": "mosaic_repl_db",
        "replication_password": "secret",
        "force_rebuild": True,
    }
    assert agent.handle("build_standby", payload) == {"status": "building"}
    assert rebuilt.wait(timeout=2)
    assert sum(call[0] == main.pg_bin("pg_basebackup") for call in calls) == 1


def test_ready_standby_status_probes_cluster_instead_of_using_build_cache(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    target = root / "standby"
    target.mkdir()
    agent = main.NodeAgent(lambda argv, env=None: None)
    agent._standby_jobs[target] = {"status": "ready"}

    assert agent.handle("inspect_standby", {"target_path": str(target)}) == {
        "status": "failed",
        "error": "standby postmaster is not running",
    }


def test_forced_standby_rebuild_supersedes_inflight_build(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    target = root / "standby"
    target.mkdir()
    started = threading.Event()
    release = threading.Event()
    calls = []

    def run(argv, env=None):
        calls.append(argv)
        if argv[0] == main.pg_bin("pg_basebackup"):
            target.mkdir(parents=True, exist_ok=True)
            (target / "postgresql.conf").write_text("")
            started.set()
            release.wait(timeout=2)

    agent = main.NodeAgent(run)
    payload = {
        "target_path": str(target),
        "target_port": 55433,
        "target_host_id": "local",
        "primary_address": "127.0.0.1",
        "primary_port": 55432,
        "replication_user": "mosaic_repl_db",
        "replication_password": "secret",
        "force_rebuild": True,
    }
    assert agent.handle("build_standby", payload) == {"status": "building"}
    assert started.wait(timeout=2)
    assert agent.handle("build_standby", payload) == {
        "status": "building",
        "superseded": True,
    }
    release.set()
    for _ in range(100):
        result = agent.handle("inspect_standby", {"target_path": str(target)})
        if result["status"] == "failed":
            break
        time.sleep(0.01)
    assert result["status"] == "failed"
    assert "superseded" in result["error"]
    assert sum(call[0] == main.pg_bin("pg_basebackup") for call in calls) == 1


def test_concurrent_forced_rebuilds_start_one_build(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    target = root / "standby"
    target.mkdir()
    started = threading.Event()
    release = threading.Event()
    calls = []

    def run(argv, env=None):
        calls.append(argv)
        if argv[0] == main.pg_bin("pg_basebackup"):
            target.mkdir(parents=True, exist_ok=True)
            (target / "postgresql.conf").write_text("")
            started.set()
            release.wait(timeout=2)

    agent = main.NodeAgent(run)
    payload = {
        "target_path": str(target),
        "target_port": 55433,
        "target_host_id": "local",
        "primary_address": "127.0.0.1",
        "primary_port": 55432,
        "replication_user": "mosaic_repl_db",
        "replication_password": "secret",
        "force_rebuild": True,
    }
    results = []
    barrier = threading.Barrier(3)

    def request():
        barrier.wait()
        results.append(agent.handle("build_standby", payload))

    threads = [threading.Thread(target=request) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    assert started.wait(timeout=2)
    release.set()
    assert len(results) == 2
    assert sum(call[0] == main.pg_bin("pg_basebackup") for call in calls) == 1
    assert all(result["status"] == "building" for result in results)


def test_zfs_standby_dataset_is_reusable_and_promoted_path_can_clone(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local")
    calls = []
    dataset_exists = [False]
    standby = root / "cluster" / ".replicas" / "sv2"
    branch = root / "cluster" / ".replicas" / "sv2-branch"

    def run(argv, env=None):
        calls.append(argv)
        if argv[:3] == ["zfs", "list", "-H"]:
            if not dataset_exists[0]:
                raise subprocess.CalledProcessError(
                    1, argv, stderr="dataset does not exist"
                )
        elif argv[:2] == ["zfs", "create"]:
            Path(argv[-1]).parent.mkdir(parents=True, exist_ok=True)
            Path(argv[-1]).mkdir(parents=True, exist_ok=True)
            (Path(argv[-1]) / "postgresql.conf").write_text("")
        elif argv[:2] == ["zfs", "clone"]:
            branch.mkdir(parents=True, exist_ok=True)
            (branch / "postgresql.conf").write_text("")

    zfs = main.ZfsBranchEngine("mosaic/db", run)
    zfs.prepare_standby(standby)
    dataset_exists[0] = True
    zfs.prepare_standby(standby)
    zfs.clone(standby, branch, target_port=55440)
    assert [
        "zfs", "create", "-p", "-o",
        f"mountpoint={standby.resolve()}",
        "mosaic/db/cluster/.replicas/sv2",
    ] in calls
    assert ["zfs", "destroy", "-r", "mosaic/db/cluster/.replicas/sv2"] in calls
    assert [
        "zfs", "clone", "-o", f"mountpoint={branch.resolve()}",
        "mosaic/db/cluster/.replicas/sv2@branch-sv2-branch",
        "mosaic/db/cluster/.replicas/sv2-branch",
    ] in calls


def test_promote_standby_clears_standby_configuration_and_is_idempotent(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    target = root / "standby"
    target.mkdir()
    (target / "PG_VERSION").write_text("14\n")
    (target / "postmaster.pid").write_text("321\n")
    (target / "postgresql.conf").write_text("port = 55433\nhot_standby = off\n")
    (target / "postgresql.auto.conf").write_text(
        "primary_conninfo = 'host=10.0.0.1'\nprimary_slot_name = 'slot_x'\n"
    )
    (target / "standby.signal").write_text("")
    calls = []
    recovery = iter(["in archive recovery", "in production", "in production"])

    def run(argv, env=None):
        calls.append(argv)
        if argv[0] == main.pg_bin("pg_controldata"):
            return type("Result", (), {"stdout": f"Database cluster state: {next(recovery)}\n"})()

    agent = main.NodeAgent(run)
    payload = {
        "target_path": str(target),
        "target_port": 55433,
        "target_host_id": "local",
        "postgres_password": "secret",
        "promotion_timeout": 1,
    }
    first = agent.handle("promote_standby", payload)
    second = agent.handle("promote_standby", payload)
    assert first == {"status": "promoted", "pid": 321, "port": 55433}
    assert second == first
    assert sum(call[-1] == "promote" for call in calls) == 1
    assert not (target / "standby.signal").exists()
    auto = (target / "postgresql.auto.conf").read_text()
    assert "primary_conninfo" not in auto
    assert "primary_slot_name" not in auto
    assert "hot_standby = on" in (target / "postgresql.conf").read_text()
    assert sum(call[-1] == "reload" for call in calls) == 2


def test_promote_dark_standby_does_not_connect_to_postgres(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    target = root / "standby"
    target.mkdir()
    (target / "PG_VERSION").write_text("14\n")
    (target / "postmaster.pid").write_text("321\n")
    (target / "postgresql.conf").write_text("port = 55433\nhot_standby = off\n")
    (target / "standby.signal").write_text("")
    calls = []
    recovery = iter(["in archive recovery", "in production"])

    class RefusingPsycopg:
        def connect(self, **kwargs):
            raise AssertionError("dark standby recovery detection must not connect")

    def run(argv, env=None):
        calls.append(argv)
        if argv[0] == main.pg_bin("pg_controldata"):
            return type("Result", (), {"stdout": f"Database cluster state: {next(recovery)}\n"})()

    monkeypatch.setattr(main, "psycopg", RefusingPsycopg())
    result = main.NodeAgent(run).handle("promote_standby", {
        "target_path": str(target),
        "target_port": 55433,
        "target_host_id": "local",
        "postgres_password": "secret",
        "promotion_timeout": 1,
    })
    assert result == {"status": "promoted", "pid": 321, "port": 55433}
    assert any(call[-1] == "promote" for call in calls)


def test_starting_standby_signal_does_not_promote(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    path = root / "branch"
    path.mkdir()
    (path / "PG_VERSION").write_text("14\n")
    (path / "standby.signal").write_text("")
    (path / "postgresql.conf").write_text("")
    calls = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, query):
            return self

        def commit(self):
            return None

    class FakePsycopg:
        def connect(self, **kwargs):
            return Connection()

    def run(argv, **kwargs):
        calls.append(argv)
        (path / "postmaster.pid").write_text("456\n")

    monkeypatch.setattr(main, "psycopg", FakePsycopg())
    monkeypatch.setattr(main, "subprocess", type("Subprocess", (), {"run": staticmethod(run)}))
    monkeypatch.setattr(main, "alive", lambda pid: False)
    monkeypatch.setattr(main.Supervisor, "_cluster_is_running", lambda self, path, require_path=False: False)
    result = main.Supervisor().start_local({
        "path": str(path),
        "branch_id": "br",
        "port": 55432,
        "host_id": "local",
        "pid": None,
        "status": "stopped",
        "password": "secret",
        "parent_passwords": [],
    })
    assert result == {"status": "running", "pid": 456}
    assert not any(call[-1] == "promote" for call in calls)


def test_start_local_adopts_running_cluster_with_stale_ledger_pid(tmp_path, monkeypatch):
    path = tmp_path / "branch"
    path.mkdir()
    (path / "PG_VERSION").write_text("14\n")
    (path / "postmaster.pid").write_text("456\n")
    calls = []
    connections = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, query):
            connections.append(query)
            return self

        def commit(self):
            return None

    class FakePsycopg:
        def connect(self, **kwargs):
            return Connection()

    def run(argv, **kwargs):
        calls.append(argv)

    monkeypatch.setattr(main, "psycopg", FakePsycopg())
    monkeypatch.setattr(main, "subprocess", type("Subprocess", (), {"run": staticmethod(run)}))
    monkeypatch.setattr(main.Supervisor, "_cluster_is_running", lambda self, path, require_path=False: True)
    result = main.Supervisor().start_local({
        "path": str(path),
        "branch_id": "br",
        "port": 55432,
        "host_id": "local",
        "pid": 123,
        "status": "running",
        "password": "secret",
        "parent_passwords": [],
    })
    assert result == {"status": "running", "pid": 456}
    assert calls == []
    assert connections == []


def test_start_local_does_not_adopt_foreign_postmaster_pidfile(tmp_path, monkeypatch):
    path = tmp_path / "branch"
    path.mkdir()
    (path / "PG_VERSION").write_text("14\n")
    foreign = tmp_path / "parent"
    (path / "postmaster.pid").write_text(f"123\n{foreign}\n")
    calls = []
    monkeypatch.setattr(main, "alive", lambda pid: True)

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class FakePsycopg:
        def connect(self, **kwargs):
            return Connection()

    def run(argv, **kwargs):
        calls.append(argv)
        assert argv[-1] == "start"
        assert not (path / "postmaster.pid").exists()
        (path / "postmaster.pid").write_text(f"456\n{path.resolve()}\n")

    monkeypatch.setattr(main, "psycopg", FakePsycopg())
    monkeypatch.setattr(main.subprocess, "run", run)
    result = main.Supervisor().start_local({
        "path": str(path),
        "branch_id": "br",
        "port": 55432,
        "host_id": "local",
        "pid": None,
        "status": "stopped",
        "password": "secret",
        "parent_passwords": [],
    })
    assert result == {"status": "running", "pid": 456}
    assert len(calls) == 1


def test_stop_local_does_not_follow_foreign_postmaster_pidfile(tmp_path, monkeypatch):
    path = tmp_path / "branch"
    path.mkdir()
    (path / "PG_VERSION").write_text("14\n")
    foreign = tmp_path / "parent"
    (path / "postmaster.pid").write_text(f"123\n{foreign}\n")
    monkeypatch.setattr(main, "alive", lambda pid: True)

    def run(*args, **kwargs):
        pytest.fail("pg_ctl must not be called for a foreign postmaster pidfile")

    monkeypatch.setattr(main.subprocess, "run", run)
    assert main.Supervisor().stop_local({
        "path": str(path),
        "require_path": True,
    }) == {"status": "stopped", "pid": None}


def test_foreign_pidfile_cleanup_preserves_matching_and_unparseable_files(tmp_path):
    path = tmp_path / "branch"
    path.mkdir()
    pidfile = path / "postmaster.pid"

    pidfile.write_text("123\n")
    main._remove_foreign_postmaster_pidfile(path)
    assert pidfile.exists()

    pidfile.write_text(f"123\n{path.resolve()}\n")
    main._remove_foreign_postmaster_pidfile(path)
    assert pidfile.exists()


def test_start_local_fast_path_skips_status_and_password_reconciliation(tmp_path, monkeypatch):
    path = tmp_path / "branch"
    path.mkdir()
    (path / "PG_VERSION").write_text("14\n")

    monkeypatch.setattr(main, "alive", lambda pid: True)
    monkeypatch.setattr(
        main.Supervisor,
        "_cluster_is_running",
        lambda *args, **kwargs: pytest.fail("status check should not run on the fast path"),
    )
    monkeypatch.setattr(
        main,
        "subprocess",
        type(
            "Subprocess",
            (),
            {"run": staticmethod(lambda *args, **kwargs: pytest.fail("pg_ctl should not run on the fast path"))},
        ),
    )

    class FakePsycopg:
        def connect(self, **kwargs):
            pytest.fail("password reconciliation should not run on the fast path")

    monkeypatch.setattr(main, "psycopg", FakePsycopg())
    result = main.Supervisor().start_local({
        "path": str(path),
        "branch_id": "br",
        "port": 55432,
        "host_id": "local",
        "pid": 123,
        "status": "running",
        "password": "secret",
        "parent_passwords": [],
    })
    assert result == {"status": "running", "pid": 123}


def test_start_local_requires_cluster_directory(tmp_path):
    with pytest.raises(RuntimeError, match="no PostgreSQL cluster"):
        main.Supervisor().start_local({
            "path": str(tmp_path / "missing"),
            "branch_id": "br",
            "port": 55432,
            "host_id": "local",
            "pid": None,
            "status": "stopped",
            "password": "secret",
            "parent_passwords": [],
        })


def test_promotion_requires_ready_replica_and_fresh_lag(client, monkeypatch):
    created, database = promotion_database(
        client, monkeypatch, replica_status="building", lag_bytes=42
    )
    response = client.post(
        f"/v1/admin/databases/{database['id']}/promote",
        headers={"X-Admin-Key": "test-admin"},
        json={"host_id": "sv2"},
    )
    assert response.status_code == 409

    created, database = promotion_database(
        client, monkeypatch, replica_status="ready", lag_bytes=None
    )
    response = client.post(
        f"/v1/admin/databases/{database['id']}/promote",
        headers={"X-Admin-Key": "test-admin"},
        json={"host_id": "sv2"},
    )
    assert response.status_code == 409


def test_promotion_requires_admin(client, monkeypatch):
    created, database = promotion_database(client, monkeypatch)
    response = client.post(
        f"/v1/admin/databases/{database['id']}/promote",
        headers={"X-API-Key": created["api_key"]},
        json={"host_id": "sv2"},
    )
    assert response.status_code == 401


def test_promotion_fences_before_promoting_and_rebuilds_replicas(client, monkeypatch):
    _, database = promotion_database(client, monkeypatch)
    c = main.db()
    old_path = Path(c.execute(
        "SELECT path FROM branches WHERE database_id=? AND name='main'",
        (database["id"],),
    ).fetchone()["path"])
    c.close()
    calls = []

    class Transport:
        def call(self, host_id, operation, payload):
            calls.append((host_id, operation))
            assert main._branch_mutation_lock.locked()
            if operation == "promote_standby":
                return {"status": "promoted", "pid": 222, "port": payload["target_port"]}
            if operation == "stop":
                return {"status": "stopped", "pid": None}
            if operation == "destroy":
                shutil.rmtree(payload["path"])
                return {"status": "destroyed"}
            raise AssertionError(operation)

    monkeypatch.setattr(main, "node_transport", Transport())
    response = client.post(
        f"/v1/admin/databases/{database['id']}/promote",
        headers={"X-Admin-Key": "test-admin"},
        json={"host_id": "sv2"},
    )
    assert response.status_code == 200
    assert calls == [
        ("local", "stop"),
        ("sv2", "promote_standby"),
        ("local", "destroy"),
    ]
    assert not old_path.exists()
    c = main.db()
    try:
        main_row = c.execute(
            "SELECT host_id,path,port,status,pid FROM branches WHERE database_id=? AND name='main'",
            (database["id"],),
        ).fetchone()
        assert main_row["host_id"] == "sv2"
        assert main_row["path"].endswith("/.replicas/sv2")
        assert (main_row["port"], main_row["status"], main_row["pid"]) == (
            response.json()["port"],
            "running",
            222,
        )
        replicas = c.execute(
            "SELECT host_id,status FROM replicas WHERE database_id=? ORDER BY host_id",
            (database["id"],),
        ).fetchall()
        assert [(row["host_id"], row["status"]) for row in replicas] == [
            ("local", "rebuild_required"),
            ("sv3", "rebuild_required"),
        ]
        assert c.execute(
            "SELECT 1 FROM abandoned_clusters WHERE database_id=?",
            (database["id"],),
        ).fetchone() is None
        audit_row = c.execute(
            "SELECT action,actor,details FROM audit_log WHERE action='database.promoted' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert audit_row["actor"] == "admin"
        details = main.json.loads(audit_row["details"])
        assert details["promoted_host"] == "sv2"
        assert details["lag_bytes"] == 42
        assert details["fence"] == "reachable and stopped"
    finally:
        c.close()


def test_promotion_requires_force_when_old_primary_unreachable(client, monkeypatch):
    _, database = promotion_database(client, monkeypatch)
    calls = []

    class Transport:
        def call(self, host_id, operation, payload):
            calls.append((host_id, operation))
            if operation == "stop":
                raise RuntimeError("old host unavailable")
            return {"status": "promoted", "pid": 222, "port": payload["target_port"]}

    monkeypatch.setattr(main, "node_transport", Transport())
    endpoint = f"/v1/admin/databases/{database['id']}/promote"
    response = client.post(
        endpoint,
        headers={"X-Admin-Key": "test-admin"},
        json={"host_id": "sv2"},
    )
    assert response.status_code == 409
    assert calls == [("local", "stop")]
    response = client.post(
        endpoint,
        headers={"X-Admin-Key": "test-admin"},
        json={"host_id": "sv2", "force": True},
    )
    assert response.status_code == 200
    assert calls == [
        ("local", "stop"),
        ("local", "stop"),
        ("sv2", "promote_standby"),
    ]
    c = main.db()
    try:
        abandoned = c.execute(
            "SELECT host_id,path,port FROM abandoned_clusters WHERE database_id=?",
            (database["id"],),
        ).fetchone()
        assert abandoned["host_id"] == "local"
        audit_row = c.execute(
            "SELECT details FROM audit_log WHERE action='database.promoted' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        details = main.json.loads(audit_row["details"])
        assert details["abandoned"]["path"] == abandoned["path"]
    finally:
        c.close()


def test_promotion_failure_after_fencing_commits_stopped_ledger_and_audit(client, monkeypatch):
    _, database = promotion_database(client, monkeypatch)
    c = main.db()
    secret = main.cipher().decrypt(
        c.execute(
            "SELECT credential_encrypted FROM branches WHERE database_id=? AND name='main'",
            (database["id"],),
        ).fetchone()["credential_encrypted"].encode()
    ).decode()
    c.close()

    class Transport:
        def call(self, host_id, operation, payload):
            if operation == "stop":
                return {"status": "stopped", "pid": None}
            if operation == "promote_standby":
                raise RuntimeError(f"promotion timeout password={secret}")
            raise AssertionError(operation)

    monkeypatch.setattr(main, "node_transport", Transport())
    response = client.post(
        f"/v1/admin/databases/{database['id']}/promote",
        headers={"X-Admin-Key": "test-admin"},
        json={"host_id": "sv2"},
    )
    assert response.status_code == 503
    assert secret not in response.text
    c = main.db()
    try:
        row = c.execute(
            "SELECT status,pid FROM branches WHERE database_id=? AND name='main'",
            (database["id"],),
        ).fetchone()
        assert (row["status"], row["pid"]) == ("stopped", None)
        actions = [
            item["action"]
            for item in c.execute(
                "SELECT action FROM audit_log ORDER BY id DESC LIMIT 2"
            ).fetchall()
        ]
        assert "database.promotion_fenced" in actions
        assert "database.promotion_failed" in actions
    finally:
        c.close()


def test_promotion_fence_checks_live_cluster_not_recorded_pid(client, monkeypatch):
    _, database = promotion_database(client, monkeypatch)
    c = main.db()
    c.execute(
        "UPDATE branches SET pid=NULL WHERE database_id=? AND name='main'",
        (database["id"],),
    )
    c.commit()
    c.close()
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if argv[-1] == "status":
            return None
        return None

    monkeypatch.setattr(main.subprocess, "run", run)

    class Transport:
        def call(self, host_id, operation, payload):
            if operation == "stop":
                return main.Supervisor().stop_local(payload)
            if operation == "promote_standby":
                raise AssertionError("promotion must not run while primary is live")
            raise AssertionError(operation)

    monkeypatch.setattr(main, "node_transport", Transport())
    response = client.post(
        f"/v1/admin/databases/{database['id']}/promote",
        headers={"X-Admin-Key": "test-admin"},
        json={"host_id": "sv2"},
    )
    assert response.status_code == 409
    assert any(call[-1] == "status" for call in calls)
    assert not any(call[-1] == "promote_standby" for call in calls)


def test_promotion_is_idempotent_when_main_already_on_target(client, monkeypatch):
    _, database = promotion_database(client, monkeypatch)
    c = main.db()
    main_row = c.execute(
        "SELECT * FROM branches WHERE database_id=? AND name='main'",
        (database["id"],),
    ).fetchone()
    target_path = Path(main_row["path"]).parent / ".replicas" / "sv2"
    c.execute(
        "UPDATE branches SET host_id='sv2',path=?,port=55433,status='running',pid=222 WHERE id=?",
        (str(target_path), main_row["id"]),
    )
    c.execute("DELETE FROM replicas WHERE database_id=?", (database["id"],))
    c.commit()
    c.close()
    calls = []

    class Transport:
        def call(self, host_id, operation, payload):
            calls.append((host_id, operation))
            return {"status": "promoted", "pid": 222, "port": 55433}

    monkeypatch.setattr(main, "node_transport", Transport())
    response = client.post(
        f"/v1/admin/databases/{database['id']}/promote",
        headers={"X-Admin-Key": "test-admin"},
        json={"host_id": "sv2"},
    )
    assert response.status_code == 200
    assert calls == [("sv2", "promote_standby")]


def test_already_primary_promotion_reports_bad_credentials_as_503(client, monkeypatch):
    _, database = promotion_database(client, monkeypatch)
    c = main.db()
    c.execute(
        "UPDATE branches SET credential_encrypted=? WHERE database_id=? AND name='main'",
        ("not-a-fernet-token", database["id"]),
    )
    c.commit()
    c.close()
    response = client.post(
        f"/v1/admin/databases/{database['id']}/promote",
        headers={"X-Admin-Key": "test-admin"},
        json={"host_id": "local"},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "primary credentials cannot be decrypted"


def test_promotion_refuses_absent_old_primary_without_force(client, monkeypatch):
    _, database = promotion_database(client, monkeypatch)
    c = main.db()
    main_path = Path(
        c.execute(
            "SELECT path FROM branches WHERE database_id=? AND name='main'",
            (database["id"],),
        ).fetchone()["path"]
    )
    c.close()
    shutil.rmtree(main_path)
    calls = []

    class Transport:
        def call(self, host_id, operation, payload):
            calls.append((host_id, operation, payload))
            if operation == "stop":
                return main.Supervisor().stop_local(payload)
            raise AssertionError("promotion must not run")

    monkeypatch.setattr(main, "node_transport", Transport())
    response = client.post(
        f"/v1/admin/databases/{database['id']}/promote",
        headers={"X-Admin-Key": "test-admin"},
        json={"host_id": "sv2"},
    )
    assert response.status_code == 409
    assert calls[0][1] == "stop"
    assert calls[0][2]["require_path"] is True


def test_strict_stop_refuses_unusable_cluster_directory_but_lenient_stop_succeeds(tmp_path, monkeypatch):
    path = tmp_path / "not-a-cluster"
    path.mkdir()

    def run(argv, **kwargs):
        raise subprocess.CalledProcessError(
            4,
            argv,
            stderr='pg_ctl: directory is not a database cluster directory',
        )

    monkeypatch.setattr(main.subprocess, "run", run)
    supervisor = main.Supervisor()
    assert supervisor.stop_local({"path": str(path)}) == {"status": "stopped", "pid": None}
    with pytest.raises(RuntimeError, match="not a usable cluster"):
        supervisor.stop_local({"path": str(path), "require_path": True})


def test_standby_teardown_accepts_absent_empty_and_noncluster_targets(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    agent = main.NodeAgent(
        lambda argv, env=None: (_ for _ in ()).throw(
            subprocess.CalledProcessError(
                4, argv, stderr="pg_ctl: directory is not a database cluster directory"
            )
        )
    )
    assert agent._standby_status_is_not_running(root / "absent")
    empty = root / "empty"
    empty.mkdir()
    assert agent._standby_status_is_not_running(empty)
    noncluster = root / "noncluster"
    noncluster.mkdir()
    (noncluster / "postgresql.conf").write_text("")
    assert agent._standby_status_is_not_running(noncluster)


def test_standby_teardown_accepts_stale_and_recycled_pids(tmp_path, monkeypatch):
    target = tmp_path / "standby"
    target.mkdir()
    (target / "PG_VERSION").write_text("17\n")
    (target / "postmaster.pid").write_text("123\n")

    def run(argv, env=None):
        raise subprocess.CalledProcessError(
            4, argv, stderr="pg_ctl: could not read status"
        )

    agent = main.NodeAgent(run)
    monkeypatch.setattr(main, "alive", lambda pid: False)
    assert agent._standby_status_is_not_running(target)
    monkeypatch.setattr(main, "alive", lambda pid: True)
    monkeypatch.setattr(main, "_pid_owns_postgres_directory", lambda pid, path: False)
    assert agent._standby_status_is_not_running(target)


def test_standby_teardown_refuses_live_postmaster_and_reports_pgctl_stderr(
    tmp_path, monkeypatch
):
    target = tmp_path / "standby"
    target.mkdir()
    (target / "PG_VERSION").write_text("17\n")
    (target / "postmaster.pid").write_text("123\n")

    def run(argv, env=None):
        raise subprocess.CalledProcessError(
            4, argv, stderr="pg_ctl: status could not classify cluster"
        )

    monkeypatch.setattr(main, "alive", lambda pid: True)
    monkeypatch.setattr(main, "_pid_owns_postgres_directory", lambda pid, path: True)
    agent = main.NodeAgent(run)
    assert not agent._standby_status_is_not_running(target)


def test_recycled_pid_does_not_look_like_running_postmaster(tmp_path, monkeypatch):
    target = tmp_path / "standby"
    target.mkdir()
    (target / "PG_VERSION").write_text("17\n")
    (target / "postmaster.pid").write_text("456\n")
    monkeypatch.setattr(main, "alive", lambda pid: True)
    monkeypatch.setattr(main, "_pid_owns_postgres_directory", lambda pid, path: False)
    agent = main.NodeAgent(
        lambda argv, env=None: (_ for _ in ()).throw(
            subprocess.CalledProcessError(4, argv, stderr="unclassified status")
        )
    )
    assert agent._standby_status_is_not_running(target)


def test_live_pid_owned_by_working_directory_is_running(tmp_path, monkeypatch):
    target = tmp_path / "standby"
    target.mkdir()
    monkeypatch.setattr(
        main,
        "_pid_process_evidence",
        lambda pid: (["postgres"], target),
    )
    assert main._pid_owns_postgres_directory(123, target)


def test_live_pid_without_ownership_evidence_is_ambiguous(tmp_path, monkeypatch):
    target = tmp_path / "standby"
    target.mkdir()
    monkeypatch.setattr(
        main,
        "_pid_process_evidence",
        lambda pid: ([], None),
    )
    with pytest.raises(RuntimeError, match="cannot determine"):
        main._pid_owns_postgres_directory(123, target)


def test_strict_pgctl_failure_includes_stderr(tmp_path, monkeypatch):
    path = tmp_path / "cluster"
    path.mkdir()

    def run(argv, **kwargs):
        raise subprocess.CalledProcessError(
            4, argv, stderr="pg_ctl: status output detail"
        )

    monkeypatch.setattr(main.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="status output detail"):
        main.Supervisor().stop_local({"path": str(path), "require_path": True})


def test_standby_build_stops_before_removing_target(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    target = root / "standby"
    target.mkdir()
    (target / "postmaster.pid").write_text("123\n")
    calls = []

    def run(argv, env=None):
        calls.append(argv)
        if argv[-1] == "status":
            raise RuntimeError("stale postmaster")
        if argv[0] == main.pg_bin("pg_basebackup"):
            raise RuntimeError("backup failed")

    agent = main.NodeAgent(run)
    agent.handle("build_standby", {
        "target_path": str(target),
        "target_port": 55433,
        "target_host_id": "local",
        "primary_address": "127.0.0.1",
        "primary_port": 55432,
        "replication_user": "mosaic_repl_db",
        "replication_password": "secret",
    })
    for _ in range(100):
        result = agent.handle("inspect_standby", {"target_path": str(target)})
        if result["status"] == "failed":
            break
        time.sleep(0.01)
    assert result["status"] == "failed"
    assert calls[1] == [
        main.pg_bin("pg_ctl"), "-D", str(target), "-m", "immediate", "stop"
    ]
    assert calls[2][0] == main.pg_bin("pg_basebackup")
    assert not target.exists()


def test_standby_build_does_not_remove_live_target_after_failed_stop(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    target = root / "standby"
    target.mkdir()
    (target / "postmaster.pid").write_text("123\n")
    calls = []

    def run(argv, env=None):
        calls.append(argv)
        if argv[-1] == "status":
            raise RuntimeError("standby status unavailable")
        if argv[-3:] == ["-m", "immediate", "stop"]:
            raise RuntimeError("permission denied")

    monkeypatch.setattr(main, "alive", lambda pid: pid == 123)
    monkeypatch.setattr(main, "_pid_owns_postgres_directory", lambda pid, path: True)
    agent = main.NodeAgent(run)
    assert agent.handle("build_standby", {
        "target_path": str(target),
        "target_port": 55433,
        "target_host_id": "local",
        "primary_address": "127.0.0.1",
        "primary_port": 55432,
        "replication_user": "mosaic_repl_db",
        "replication_password": "secret",
    }) == {"status": "building"}
    for _ in range(100):
        result = agent.handle("inspect_standby", {"target_path": str(target)})
        if result["status"] == "failed":
            break
        time.sleep(0.01)
    assert result["status"] == "failed"
    assert target.exists()
    assert (target / "postmaster.pid").exists()
    assert not any(call[0] == main.pg_bin("pg_basebackup") for call in calls)


def test_standby_build_cleans_unparseable_stopped_target(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    target = root / "standby"
    target.mkdir()
    (target / "postmaster.pid").write_text("")
    def run(argv, env=None):
        if argv[-1] == "status":
            return None
        if argv[0] == main.pg_bin("pg_basebackup"):
            target.mkdir(parents=True, exist_ok=True)
            (target / "postgresql.conf").write_text("")
            (target / "pg_hba.conf").write_text("")

    agent = main.NodeAgent(run)
    initial = agent.handle("build_standby", {
        "target_path": str(target),
        "target_port": 55433,
        "target_host_id": "local",
        "primary_address": "127.0.0.1",
        "primary_port": 55432,
        "replication_user": "mosaic_repl_db",
        "replication_password": "secret",
    })
    assert initial in ({"status": "building"}, {"status": "ready"})
    if initial == {"status": "ready"}:
        result = initial
    else:
        result = None
    for _ in range(100):
        if result is None:
            result = agent.handle("inspect_standby", {"target_path": str(target)})
            if result["status"] == "ready":
                break
            time.sleep(0.01)
    assert result == {"status": "ready"}


def test_copy_clone_passes_password_per_command_without_mutating_environment(tmp_path, monkeypatch):
    parent = tmp_path / "parent"
    target = tmp_path / "target"
    parent.mkdir()
    calls = []

    monkeypatch.delenv("PGPASSWORD", raising=False)
    monkeypatch.setattr(main, "_checkpoint", lambda *args: None)

    def run(argv, env=None):
        calls.append((argv, env))
        assert os.environ.get("PGPASSWORD") is None

    main.CopyBranchEngine(run).clone(
        parent,
        target,
        parent_port=55432,
        parent_password="parent-secret",
    )
    assert calls[0][1] == {"PGPASSWORD": "parent-secret"}
    assert os.environ.get("PGPASSWORD") is None


def test_replica_build_failure_does_not_downgrade_ready_sibling(client, monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local,sv2,sv3")
    monkeypatch.setenv(
        "MOSAIC_NODE_PRIVATE_ADDRESSES",
        "local=10.0.0.1,sv2=10.0.0.2,sv3=10.0.0.3",
    )
    created = tenant(client)

    class FakeTransport:
        failure_host = None

        def call(self, host_id, operation, payload):
            if operation == "provision":
                return {"status": "provisioned"}
            if operation == "start":
                return {"status": "running", "pid": 123}
            if operation == "prepare_primary":
                return {"status": "running", "pid": 123}
            if operation == "build_standby" and host_id == self.failure_host:
                raise subprocess.CalledProcessError(1, "pg_basebackup", stderr="bad backup")
            if operation == "build_standby":
                return {"status": "ready"}
            raise AssertionError(operation)

    monkeypatch.setattr(main, "node_transport", FakeTransport())
    response = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "sibling-failure"},
    )
    c = main.db()
    replica_hosts = [
        row["host_id"] for row in c.execute(
            "SELECT host_id FROM replicas WHERE database_id=?",
            (response.json()["id"],),
        ).fetchall()
    ]
    FakeTransport.failure_host = replica_hosts[0]
    main.reconcile_replicas(c)
    statuses = {
        row["host_id"]: row["status"]
        for row in c.execute(
            "SELECT host_id,status FROM replicas WHERE database_id=?",
            (response.json()["id"],),
        ).fetchall()
    }
    assert statuses[FakeTransport.failure_host] == "retryable"
    assert all(
        status == "ready"
        for host, status in statuses.items()
        if host != FakeTransport.failure_host
    )
    c.close()


def test_reconciler_starts_stopped_primary_before_building_standbys(client, monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local,sv2")
    monkeypatch.setenv("MOSAIC_NODE_PRIVATE_ADDRESSES", "local=10.0.0.1,sv2=10.0.0.2")
    created = tenant(client)
    calls = []

    class FakeTransport:
        def call(self, host_id, operation, payload):
            calls.append(operation)
            if operation == "provision":
                return {"status": "provisioned"}
            if operation == "start":
                return {"status": "running", "pid": 321}
            if operation == "prepare_primary":
                return {"status": "running", "pid": 321}
            if operation == "build_standby":
                return {"status": "ready"}
            raise AssertionError(operation)

    monkeypatch.setattr(main, "node_transport", FakeTransport())
    response = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "starts-primary"},
    )
    c = main.db()
    main.reconcile_replicas(c)
    assert calls.index("start") < calls.index("build_standby")
    assert c.execute(
        "SELECT status,pid FROM branches WHERE database_id=? AND name='main'",
        (response.json()["id"],),
    ).fetchone()["status"] == "running"
    c.close()


def test_ready_replica_with_stopped_cluster_requires_rebuild(client, monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local,sv2")
    monkeypatch.setenv("MOSAIC_NODE_PRIVATE_ADDRESSES", "local=10.0.0.1,sv2=10.0.0.2")
    created = tenant(client)

    class FakeTransport:
        def call(self, host_id, operation, payload):
            if operation == "provision":
                return {"status": "provisioned"}
            if operation == "start":
                return {"status": "running", "pid": 321}
            if operation == "inspect_standby":
                return {"status": "failed", "error": "standby postmaster is not running"}
            raise AssertionError(operation)

    monkeypatch.setattr(main, "node_transport", FakeTransport())
    response = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "missing-standby"},
    )
    c = main.db()
    c.execute(
        "UPDATE replicas SET status='ready',lag_bytes=0,lag_sampled_at=? WHERE database_id=?",
        (main.now(), response.json()["id"]),
    )
    c.commit()
    main.reconcile_replicas(c)
    assert all(
        row["status"] == "rebuild_required"
        for row in c.execute(
            "SELECT status FROM replicas WHERE database_id=?",
            (response.json()["id"],),
        ).fetchall()
    )
    c.close()


@pytest.mark.parametrize("failure", ["transport", "primary"])
def test_ready_replica_stays_ready_on_inconclusive_or_primary_failure(client, monkeypatch, failure):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local,sv2")
    monkeypatch.setenv("MOSAIC_NODE_PRIVATE_ADDRESSES", "local=10.0.0.1,sv2=10.0.0.2")
    created = tenant(client)

    class FakeTransport:
        def call(self, host_id, operation, payload):
            if operation == "provision":
                return {"status": "provisioned"}
            if operation == "start":
                raise RuntimeError("primary unavailable")
            if operation == "inspect_standby":
                if failure == "transport":
                    raise RuntimeError("standby unavailable")
                return {"status": "failed", "error": "probe inconclusive"}
            raise AssertionError(operation)

    monkeypatch.setattr(main, "node_transport", FakeTransport())
    response = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers={"X-API-Key": created["api_key"]},
        json={"name": f"ready-{failure}"},
    )
    c = main.db()
    c.execute(
        "UPDATE replicas SET status='ready',lag_bytes=0,lag_sampled_at=? WHERE database_id=?",
        (main.now(), response.json()["id"]),
    )
    c.commit()
    main.reconcile_replicas(c)
    assert all(
        row["status"] == "ready"
        for row in c.execute(
            "SELECT status FROM replicas WHERE database_id=?",
            (response.json()["id"],),
        ).fetchall()
    )
    c.close()


def test_replica_directories_are_reserved_outside_branch_namespace(client, monkeypatch):
    created = tenant(client)
    database = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "reserved-path"},
    ).json()
    response = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/branches",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "replicas"},
    )
    assert response.status_code == 400
    c = main.db()
    main_row = c.execute(
        "SELECT * FROM branches WHERE database_id=? AND name='main'",
        (database["id"],),
    ).fetchone()
    assert Path(main_row["path"]).parent / ".replicas" != Path(main_row["path"]).parent / "replicas"
    c.close()


def test_https_transport_always_uses_verifying_context(monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "sv2=https://10.0.0.2:8000")
    monkeypatch.setenv("MOSAIC_NODE_PRIVATE_ADDRESSES", "sv2=10.0.0.2")
    monkeypatch.setattr(main, "NODE_AGENT_CA_BUNDLE", "")
    contexts = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"status":"ok"}'

    monkeypatch.setattr(
        main.ssl, "create_default_context",
        lambda **kwargs: contexts.append(kwargs) or object(),
    )
    monkeypatch.setattr(main.urllib.request, "urlopen", lambda request, timeout, context: Response())
    assert main.NodeTransport(main.NodeAgent()).call("sv2", "inspect", {}) == {"status": "ok"}
    assert contexts == [{"cafile": None}]


def test_reaper_ignores_standbys(tmp_path, monkeypatch):
    main.DB_PATH = tmp_path / "reaper-replica.db"
    c = main.db()
    main.initialize_schema(c)
    c.execute("INSERT INTO tenants(id,name,plan,api_key_hash,status,created_at) VALUES(?,?,?,?,?,?)", ("ten_r", "r", "shared", "h", "active", main.now()))
    c.execute("INSERT INTO databases VALUES(?,?,?,?,?,?)", ("db_r", "ten_r", "r", str(tmp_path), "ready", main.now()))
    old = "2000-01-01T00:00:00+00:00"
    c.execute("INSERT INTO branches VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", ("br_r", "db_r", "main", None, str(tmp_path / "main"), 55432, 123, "running", "x", old, old, "local"))
    c.execute("INSERT INTO branches VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", ("br_e", "db_r", "ephemeral", None, str(tmp_path / "ephemeral"), 55436, 124, "running", "x", old, old, "local"))
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
    assert c.execute("SELECT status FROM branches WHERE id='br_r'").fetchone()["status"] == "running"
    assert c.execute("SELECT status FROM branches WHERE id='br_e'").fetchone()["status"] == "stopped"
    assert c.execute("SELECT status FROM replicas").fetchone()["status"] == "ready"
    c.close()


def test_supervisor_reaper_skips_replicated_primary(tmp_path, monkeypatch):
    main.DB_PATH = tmp_path / "supervisor-reaper-replica.db"
    c = main.db()
    main.initialize_schema(c)
    c.execute("INSERT INTO tenants(id,name,plan,api_key_hash,status,created_at) VALUES(?,?,?,?,?,?)", ("ten_r", "r", "shared", "h", "active", main.now()))
    c.execute("INSERT INTO databases VALUES(?,?,?,?,?,?)", ("db_r", "ten_r", "r", str(tmp_path), "ready", main.now()))
    old = "2000-01-01T00:00:00+00:00"
    for branch_id, name in (("br_r", "main"), ("br_e", "ephemeral")):
        c.execute(
            "INSERT INTO branches VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (branch_id, "db_r", name, None, str(tmp_path / name), 55432 if name == "main" else 55436,
             123, "running", "x", old, old, "local"),
        )
    c.execute(
        "INSERT INTO replicas(id,database_id,primary_branch_id,host_id,path,port,status,lag_bytes,lag_sampled_at,created_at,slot_name) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("rep_r", "db_r", "br_r", "sv2", str(tmp_path / "standby"), 55433, "ready", 0, old, old, "slot_r"),
    )
    c.commit()
    stopped = []
    supervisor = main.Supervisor()
    monkeypatch.setattr(
        supervisor,
        "stop",
        lambda row, connection: stopped.append(row["id"]) or {"status": "stopped", "pid": None},
    )
    assert supervisor.reap(c, idle_seconds=1) == 1
    assert stopped == ["br_e"]
    assert c.execute("SELECT status FROM branches WHERE id='br_r'").fetchone()["status"] == "running"
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
    c.execute(
        "UPDATE branches SET host_id='local',status='running',pid=123 WHERE id=?",
        (main_row["id"],),
    )
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
            return {
                "sampled_at": "2025-01-01T00:00:00+00:00",
                "replicas": [{"client_addr": "10.0.0.2/32", "lag_bytes": 42}],
                "invalid_slots": ["slot_lag"],
            }

    monkeypatch.setattr(main, "node_transport", FakeTransport())
    response = client.get(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/replicas",
        headers={"X-API-Key": created["api_key"]},
    )
    assert response.status_code == 200
    assert response.json()["replicas"][0]["lag_bytes"] == 42
    assert response.json()["lag_unit"] == "bytes behind primary WAL replay position"
    fresh = main.db()
    try:
        row = fresh.execute(
            "SELECT lag_bytes,lag_sampled_at,status FROM replicas WHERE id=?",
            ("rep_lag",),
        ).fetchone()
        assert row["lag_bytes"] == 42
        assert row["lag_sampled_at"] == "2025-01-01T00:00:00+00:00"
        assert row["status"] == "rebuild_required"
    finally:
        fresh.close()


def test_local_primary_down_lag_sample_is_reported(client, monkeypatch):
    created = tenant(client)
    database = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "local-lag-down"},
    ).json()
    c = main.db()
    primary = c.execute(
        "SELECT * FROM branches WHERE database_id=?", (database["id"],)
    ).fetchone()
    c.execute(
        "INSERT INTO replication_credentials VALUES(?,?,?,?)",
        (database["id"], "mosaic_repl_down", main.cipher().encrypt(b"repl").decode(), main.now()),
    )
    c.execute(
        "INSERT INTO replicas(id,database_id,primary_branch_id,host_id,path,port,status,lag_bytes,lag_sampled_at,created_at,slot_name) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("rep_down", database["id"], primary["id"], "local", "/standby", 55433, "ready", 0, main.now(), main.now(), "slot_down"),
    )
    c.commit()
    c.close()

    operational_error = type("OperationalError", (Exception,), {})

    class FailedPsycopg:
        OperationalError = operational_error

        def connect(self, **kwargs):
            raise self.OperationalError("server is down")

    monkeypatch.setattr(main, "psycopg", FailedPsycopg())
    response = client.get(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/replicas",
        headers={"X-API-Key": created["api_key"]},
    )
    assert response.status_code == 200
    assert response.json()["lag_sample_error"] == "replication lag sampling failed"


def test_removed_replica_host_lag_sample_is_reported(client, monkeypatch):
    created = tenant(client)
    database = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "removed-replica-host"},
    ).json()
    c = main.db()
    primary = c.execute(
        "SELECT * FROM branches WHERE database_id=?", (database["id"],)
    ).fetchone()
    c.execute(
        "UPDATE branches SET status='running',pid=123 WHERE id=?",
        (primary["id"],),
    )
    c.execute(
        "INSERT INTO replication_credentials VALUES(?,?,?,?)",
        (database["id"], "mosaic_repl_removed", main.cipher().encrypt(b"repl").decode(), main.now()),
    )
    for replica_id, host_id, slot_name in (
        ("rep_removed", "sv2", "slot_removed"),
        ("rep_healthy", "sv3", "slot_healthy"),
    ):
        c.execute(
            "INSERT INTO replicas(id,database_id,primary_branch_id,host_id,path,port,status,lag_bytes,lag_sampled_at,created_at,slot_name) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (replica_id, database["id"], primary["id"], host_id, f"/{replica_id}", 55433 + (host_id == "sv3"), "ready", 0, main.now(), main.now(), slot_name),
        )
    c.commit()
    c.close()
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "local,sv3")
    monkeypatch.setenv(
        "MOSAIC_NODE_PRIVATE_ADDRESSES",
        "local=10.0.0.1,sv3=10.0.0.3",
    )
    monkeypatch.setattr(
        main, "node_transport",
        type("Transport", (), {
            "call": lambda self, *args, **kwargs: {
                "sampled_at": "2025-01-01T00:00:00+00:00",
                "replicas": [{"client_addr": "10.0.0.3", "lag_bytes": 42}],
            }
        })(),
    )
    response = client.get(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/replicas",
        headers={"X-API-Key": created["api_key"]},
    )
    assert response.status_code == 200
    replicas = {row["host_id"]: row for row in response.json()["replicas"]}
    assert replicas["sv3"]["lag_bytes"] == 42
    assert replicas["sv2"]["last_error"].startswith("replica host unavailable:")


def test_plaintext_remote_transport_requires_opt_out(monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "sv2=http://10.0.0.2:8000")
    monkeypatch.setattr(main, "ALLOW_PLAINTEXT_NODE_AGENT", False)
    with pytest.raises(RuntimeError, match="plaintext node-agent transport"):
        main.NodeTransport(main.NodeAgent()).call("sv2", "inspect", {})


def test_single_remote_node_is_not_adopted_as_local_identity(monkeypatch):
    monkeypatch.setenv("MOSAIC_NODE_HOSTS", "sv1=https://10.0.0.1:8000")
    monkeypatch.delenv("MOSAIC_NODE_ID", raising=False)
    calls = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return b'{"status": "ok"}'

    def urlopen(request, timeout, context):
        calls.append((request.full_url, timeout, context))
        return Response()

    monkeypatch.setattr(main.urllib.request, "urlopen", urlopen)
    assert main.current_node_id() == "local"
    assert main.NodeTransport(main.NodeAgent()).call("sv1", "inspect", {}) == {"status": "ok"}
    assert calls and calls[0][0] == "https://10.0.0.1:8000/internal/node/inspect"


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
            if operation == "start":
                return {"status": "running", "pid": 123}
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


def test_replication_loop_survives_ledger_connection_error(monkeypatch):
    calls = {"sleep": 0, "db": 0, "reconcile": 0}

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

    def fake_reconcile(connection):
        calls["reconcile"] += 1

    monkeypatch.setattr(main.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(main, "db", fake_db)
    monkeypatch.setattr(main, "reconcile_replicas", fake_reconcile)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(main._replication_loop())
    assert calls["db"] == 2
    assert calls["reconcile"] == 1


def test_replication_loop_invalid_interval_still_yields(monkeypatch):
    monkeypatch.setenv("MOSAIC_REPLICATION_RETRY_INTERVAL", "10s")
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
        asyncio.run(main._replication_loop())
    assert calls["sleep"] == 2


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
    }
    agent.handle("prepare_primary", payload)
    agent.handle("prepare_primary", payload)
    assert sum("ALTER ROLE" in query for query in calls) == 2
    assert not any("CREATE ROLE" in query for query in calls)
    assert f"max_slot_wal_keep_size = {main.REPLICATION_WAL_RETENTION_BYTES}B" in config.read_text()


def test_replication_identifiers_are_valid_and_database_specific():
    first = main.replication_identifier("db_Ab-cD", "sv2-west")
    second = main.replication_identifier("db_Ab-cE", "sv2-west")
    assert re.fullmatch(r"[a-z0-9_]+", first)
    assert len(first) <= 63
    assert first != second


def test_standby_build_clears_partial_target_before_backup(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    target = root / "standby"
    target.mkdir()
    (target / "partial").write_text("stale")
    seen = []

    def run(argv, env=None):
        if argv[0] == main.pg_bin("pg_basebackup"):
            seen.append(target.exists())
            raise RuntimeError("backup failed")

    agent = main.NodeAgent(run)
    assert agent.handle("build_standby", {
        "target_path": str(target),
        "target_port": 55433,
        "target_host_id": "local",
        "primary_address": "127.0.0.1",
        "primary_port": 55432,
        "replication_user": "mosaic_repl_db",
        "replication_password": "secret",
    }) == {"status": "building"}
    for _ in range(100):
        result = agent.handle("inspect_standby", {"target_path": str(target)})
        if result["status"] == "failed":
            break
        time.sleep(0.01)
    assert seen == [False]
    assert result["status"] == "failed"


def test_prepare_primary_refreshes_pid_after_restart(tmp_path, monkeypatch):
    root = tmp_path / "branches"
    root.mkdir()
    monkeypatch.setattr(main, "BRANCH_ROOT", root)
    primary = root / "primary"
    primary.mkdir()
    (primary / "postgresql.conf").write_text("listen_addresses = '10.0.0.2'\n")
    calls = []

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, query, params=None):
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
    monkeypatch.setattr(main.supervisor, "start_local", lambda payload: {"status": "running", "pid": 111})
    monkeypatch.setattr(main.supervisor, "_cluster_is_running", lambda path: True)

    def run(argv, env=None):
        calls.append(argv)
        if argv[-1] == "restart":
            (primary / "postmaster.pid").write_text("222\n")

    result = main.NodeAgent(run).handle("prepare_primary", {
        "path": str(primary),
        "port": 55432,
        "host_id": "local",
        "branch_id": "br",
        "pid": 111,
        "status": "running",
        "postgres_password": "postgres",
        "replication_user": "mosaic_repl",
        "replication_password": "secret",
        "replication_addresses": [],
    })
    assert result["pid"] == 222


def test_replica_retry_error_redacts_credentials(tmp_path):
    main.DB_PATH = tmp_path / "redaction.db"
    c = main.db()
    main.initialize_schema(c)
    c.execute(
        "INSERT INTO tenants(id,name,plan,api_key_hash,status,created_at) VALUES(?,?,?,?,?,?)",
        ("ten_redact", "redact", "shared", "h", "active", main.now()),
    )
    c.execute(
        "INSERT INTO databases VALUES(?,?,?,?,?,?)",
        ("db_redact", "ten_redact", "redact", str(tmp_path), "ready", main.now()),
    )
    c.execute(
        "INSERT INTO branches VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        ("br_redact", "db_redact", "main", None, str(tmp_path / "main"), 55432, None, "stopped", "x", main.now(), main.now(), "local"),
    )
    c.execute(
        "INSERT INTO replicas(id,database_id,primary_branch_id,host_id,path,port,status,lag_bytes,lag_sampled_at,created_at,slot_name) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("rep_redact", "db_redact", "br_redact", "sv2", str(tmp_path / "standby"), 55433, "pending", None, None, main.now(), "slot_redact"),
    )
    row = c.execute("SELECT * FROM replicas WHERE id=?", ("rep_redact",)).fetchone()
    main._retry_replica(c, row, RuntimeError("failed postgres=pg-secret replication=repl-secret"), ("pg-secret", "repl-secret"))
    stored = c.execute("SELECT last_error FROM replicas WHERE id=?", ("rep_redact",)).fetchone()["last_error"]
    assert "pg-secret" not in stored
    assert "repl-secret" not in stored
    assert "[REDACTED]" in stored
    c.close()


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


def _deploy_database(client, monkeypatch):
    created = tenant(client)

    class Transport:
        def call(self, host_id, operation, payload):
            if operation == "start":
                return {"status": "running", "pid": 1234}
            return {"status": "ready", "pid": None}

    monkeypatch.setattr(main, "node_transport", Transport())
    database = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "deployments"},
    ).json()
    branch = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/branches",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "verify"},
    ).json()
    return created, database, branch


def test_deploy_operations_compile_to_allowlisted_sql():
    operations = [
        main.CreateTableOperation(
            op="create_table",
            name="events",
            columns=[
                main.DeployColumn(name="id", type="bigint", pk=True, identity=True),
                main.DeployColumn(name="payload", type="jsonb", nullable=False),
                main.DeployColumn(name="at", type="timestamptz", default="now()"),
            ],
        ),
        main.AddColumnOperation(
            op="add_column",
            table="events",
            column=main.DeployColumn(name="actor", type="text"),
        ),
        main.CreateIndexOperation(op="create_index", table="events", columns=["at"]),
        main.AddConstraintOperation(
            op="add_constraint",
            table="events",
            kind="check",
            expression="jsonb_typeof(payload) = 'object'",
        ),
        main.RenameColumnOperation(op="rename_column", table="events", **{"from": "at", "to": "occurred_at"}),
        main.DropColumnOperation(op="drop_column", table="events", column="actor", confirm_destructive=True),
        main.DropTableOperation(op="drop_table", name="events", confirm_destructive=True),
    ]
    assert main.compile_deploy_operations(operations) == [
        'CREATE TABLE "events" ("id" bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, "payload" jsonb NOT NULL, "at" timestamptz DEFAULT now())',
        'ALTER TABLE "events" ADD COLUMN "actor" text',
        'CREATE INDEX "idx_events_at" ON "events" ("at")',
        'ALTER TABLE "events" ADD CONSTRAINT "ck_events_f24a821e55" CHECK (jsonb_typeof(payload) = \'object\')',
        'ALTER TABLE "events" RENAME COLUMN "at" TO "occurred_at"',
        'ALTER TABLE "events" DROP COLUMN "actor"',
        'DROP TABLE "events"',
    ]
    assert main.forbidden_sql("CREATE TABLE events (id bigint)") is not None
    with pytest.raises(Exception):
        main.DeployCreate.model_validate({
            "operations": [{
                "op": "create_table",
                "name": "events",
                "sql": "CREATE TABLE events (id bigint)",
                "columns": [{"name": "id", "type": "bigint"}],
            }]
        })


def test_main_deploy_requires_matching_successful_branch_deploy(client, monkeypatch):
    created, database, branch = _deploy_database(client, monkeypatch)
    headers = {"X-API-Key": created["api_key"]}
    operation = {
        "op": "create_table",
        "name": "events",
        "columns": [{"name": "id", "type": "bigint", "pk": True, "identity": True}],
    }
    branch_deploy = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys",
        headers=headers,
        json={"branch": branch["id"], "operations": [operation]},
    )
    assert branch_deploy.status_code == 201
    refused = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys",
        headers=headers,
        json={"branch": "main", "operations": [operation]},
    )
    assert refused.status_code == 400
    assert "requires a successful branch deploy" in refused.json()["detail"]
    c = main.db()
    try:
        c.execute("UPDATE deploy_requests SET status='applied',schema_version=1 WHERE id=?", (branch_deploy.json()["id"],))
        c.commit()
    finally:
        c.close()
    accepted = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys",
        headers=headers,
        json={"branch": "main", "source_deploy_id": branch_deploy.json()["id"], "operations": [operation]},
    )
    assert accepted.status_code == 201
    assert accepted.json()["status"] == "pending"


def test_destructive_deploy_guards(client, monkeypatch):
    created, database, branch = _deploy_database(client, monkeypatch)
    headers = {"X-API-Key": created["api_key"]}
    drop = {"op": "drop_table", "name": "events"}
    refused_confirmation = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys",
        headers=headers,
        json={"branch": branch["id"], "operations": [drop]},
    )
    assert refused_confirmation.status_code == 400
    assert "confirm_destructive" in refused_confirmation.json()["detail"]
    refused_main = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys",
        headers=headers,
        json={"branch": "main", "operations": [{**drop, "confirm_destructive": True}]},
    )
    assert refused_main.status_code == 400
    assert "not allowed on main" in refused_main.json()["detail"]


def test_deploy_quota_and_cross_tenant_scope(client, monkeypatch):
    created, database, _ = _deploy_database(client, monkeypatch)
    headers = {"X-API-Key": created["api_key"]}
    old_limit = main.PLANS["shared"]["max_deploy_operations"]
    main.PLANS["shared"]["max_deploy_operations"] = 1
    try:
        response = client.post(
            f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys",
            headers=headers,
            json={
                "operations": [
                    {"op": "create_table", "name": "a", "columns": [{"name": "id", "type": "bigint"}]},
                    {"op": "create_table", "name": "b", "columns": [{"name": "id", "type": "bigint"}]},
                ],
            },
        )
        assert response.status_code == 403
    finally:
        main.PLANS["shared"]["max_deploy_operations"] = old_limit
    other = tenant(client)
    response = client.post(
        f"/v1/tenants/{other['tenant_id']}/databases/{database['id']}/deploys",
        headers={"X-API-Key": other["api_key"]},
        json={"operations": [{"op": "create_table", "name": "x", "columns": [{"name": "id", "type": "bigint"}]}]},
    )
    assert response.status_code == 404


def test_deploy_apply_rolls_back_all_operations_on_failure(client, monkeypatch):
    created, database, branch = _deploy_database(client, monkeypatch)
    headers = {"X-API-Key": created["api_key"]}
    response = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys",
        headers=headers,
        json={
            "branch": branch["id"],
            "operations": [
                {"op": "create_table", "name": "events", "columns": [{"name": "id", "type": "bigint"}]},
                {"op": "add_column", "table": "events", "column": {"name": "id", "type": "text"}},
            ],
        },
    )
    deploy_id = response.json()["id"]
    class ProgrammingFailure(Exception):
        class Diag:
            message_primary = "column id already exists"
            message_hint = None
            statement_position = None
        diag = Diag()

    class Errors:
        ProgrammingError = ProgrammingFailure

    class Connection:
        def __init__(self):
            self.schema = []
        def execute(self, statement, params=()):
            if statement.startswith("SET "):
                return self
            if "ADD COLUMN" in statement:
                raise ProgrammingFailure("column id already exists")
            self.schema.append(statement)
            return self
        def commit(self):
            return None
        def rollback(self):
            self.schema.clear()
        def close(self):
            return None

    connection = Connection()
    class FakePsycopg:
        errors = Errors()
        def connect(self, **kwargs):
            return connection

    monkeypatch.setattr(main, "psycopg", FakePsycopg())
    c = main.db()
    try:
        main._begin_deploy(c, created["tenant_id"], deploy_id)
    finally:
        c.close()
    main._apply_deploy(deploy_id, created["tenant_id"])
    assert connection.schema == []
    final = client.get(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys/{deploy_id}",
        headers=headers,
    )
    assert final.json()["status"] == "failed"
    assert "column id already exists" in final.json()["error"]


def test_reaper_does_not_stop_branch_with_deploy_lock(tmp_path, monkeypatch):
    main.DB_PATH = tmp_path / "deploy-reaper.db"
    c = main.db()
    main.initialize_schema(c)
    c.execute("INSERT INTO tenants(id,name,plan,api_key_hash,status,created_at) VALUES(?,?,?,?,?,?)", ("ten_r", "r", "shared", "h", "active", main.now()))
    c.execute("INSERT INTO databases VALUES(?,?,?,?,?,?)", ("db_r", "ten_r", "r", str(tmp_path), "ready", main.now()))
    c.execute(
        "INSERT INTO branches VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        ("br_r", "db_r", "main", None, str(tmp_path / "main"), 55432, 123, "running", "x", "2000-01-01T00:00:00+00:00", "2000-01-01T00:00:00+00:00", "local"),
    )
    c.execute(
        "INSERT INTO deploy_requests(id,tenant_id,database_id,branch_id,operations,sql_preview,status,created_at) VALUES(?,?,?,?,?,?,?,?)",
        ("dep_r", "ten_r", "db_r", "br_r", "[]", "[]", "applying", main.now()),
    )
    c.execute("INSERT INTO deploy_locks VALUES(?,?,?)", ("br_r", "dep_r", main.now()))
    c.commit()
    class Transport:
        def call(self, *args, **kwargs):
            raise AssertionError("reaper tried to stop an applying deploy")
    monkeypatch.setattr(main, "node_transport", Transport())
    assert main.reap_branches(c) == 0
    c.close()


def test_deploy_check_grammar_rejects_unbounded_functions():
    for expression in (
        "pg_sleep(10) IS NULL",
        "pg_read_file('/etc/passwd') IS NOT NULL",
        "id = (SELECT 1)",
        "lower(name) = 'alice' AND id BETWEEN 1 AND 10",
    )[:2]:
        with pytest.raises(main.HTTPException):
            main.validate_check_expression(expression)
    main.validate_check_expression("lower(name) = 'alice' AND id BETWEEN 1 AND 10")
    main.validate_check_expression("(id IN (1, 2, 3) OR id IS NULL) AND NOT active = false")


def test_deploy_check_sql_is_reconstructed_from_validated_tokens():
    operations = [
        main.AddConstraintOperation(
            op="add_constraint",
            table="events",
            kind="check",
            expression="lower(name) = 'alice' AND id BETWEEN 1 AND 10",
        )
    ]
    assert main.compile_deploy_operations(operations) == [
        'ALTER TABLE "events" ADD CONSTRAINT "ck_events_0013468987" '
        "CHECK (lower(name) = 'alice' AND id BETWEEN 1 AND 10)"
    ]


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("label = 'a (b)'", "label = 'a (b)'"),
        ("label IN ('x, y')", "label IN('x, y')"),
        ("label = 'it''s'", "label = 'it''s'"),
    ],
)
def test_deploy_check_rendering_preserves_string_literals(expression, expected):
    compiled = main.compile_deploy_operations(
        [
            main.AddConstraintOperation(
                op="add_constraint",
                table="events",
                kind="check",
                expression=expression,
            )
        ]
    )[0]
    assert f"CHECK ({expected})" in compiled


def test_apply_retry_does_not_schedule_a_second_task(client, monkeypatch):
    created, database, branch = _deploy_database(client, monkeypatch)
    headers = {"X-API-Key": created["api_key"]}
    deploy = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys",
        headers=headers,
        json={
            "branch": branch["id"],
            "operations": [{"op": "create_table", "name": "events", "columns": [{"name": "id", "type": "bigint"}]}],
        },
    ).json()
    calls = []
    monkeypatch.setattr(main, "_apply_deploy", lambda deploy_id, tid: calls.append((deploy_id, tid)))
    path = f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys/{deploy['id']}/apply"
    first = client.post(path, headers=headers)
    second = client.post(path, headers=headers)
    assert first.status_code == 202
    assert second.status_code == 202
    assert calls == [(deploy["id"], created["tenant_id"])]


def test_apply_terminal_deploy_returns_conflict_and_runs_once(client, monkeypatch):
    created, database, branch = _deploy_database(client, monkeypatch)
    headers = {"X-API-Key": created["api_key"]}
    deploy = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys",
        headers=headers,
        json={
            "branch": branch["id"],
            "operations": [{"op": "create_table", "name": "events", "columns": [{"name": "id", "type": "bigint"}]}],
        },
    ).json()

    class Connection:
        def __init__(self):
            self.statements = []

        def execute(self, statement, params=()):
            self.statements.append(statement)
            return self

        def commit(self):
            return None

        def rollback(self):
            return None

        def close(self):
            return None

    connection = Connection()

    class FakePsycopg:
        def connect(self, **kwargs):
            return connection

    monkeypatch.setattr(main, "psycopg", FakePsycopg())
    path = f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys/{deploy['id']}/apply"
    first = client.post(path, headers=headers)
    second = client.post(path, headers=headers)
    assert first.status_code == 202
    assert second.status_code == 409
    assert connection.statements.count('CREATE TABLE "events" ("id" bigint)') == 1
    failed = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys",
        headers=headers,
        json={
            "branch": branch["id"],
            "operations": [{"op": "create_table", "name": "other", "columns": [{"name": "id", "type": "bigint"}]}],
        },
    ).json()
    c = main.db()
    c.execute("UPDATE deploy_requests SET status='failed' WHERE id=?", (failed["id"],))
    c.commit()
    c.close()
    failed_retry = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys/{failed['id']}/apply",
        headers=headers,
    )
    assert failed_retry.status_code == 409


def test_apply_early_return_closes_control_plane_connection(client, monkeypatch):
    created, database, branch = _deploy_database(client, monkeypatch)
    headers = {"X-API-Key": created["api_key"]}
    deploy = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys",
        headers=headers,
        json={
            "branch": branch["id"],
            "operations": [{"op": "create_table", "name": "events", "columns": [{"name": "id", "type": "bigint"}]}],
        },
    ).json()
    c = main.db()
    c.execute("UPDATE deploy_requests SET status='applied' WHERE id=?", (deploy["id"],))
    c.commit()
    c.close()
    original = main.db()

    class TrackingConnection:
        def __init__(self, connection):
            self.connection = connection
            self.closed = False

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def close(self):
            self.closed = True
            self.connection.close()

    tracked = TrackingConnection(original)
    monkeypatch.setattr(main, "db", lambda: tracked)
    main._apply_deploy(deploy["id"], created["tenant_id"])
    assert tracked.closed is True


def test_stranded_deploy_lease_is_recovered_and_branch_reaped(tmp_path, monkeypatch):
    main.DB_PATH = tmp_path / "lease-recovery.db"
    c = main.db()
    main.initialize_schema(c)
    c.execute("INSERT INTO tenants(id,name,plan,api_key_hash,status,created_at) VALUES(?,?,?,?,?,?)", ("ten_l", "l", "shared", "h", "active", main.now()))
    c.execute("INSERT INTO databases VALUES(?,?,?,?,?,?)", ("db_l", "ten_l", "l", str(tmp_path), "ready", main.now()))
    c.execute(
        "INSERT INTO branches VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        ("br_l", "db_l", "main", None, str(tmp_path / "main"), 55432, 123, "running", "x", "2000-01-01T00:00:00+00:00", "2000-01-01T00:00:00+00:00", "local"),
    )
    c.execute(
        "INSERT INTO deploy_requests(id,tenant_id,database_id,branch_id,operations,sql_preview,status,created_at) VALUES(?,?,?,?,?,?,?,?)",
        ("dep_l", "ten_l", "db_l", "br_l", "[]", "[]", "applying", main.now()),
    )
    c.execute("INSERT INTO deploy_locks VALUES(?,?,?)", ("br_l", "dep_l", "2000-01-01T00:00:00+00:00"))
    c.commit()
    assert main.reconcile_deploy_locks(c) == 1
    assert c.execute("SELECT status,error FROM deploy_requests WHERE id='dep_l'").fetchone()["status"] == "failed"
    assert c.execute("SELECT COUNT(*) AS n FROM deploy_locks").fetchone()["n"] == 0
    stopped = []
    class Transport:
        def call(self, host_id, operation, payload):
            stopped.append(operation)
            return {"status": "stopped", "pid": None}
    monkeypatch.setattr(main, "node_transport", Transport())
    assert main.reap_branches(c) == 1
    assert stopped == ["stop"]
    c.close()


def test_supervisor_reap_also_respects_deploy_lock(tmp_path, monkeypatch):
    main.DB_PATH = tmp_path / "supervisor-reaper.db"
    c = main.db()
    main.initialize_schema(c)
    c.execute("INSERT INTO tenants(id,name,plan,api_key_hash,status,created_at) VALUES(?,?,?,?,?,?)", ("ten_s", "s", "shared", "h", "active", main.now()))
    c.execute("INSERT INTO databases VALUES(?,?,?,?,?,?)", ("db_s", "ten_s", "s", str(tmp_path), "ready", main.now()))
    c.execute(
        "INSERT INTO branches VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        ("br_s", "db_s", "main", None, str(tmp_path / "main"), 55432, 123, "running", "x", "2000-01-01T00:00:00+00:00", "2000-01-01T00:00:00+00:00", "local"),
    )
    c.execute(
        "INSERT INTO deploy_requests(id,tenant_id,database_id,branch_id,operations,sql_preview,status,created_at) VALUES(?,?,?,?,?,?,?,?)",
        ("dep_s", "ten_s", "db_s", "br_s", "[]", "[]", "applying", main.now()),
    )
    c.execute("INSERT INTO deploy_locks VALUES(?,?,?)", ("br_s", "dep_s", main.now()))
    c.commit()
    monkeypatch.setattr(main.supervisor, "stop", lambda row, conn: pytest.fail("locked branch was reaped"))
    assert main.supervisor.reap(c, idle_seconds=1) == 0
    c.close()


def test_deploy_rest_applies_every_operation_and_branch_version(client, monkeypatch):
    created, database, branch = _deploy_database(client, monkeypatch)
    headers = {"X-API-Key": created["api_key"]}

    class Connection:
        def __init__(self):
            self.statements = []
        def execute(self, statement, params=()):
            self.statements.append(statement)
            return self
        def commit(self):
            return None
        def rollback(self):
            return None
        def close(self):
            return None

    connection = Connection()
    class FakePsycopg:
        def connect(self, **kwargs):
            return connection
    monkeypatch.setattr(main, "psycopg", FakePsycopg())
    operations = [
        {"op": "create_table", "name": "events", "columns": [{"name": "id", "type": "bigint"}]},
        {"op": "add_column", "table": "events", "column": {"name": "name", "type": "text"}},
        {"op": "create_index", "table": "events", "columns": ["name"]},
        {"op": "add_constraint", "table": "events", "kind": "check", "expression": "length(name) > 0"},
        {"op": "rename_column", "table": "events", "from": "name", "to": "label"},
        {"op": "drop_column", "table": "events", "column": "label", "confirm_destructive": True},
        {"op": "drop_table", "name": "events", "confirm_destructive": True},
    ]
    created_deploy = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys",
        headers=headers,
        json={"branch": branch["id"], "operations": operations, "idempotency_key": "all-ops"},
    )
    assert created_deploy.status_code == 201
    deploy_id = created_deploy.json()["id"]
    applied = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys/{deploy_id}/apply",
        headers=headers,
    )
    assert applied.status_code == 202
    fetched = client.get(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys/{deploy_id}",
        headers=headers,
    ).json()
    assert fetched["status"] == "applied"
    assert fetched["schema_version"] == 1
    assert all("SET " not in statement for statement in fetched["sql_preview"])
    assert any("CREATE TABLE" in statement for statement in connection.statements)


def test_deploy_branch_then_main_and_duplicate_is_200(client, monkeypatch):
    created, database, branch = _deploy_database(client, monkeypatch)
    headers = {"X-API-Key": created["api_key"]}
    class Connection:
        def execute(self, statement, params=()):
            return self
        def commit(self):
            return None
        def rollback(self):
            return None
        def close(self):
            return None
    class FakePsycopg:
        def connect(self, **kwargs):
            return Connection()
    monkeypatch.setattr(main, "psycopg", FakePsycopg())
    operation = {"op": "create_table", "name": "events", "columns": [{"name": "id", "type": "bigint"}]}
    branch_deploy = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys",
        headers=headers,
        json={"branch": branch["id"], "operations": [operation], "idempotency_key": "branch-once"},
    )
    deploy_id = branch_deploy.json()["id"]
    client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys/{deploy_id}/apply",
        headers=headers,
    )
    main_deploy = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys",
        headers=headers,
        json={"branch": "main", "source_deploy_id": deploy_id, "operations": [operation], "idempotency_key": "main-once"},
    )
    assert main_deploy.status_code == 201
    main_id = main_deploy.json()["id"]
    client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys/{main_id}/apply",
        headers=headers,
    )
    main_result = client.get(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys/{main_id}",
        headers=headers,
    ).json()
    assert main_result["status"] == "applied"
    assert main_result["schema_version"] == 1
    duplicate = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys",
        headers=headers,
        json={"branch": "main", "source_deploy_id": deploy_id, "operations": [operation], "idempotency_key": "main-once"},
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True


def test_failed_deploy_is_redacted_and_list_get_are_database_scoped(client, monkeypatch):
    created, database, branch = _deploy_database(client, monkeypatch)
    headers = {"X-API-Key": created["api_key"]}
    second = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers=headers,
        json={"name": "second"},
    ).json()
    operation = {"op": "create_table", "name": "events", "columns": [{"name": "id", "type": "bigint"}]}
    deploy = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys",
        headers=headers,
        json={"branch": branch["id"], "operations": [operation]},
    ).json()
    c = main.db()
    try:
        branch_row = c.execute("SELECT path,credential_encrypted FROM branches WHERE id=?", (branch["id"],)).fetchone()
        branch_path = branch_row["path"]
        branch_password = main.cipher().decrypt(branch_row["credential_encrypted"].encode()).decode()
    finally:
        c.close()
    class ProgrammingFailure(Exception):
        class Diag:
            message_primary = f"bad at {branch_path}"
            message_hint = f"password={branch_password}"
            statement_position = None
        diag = Diag()
    class Errors:
        ProgrammingError = ProgrammingFailure
    class Connection:
        def execute(self, statement, params=()):
            if statement.startswith("SET "):
                return self
            raise ProgrammingFailure("failed")
        def commit(self):
            return None
        def rollback(self):
            return None
        def close(self):
            return None
    class FakePsycopg:
        errors = Errors()
        def connect(self, **kwargs):
            return Connection()
    monkeypatch.setattr(main, "psycopg", FakePsycopg())
    c = main.db()
    try:
        main._begin_deploy(c, created["tenant_id"], deploy["id"])
    finally:
        c.close()
    main._apply_deploy(deploy["id"], created["tenant_id"])
    failed = client.get(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/deploys/{deploy['id']}",
        headers=headers,
    ).json()
    assert failed["status"] == "failed"
    assert str(main.BRANCH_ROOT) not in failed["error"]
    assert "password=hidden" not in failed["error"]
    c = main.db()
    try:
        assert c.execute("SELECT COUNT(*) AS n FROM deploy_locks").fetchone()["n"] == 0
    finally:
        c.close()
    assert client.get(
        f"/v1/tenants/{created['tenant_id']}/databases/{second['id']}/deploys",
        headers=headers,
    ).json()["deploys"] == []
    assert client.get(
        f"/v1/tenants/{created['tenant_id']}/databases/{second['id']}/deploys/{deploy['id']}",
        headers=headers,
    ).status_code == 404


def test_mcp_deploy_and_get_deploy_use_same_path(client, monkeypatch):
    created, database, branch = _deploy_database(client, monkeypatch)
    args = {
        "database_id": database["id"],
        "branch": branch["id"],
        "operations": [{"op": "create_table", "name": "events", "columns": [{"name": "id", "type": "bigint"}]}],
    }
    def call(name, arguments):
        return client.post(
            "/mcp",
            headers={"X-API-Key": created["api_key"]},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}},
        )
    deploy = call("deploy", args)
    assert deploy.status_code == 200
    result = json.loads(deploy.json()["result"]["content"][0]["text"])
    fetched = call("get_deploy", {"database_id": database["id"], "deploy_id": result["id"]})
    assert fetched.status_code == 200
    assert json.loads(fetched.json()["result"]["content"][0]["text"])["id"] == result["id"]


def _query_database(client, monkeypatch):
    created = tenant(client)
    database = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases",
        headers={"X-API-Key": created["api_key"]},
        json={"name": "query-errors"},
    ).json()

    class FakeTransport:
        def call(self, *args, **kwargs):
            return {"status": "running", "pid": 1234}

    monkeypatch.setattr(main, "node_transport", FakeTransport())
    return created, database


def test_query_rejected_statement_returns_redacted_diagnostic(client, monkeypatch):
    created, database = _query_database(client, monkeypatch)
    c = main.db()
    try:
        row = c.execute(
            "SELECT path,credential_encrypted FROM branches WHERE database_id=?",
            (database["id"],),
        ).fetchone()
        path = str(row["path"])
        secret = main.cipher().decrypt(row["credential_encrypted"].encode()).decode()
    finally:
        c.close()

    class Diag:
        message_primary = 'relation "t" does not exist'
        message_detail = f"detail path={path} password={secret}"
        message_hint = "Check the relation name."
        statement_position = "23"

    class StatementError(Exception):
        diag = Diag()

    class Errors:
        ProgrammingError = StatementError

    class Connection:
        def execute(self, sql, params=()):
            if sql.startswith("SET statement_timeout"):
                return self
            raise StatementError("relation does not exist")

        def close(self):
            return None

    class FakePsycopg:
        errors = Errors()

        def connect(self, **kwargs):
            return Connection()

    monkeypatch.setattr(main, "psycopg", FakePsycopg())
    response = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/query",
        headers={"X-API-Key": created["api_key"]},
        json={"sql": "SELECT count(*) FROM t"},
    )
    assert response.status_code == 400
    assert "relation" in response.json()["detail"]
    assert "position 23" in response.json()["detail"]
    assert path not in response.text
    assert secret not in response.text


def test_query_connection_failure_remains_redacted_503(client, monkeypatch):
    created, database = _query_database(client, monkeypatch)

    class OperationalFailure(Exception):
        pass

    class FakePsycopg:
        OperationalError = OperationalFailure

        def connect(self, **kwargs):
            raise self.OperationalError("connection failed at /internal/host:55432")

    monkeypatch.setattr(main, "psycopg", FakePsycopg())
    response = client.post(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/query",
        headers={"X-API-Key": created["api_key"]},
        json={"sql": "SELECT 1"},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "database unavailable"
    assert "connection failed" not in response.text
    assert "55432" not in response.text


def test_schema_uses_statement_error_handling(client, monkeypatch):
    created, database = _query_database(client, monkeypatch)

    class StatementError(Exception):
        class Diag:
            message_primary = "schema query rejected"
            message_detail = None
            message_hint = None
            statement_position = None

        diag = Diag()

    class Errors:
        ProgrammingError = StatementError

    class Connection:
        def execute(self, sql, params=()):
            if sql.startswith("SET statement_timeout"):
                return self
            raise StatementError("schema query rejected")

        def close(self):
            return None

    class FakePsycopg:
        errors = Errors()

        def connect(self, **kwargs):
            return Connection()

    monkeypatch.setattr(main, "psycopg", FakePsycopg())
    response = client.get(
        f"/v1/tenants/{created['tenant_id']}/databases/{database['id']}/schema",
        headers={"X-API-Key": created["api_key"]},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "schema query rejected"
