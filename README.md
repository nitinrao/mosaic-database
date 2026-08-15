# Mosaic Database

Managed PostgreSQL with instant branching for `database.mosaicos.com`.

V0 provides tenant-scoped API keys, explicit plans and limits, encrypted
per-branch credentials, governed single-statement SQL (including writes),
schema inspection, usage events, audit logging, and a stateless MCP surface.
ZFS is the production branching engine; a copy/`pg_basebackup` engine is
available for development and CI.

This is deliberately single-primary. V0 has no HA, no PITR, and no DR promise.
DDL is not accepted by the query endpoint; schema changes belong to deploy
requests in a follow-up.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export MOSAIC_ADMIN_KEY=dev-admin-key
export MOSAIC_CREDENTIAL_ENCRYPTION_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
uvicorn app.main:app --reload
pytest -q
```

`MOSAIC_CREDENTIAL_ENCRYPTION_KEY` is mandatory in production and must remain
stable across control-plane restarts. For local development or tests only,
`MOSAIC_ALLOW_EPHEMERAL_CREDENTIAL_KEY=true` stores a generated key under the
branch root; do not use that escape hatch for production data.

The production ZFS engine pins every dataset's mountpoint to its corresponding
absolute path under `MOSAIC_BRANCH_ROOT`. The mountpoint is part of the
branching contract: PostgreSQL clusters are initialized and supervised at that
path, and ZFS snapshots/clones must remain mounted there.

Host-aware lifecycle management is available for multi-host deployments.
Configure `MOSAIC_NODE_HOSTS`, `MOSAIC_NODE_PRIVATE_ADDRESSES`, and the shared
`MOSAIC_NODE_AGENT_TOKEN`; private addresses are required explicitly and
PostgreSQL never binds to `0.0.0.0`. A single `local` node remains the default.
Branch placement is recorded in the ledger, with database placement
deterministically spread across configured nodes and child branches staying
with their parent.

Replication is not included in this scope. The planned model is asynchronous
replication for `main` branches only; ephemeral branches are not replicated,
and losing a host loses those branches. Standbys will remain dark until a
later manual or scripted promotion. Automatic failover, leader election, and
fencing are not implemented.

See [docs/deployment.md](docs/deployment.md) for the production storage and
node configuration contract.
