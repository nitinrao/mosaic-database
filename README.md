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
uvicorn app.main:app --reload
pytest -q
```
