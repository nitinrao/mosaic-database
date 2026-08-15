# Mosaic Database architecture

Each database has an independent PostgreSQL data directory and a `main` branch.
The unauthenticated `POST /v1/public/signup` endpoint supports self-serve
`shared` tenants and returns an API key exactly once. An email that already has
a tenant is refused with `409`; no tenant or key state is changed. Its public base URL is configured with
`MOSAIC_PUBLIC_ENDPOINT` (default `https://database-api.mosaicos.com`).
Self-serve signup is rate-limited independently by IP and email.

The control plane enforces a global database ceiling with
`MOSAIC_MAX_DATABASES_TOTAL` (default `50`). This applies to every database
creation caller and returns `503` at capacity; refusals are written to the
audit log because each database's replicated `main` pins postmasters across
the co-tenancy slice.
Branches have their own postmaster and port. ZFS snapshots and clones make
creation O(1) in data size. Before a ZFS snapshot or `pg_basebackup`, the
supervisor issues `CHECKPOINT` when the parent is running. This makes the
snapshot crash-consistent and reduces recovery work, but it is not a
transactionally quiesced backup: PostgreSQL recovery may still run after a
clone. The copy engine uses `pg_basebackup` for a running parent rather than
`cp -a`, because copying a live PostgreSQL directory can capture torn pages
and inconsistent WAL state.

The supervisor records port, PID, status, and last-query time in the ledger.
It starts stopped branches on demand and stops idle postmasters while retaining
data. V0 is single-primary, with no HA, PITR, or DR promise. DDL is deferred to
deploy requests.

Production ZFS datasets are created and cloned with an explicit mountpoint equal
to the branch's absolute path under `MOSAIC_BRANCH_ROOT`; relying on ZFS's
default mountpoint would initialize a different filesystem location and make
snapshots ineffective. Clones also rewrite their PostgreSQL port and Unix socket
directory before startup.

`MOSAIC_CREDENTIAL_ENCRYPTION_KEY` is mandatory and must be stable across
restarts so encrypted branch credentials remain decryptable. The explicit
development/test escape hatch `MOSAIC_ALLOW_EPHEMERAL_CREDENTIAL_KEY=true`
persists a generated key under the branch root and must not be used for
production data.

The control plane records each branch's physical node in the ledger. Nodes
default to a single `local` node; multi-host deployments configure
`MOSAIC_NODE_HOSTS` as node IDs with optional internal agent URLs and must
explicitly provide `MOSAIC_NODE_PRIVATE_ADDRESSES`. Database placement is a
deterministic hash of the database ID, while child branches remain on their
parent's node. Lifecycle operations use the same node-agent path for local
and remote nodes: local calls are in-process and remote calls use the
authenticated internal HTTP agent with `MOSAIC_NODE_AGENT_TOKEN`.
`MOSAIC_NODE_ID` identifies the node running this process. It resolves to the
sole configured node when `MOSAIC_NODE_HOSTS` has one entry and the variable is
unset; multi-node deployments must set it to this host's configured node ID.

In multi-host mode PostgreSQL listens only on the configured private address
for its node, and `pg_hba.conf` permits the configured peer addresses; it
never binds to `0.0.0.0`. Single-host mode remains loopback-only. Existing
ledgers migrate branch placement to `local`.

Physical streaming replication is asynchronous. Each `main` branch gets one
dark standby on each other configured node; ephemeral branches are not
replicated. Replication slots use the bounded
`MOSAIC_REPLICATION_WAL_RETENTION_BYTES` budget (10 GiB by default), and a
standby whose slot is invalidated must be rebuilt from a fresh base backup.
Standby base backups run as asynchronous node-agent jobs. Replica rows move
through `pending`, `building`, `ready`, `rebuild_required`, and retryable
failure states; the control plane polls job status rather than holding an HTTP
request open.
Observed lag is exposed as bytes behind the primary WAL replay position with a
sample timestamp. Standbys use `hot_standby=off` and are never query targets.
Replica data directories live under the reserved `.replicas` directory beside
the primary branch, outside the tenant branch namespace.
Any branch with replica rows is treated as a replicated primary and is never
idle-reaped. The replication reconciler starts a stopped replicated primary
before building standbys or sampling lag. A replica is reported healthy only
while its standby cluster is verifiably running; a ready row whose cluster is
gone is marked `rebuild_required` and rebuilt.
Standbys remain dark until a later manual or scripted promotion. There is no
automatic failover, leader election, watchdog, synchronous replication, or
PITR in this scope. Promotion is an operator-only action through the admin
API. It first fences the old primary when reachable; if that host is
unreachable, `force=true` records the operator's assertion that it is dead.
The API reports the last observed standby lag as the promotion event's RPO.
Recovery detection during promotion is connection-free: the node agent reads
`pg_controldata` because dark standbys reject SQL connections. An unmounted or
otherwise unusable old-primary data directory is unverifiable, so promotion
refuses without `force=true`.
After promotion, surviving standbys and the old primary are marked
`rebuild_required` and forced through a full teardown and fresh `pg_basebackup`
rather than reusing anything found at the target path or reattaching to the
divergent timeline. This prevents a stale standby on a diverged timeline from
being reported healthy. A forced rebuild that fails remains `rebuild_required`
and retries with backoff. Slot-invalidated replicas are reconciled
automatically through the same rebuild path. When the old primary host is
reachable, its stopped data directory is destroyed before the transition
completes. A forced promotion records an unreachable old-primary path as
abandoned and reserves its port until an operator cleans it up. Fencing
verifies the old primary's actual cluster state from its data directory rather
than trusting the recorded ledger PID; promotion refuses while that cluster is
still running unless `force=true`.
Before each standby rebuild, the node agent drops that standby's existing
physical replication slot on the current primary, tolerating an already
missing slot, and runs `pg_basebackup -C -S` so the backup creates a fresh slot
at its own start LSN. The primary preparation path does not pre-create rebuild
slots, avoiding stale WAL-retention state after a promotion.
