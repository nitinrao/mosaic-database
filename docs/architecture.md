# Mosaic Database architecture

Each database has an independent PostgreSQL data directory and a `main` branch.
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

In multi-host mode PostgreSQL listens only on the configured private address
for its node, and `pg_hba.conf` permits the configured peer addresses; it
never binds to `0.0.0.0`. Single-host mode remains loopback-only. Existing
ledgers migrate branch placement to `local`.

Replication is future work and is intentionally not implemented here. The
approved design is asynchronous replication of `main` branches only.
Ephemeral branches are not replicated, so losing a host loses those branches.
Standbys remain dark until a later manual or scripted promotion. There is no
automatic failover, leader election, or fencing in this scope.
