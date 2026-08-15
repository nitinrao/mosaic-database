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
