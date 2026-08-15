# Mosaic Database architecture

Each database has an independent PostgreSQL data directory and a `main` branch.
Branches have their own postmaster and port. ZFS snapshots and clones make
creation O(1) in data size. The copy engine uses `pg_basebackup` for a running
parent rather than `cp -a`, because copying a live PostgreSQL directory can
capture torn pages and inconsistent WAL state.

The supervisor records port, PID, status, and last-query time in the ledger.
It starts stopped branches on demand and stops idle postmasters while retaining
data. V0 is single-primary, with no HA, PITR, or DR promise. DDL is deferred to
deploy requests.
