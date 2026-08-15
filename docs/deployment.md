# Deployment

Production storage uses the documented `mosaic/db` ZFS dataset mounted at
`/var/lib/mosaic-database`. Configure:

```text
MOSAIC_BRANCH_ROOT=/var/lib/mosaic-database
MOSAIC_BRANCH_ENGINE=zfs
MOSAIC_ZFS_POOL=mosaic/db
```

Replication uses asynchronous physical streaming. Configure the bounded WAL
retention budget with `MOSAIC_REPLICATION_WAL_RETENTION_BYTES` (the default is
10 GiB). Primary PostgreSQL configurations set
`max_slot_wal_keep_size` to this value and leave
`synchronous_standby_names` empty, so commits never wait for a standby. If a
standby remains down long enough to exceed the budget, PostgreSQL invalidates
its replication slot; that standby is marked for rebuild from a fresh
base-backup rather than allowing unbounded WAL retention to fill the pool.

The host-aware control plane defaults to one `local` node and loopback-only
PostgreSQL. For multiple nodes, set `MOSAIC_NODE_HOSTS` to comma-separated
node IDs with optional internal agent URLs, for example:

```text
MOSAIC_NODE_HOSTS=sv1=https://10.0.0.1:8000,sv2=https://10.0.0.2:8000
MOSAIC_NODE_PRIVATE_ADDRESSES=sv1=10.0.0.1,sv2=10.0.0.2
MOSAIC_NODE_AGENT_TOKEN=<shared-internal-token>
MOSAIC_NODE_AGENT_CA_BUNDLE=/etc/mosaic-database/node-agent-ca.pem
```

Every configured node must have an explicit private address. Public host
addresses are not inferred, and PostgreSQL never binds to `0.0.0.0`.
The node agent exposes lifecycle operations only through its authenticated
internal API. HTTPS node-agent URLs use the configured
`MOSAIC_NODE_AGENT_CA_BUNDLE` trust bundle. Plaintext `http://` URLs in
multi-host mode are refused unless the explicit development-only
`MOSAIC_ALLOW_PLAINTEXT_NODE_AGENT=true` opt-out is set. In either case, the
agent listener and firewall must be confined to the private peer network; it
must not be exposed on a public interface. Requests are rejected unless they
arrive from loopback or one of the configured private node addresses.
The node agent does not access the control-plane ledger; the control plane
passes operation details and remains the only ledger writer. Existing branch
rows migrate to the `local` node.

Each database `main` branch has one dark standby on each other configured
node. Standbys use `hot_standby=off` and are not readable; no query routing
targets them. The tenant replica API reports observed bytes behind the
primary's WAL replay position and the timestamp of the last sample. A replica
is not a branch and is never selected by the idle branch reaper.

V0 remains single-primary per host with no HA, PITR, or DR promise.
Only `main` branches are replicated; ephemeral ZFS branches are not, so losing
a host loses its ephemeral branches. Standbys remain dark until a later manual
or scripted promotion. Automatic failover, leader election, and fencing are
not implemented.
