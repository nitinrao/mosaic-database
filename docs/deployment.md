# Deployment

Mosaic Database is provisioned on three Proxmox hosts:

| Host | Address |
| --- | --- |
| `mch-sv1` | `152.236.1.61` |
| `mch-sv2` | `152.236.1.51` |
| `mch-sv3` | `206.223.239.247` |

Each host runs Proxmox 9.2 with kernel `7.0.14-8-pve`, ZFS
`2.4.3-pve1`, 32 cores, and 125 GB RAM. The hosts also run the
Mosaic ClickHouse cluster and its control-plane PostgreSQL container. That
workload remains on the approximately 94 GB root LV; Mosaic Database uses the
dedicated ZFS pool below.

For public database signup, expose the control plane at
`MOSAIC_PUBLIC_ENDPOINT` (default `https://database-api.mosaicos.com`). The
unauthenticated `POST /v1/public/signup` route provisions shared tenants and
refuses repeat signups for an email that already has a tenant; dedicated plans
remain an operator conversation. Set `MOSAIC_PUBLIC_SIGNUP_RATE_LIMIT_REQUESTS` for its
per-minute IP and email limit (default `5`). Set
`MOSAIC_MAX_DATABASES_TOTAL` for the global database ceiling (default `50`);
the service returns `503` and audits the refusal when that ceiling is reached.
When the control plane is reachable only through a Cloudflare tunnel, set
`MOSAIC_TRUST_CLOUDFLARE_IP=true` to bucket signup requests by Cloudflare's
`CF-Connecting-IP` header. The header is honored only when the socket peer is a
loopback/private address and the value parses as an IP address. It is off by
default; when off or invalid, the service uses the socket peer address. This
setting affects only signup rate-limit bucketing, not authentication or
authorization.

## Storage

Each host has a `mosaic` pool built as a mirror of `nvme2n1` and `nvme3n1`,
the two 1.9 TB Micron 7450 NVMe devices referenced through
`/dev/disk/by-id`. The pool has 1.68 TB usable capacity and these properties:

- `ashift=12`
- `compression=lz4`
- `atime=off`
- `xattr=sa`
- `acltype=posixacl`
- `recordsize=8k`
- `logbias=throughput`
- `mountpoint=none`
- `autotrim=on`

The `mosaic/db` dataset is mounted at `/var/lib/mosaic-database`. Configure
the service with:

```text
MOSAIC_BRANCH_ROOT=/var/lib/mosaic-database
MOSAIC_BRANCH_ENGINE=zfs
MOSAIC_ZFS_POOL=mosaic/db
```

Branches therefore use datasets and mountpoints of the form:

```text
mosaic/db/<database>/<branch>
/var/lib/mosaic-database/<database>/<branch>
```

This matches the ZFS mountpoint contract implemented by the service. The
remaining 447 GB of NVMe capacity on each host is unpartitioned and
unclaimed.

The node-agent ZFS wrapper executes ZFS in the host mount namespace and retains
the post-create/clone ownership fix-up for `postgres`. The unit must not run
in a private mount namespace: copied mounts pin datasets for the lifetime of
the service and make later ZFS destroys fail with unmount errors. The
`PrivateTmp` and `ProtectHome` unit options are therefore intentionally
omitted; the service already runs unprivileged as `postgres`.
If a stopped standby mount remains pinned by another host namespace, teardown
uses the narrow `mosaic-umount` helper for one last lazy detach of a path under
`MOSAIC_BRANCH_ROOT`, then retries the destroy once. Its warning indicates
that an external namespace is holding the mount.

## Nodes

Replication uses asynchronous physical streaming. Configure the bounded WAL
retention budget with `MOSAIC_REPLICATION_WAL_RETENTION_BYTES` (the default is
10 GiB). Primary PostgreSQL configurations set
`max_slot_wal_keep_size` to this value and leave
`synchronous_standby_names` empty, so commits never wait for a standby. If a
standby remains down long enough to exceed the budget, PostgreSQL invalidates
its replication slot; that standby is marked for rebuild from a fresh
base-backup rather than allowing unbounded WAL retention to fill the pool.

Replication is not a backup mechanism; point-in-time recovery is a later
follow-up.

The host-aware control plane defaults to one `local` node and loopback-only
PostgreSQL. For multiple nodes, set `MOSAIC_NODE_HOSTS` to comma-separated
node IDs with optional internal agent URLs, for example:

```text
MOSAIC_NODE_HOSTS=sv1=https://10.0.0.1:8000,sv2=https://10.0.0.2:8000
MOSAIC_NODE_PRIVATE_ADDRESSES=sv1=10.0.0.1,sv2=10.0.0.2
MOSAIC_NODE_AGENT_TOKEN=<shared-internal-token>
MOSAIC_NODE_AGENT_CA_BUNDLE=/etc/mosaic-database/node-agent-ca.pem
```

`MOSAIC_NODE_ID` identifies which configured node this process runs on. If
`MOSAIC_NODE_HOSTS` contains one node and `MOSAIC_NODE_ID` is unset, it defaults
to that sole node. Every host in a multi-node deployment must set
`MOSAIC_NODE_ID` to its own ID from `MOSAIC_NODE_HOSTS`; an unknown identity is
rejected during startup.

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

## Co-tenancy

ZFS ARC is capped at 8 GiB through
`/etc/modprobe.d/zfs.conf` (`options zfs zfs_arc_max=8589934592`), and the
cap is applied live.

`/etc/systemd/system/mosaic-database.slice` defines:

```text
CPUWeight=50
CPUQuota=800%
MemoryHigh=24G
MemoryMax=32G
IOWeight=50
TasksMax=4096
```

PostgreSQL units must set `Slice=mosaic-database.slice` to join it.

## Boot and availability

`zfs-import-cache`, `zfs-mount`, and `zfs.target` are enabled, so the pools
import and mount during boot.

## V0 boundaries

Each database `main` branch has one dark standby on each other configured
node. Standbys use `hot_standby=off` and are not readable; no query routing
targets them. The tenant replica API reports observed bytes behind the
primary's WAL replay position and the timestamp of the last sample. Standby
base backups run asynchronously on the node agent; replica rows report
`pending`, `building`, `ready`, `rebuild_required`, or retryable failure
states while the control plane polls job status. Replica data directories live
under the reserved
`.replicas` directory beside the primary branch, outside the tenant branch
namespace. A replica is not a branch and is never selected by the idle branch
reaper; a branch with replica rows is also never idle-reaped, and the
replication reconciler starts that primary before building standbys or
sampling lag. A ready replica whose standby cluster is verifiably gone is
marked `rebuild_required` and rebuilt instead of being reported healthy.
HTTPS node-agent connections always use certificate verification via
the system trust store or the configured `MOSAIC_NODE_AGENT_CA_BUNDLE`.

V0 remains single-primary per host with no HA, PITR, or DR promise.
Only `main` branches are replicated; ephemeral ZFS branches are not, so losing
a host loses its ephemeral branches. Standbys remain dark until a later manual
or scripted promotion. Automatic failover, leader election, watchdogs,
synchronous replication, and PITR are not implemented. Promotion is
operator-triggered through `POST /v1/admin/databases/{database_id}/promote`
with the `X-Admin-Key` header. The control plane verifies the old primary's
actual cluster state from its data directory, rather than trusting the
recorded PID, and stops it before promoting a reachable standby. Promotion
refuses while that cluster is still running unless the operator uses
`force=true`; an unreachable old-primary host also requires `force=true`,
which is the operator's explicit assertion that it is dead. The response's
observed lag is the RPO for that promotion event. Every surviving standby,
including the old primary when it returns, is marked `rebuild_required` and
forced through a full teardown and fresh `pg_basebackup` rather than reusing
anything found at the target path or being reattached to the new timeline.
This prevents a stale standby on a diverged timeline from being reported
healthy. If that forced rebuild fails, it remains `rebuild_required` and
retries with backoff. Slot-invalidated replicas are automatically reconciled
through the same rebuild path.
Recovery detection is connection-free and reads `pg_controldata`, because dark
standbys reject SQL connections. An unmounted or otherwise unusable old-primary
data directory is unverifiable and refuses promotion without `force=true`.
Promotion rejects missing or stale lag samples and lag above
`MOSAIC_PROMOTION_MAX_LAG_BYTES` (10 GiB by default); configure the freshness
window with `MOSAIC_PROMOTION_MAX_LAG_AGE_SECONDS` (five minutes by default).
After promotion, the main branch intentionally lives at the promoted
standby's `.replicas/<host>` path. A reachable old primary is stopped and its
old data directory is destroyed. With `force=true`, the old host may be
unreachable; its abandoned path and port are recorded and the operator must
remove that stale cluster before the reserved port can be released.
