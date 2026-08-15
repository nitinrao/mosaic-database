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
`pending`, `building`, `ready`, or retryable failure states while the control
plane polls job status. Replica data directories live under the reserved
`.replicas` directory beside the primary branch, outside the tenant branch
namespace. A replica is not a branch and is never selected by the idle branch
reaper. HTTPS node-agent connections always use certificate verification via
the system trust store or the configured `MOSAIC_NODE_AGENT_CA_BUNDLE`.

V0 remains single-primary per host with no HA, PITR, or DR promise.
Only `main` branches are replicated; ephemeral ZFS branches are not, so losing
a host loses its ephemeral branches. Standbys remain dark until a later manual
or scripted promotion. Automatic failover, leader election, and fencing are
not implemented.
