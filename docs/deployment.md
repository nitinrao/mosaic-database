# Deployment

Production storage uses the documented `mosaic/db` ZFS dataset mounted at
`/var/lib/mosaic-database`. Configure:

```text
MOSAIC_BRANCH_ROOT=/var/lib/mosaic-database
MOSAIC_BRANCH_ENGINE=zfs
MOSAIC_ZFS_POOL=mosaic/db
```

The host-aware control plane defaults to one `local` node and loopback-only
PostgreSQL. For multiple nodes, set `MOSAIC_NODE_HOSTS` to comma-separated
node IDs with optional internal agent URLs, for example:

```text
MOSAIC_NODE_HOSTS=sv1=http://10.0.0.1:8000,sv2=http://10.0.0.2:8000
MOSAIC_NODE_PRIVATE_ADDRESSES=sv1=10.0.0.1,sv2=10.0.0.2
MOSAIC_NODE_AGENT_TOKEN=<shared-internal-token>
```

Every configured node must have an explicit private address. Public host
addresses are not inferred, and PostgreSQL never binds to `0.0.0.0`.
The node agent exposes lifecycle operations only through its authenticated
internal API. Agent traffic is plaintext HTTP carrying the shared token, so
the agent listener and firewall must be confined to the private peer network;
it must not be exposed on a public interface. Requests are rejected unless
they arrive from loopback or one of the configured private node addresses.
The node agent does not access the control-plane ledger; the control plane
passes operation details and remains the only ledger writer. Existing branch
rows migrate to the `local` node.

V0 remains single-primary per host with no HA, PITR, or DR promise.
Replication across the three production pools is a follow-up, not built here.
The approved future design is asynchronous replication of `main` branches
only. Ephemeral branches are not replicated, so losing a host loses those
branches. Standbys remain dark until a later manual or scripted promotion;
automatic failover, leader election, and fencing are not implemented.
