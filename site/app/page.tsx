import CopyButton from "./copy-button";
import { SiteFooter, SiteNav } from "./site-chrome";

const quickstart = `export MOSAIC_ENDPOINT=https://database-api.mosaicos.com
export MOSAIC_TENANT_ID=ten_••••••••
export MOSAIC_API_KEY=mdb_live_••••••••

DB_ID=$(curl -fsS -X POST "$MOSAIC_ENDPOINT/v1/tenants/$MOSAIC_TENANT_ID/databases" \\
  -H "X-API-Key: $MOSAIC_API_KEY" -H "Content-Type: application/json" \\
  -d '{"name":"events"}' | jq -r .id)

curl -fsS -X POST "$MOSAIC_ENDPOINT/v1/tenants/$MOSAIC_TENANT_ID/databases/$DB_ID/query" \\
  -H "X-API-Key: $MOSAIC_API_KEY" -H "Content-Type: application/json" \\
  -d '{"sql":"SELECT 1 AS ok"}'`;

export default function Home() {
  return (
    <>
      <SiteNav />
      <main>
        <section className="hero shell">
          <div className="eyebrow"><span className="live" /> Managed PostgreSQL · Silicon Valley</div>
          <h1>Branchable Postgres for agents<span className="tm">®</span></h1>
          <p className="lead">
            Mosaic Database gives you managed PostgreSQL with instant branches, a tenant-scoped API key, and governed
            SQL over HTTP. Each database&apos;s main branch is replicated asynchronously to dark standbys on the other
            hosts.
          </p>
          <p className="docs-note">Alpha means early access: interfaces and the API surface may change. Replication and rehearsed failover exist, but there is no point-in-time recovery or WAL archiving yet, so do not keep data here whose only copy is this service.</p>
          <div className="actions">
            <a className="button" href="/start">Create your API key</a>
            <a className="text-link" href="/docs#quickstart">Run the quickstart →</a>
          </div>
        </section>

        <section className="value-bar shell" aria-label="Core product values">
          <article className="value-pill">
            <span className="kicker">Branchable</span>
            <strong>Clone a database in one API call.</strong>
            <p>Branches are PostgreSQL data directories with their own lifecycle, credentials, and ports.</p>
          </article>
          <article className="value-pill">
            <span className="kicker">Governed</span>
            <strong>SQL with a clear boundary.</strong>
            <p>Parameterized reads and DML are accepted; DDL, multiple statements, and dangerous server capabilities are rejected.</p>
          </article>
          <article className="value-pill">
            <span className="kicker">Honest</span>
            <strong>Replication is not a backup.</strong>
            <p>Standbys are asynchronous and dark, failover is operator-triggered, and PITR is not available yet.</p>
          </article>
        </section>

        <section className="demo shell" aria-label="Quickstart">
          <div className="demo-head"><span>Quickstart</span><span>Create, then query</span></div>
          <pre><CopyButton value={quickstart} /><code>{quickstart}</code></pre>
          <p className="demo-note">
            The database response includes the main-branch password once. Store it securely.{" "}
            <a href="/docs#quickstart">Read the full DevDocs quickstart</a>
          </p>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
