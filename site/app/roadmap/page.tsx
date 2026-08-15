import { SiteFooter, SiteNav } from "../site-chrome";

export const metadata = {
  title: "Roadmap — Mosaic Database",
  description: "What Mosaic Database supports now and which recovery and deployment features are future work.",
};

export default function RoadmapPage() {
  return (
    <>
      <SiteNav current="/roadmap" />
      <main className="docs shell">
        <aside className="toc" aria-label="Roadmap sections">
          <a href="#now">Now</a>
          <a href="#next">Next</a>
          <a href="#later">Later</a>
          <a href="#principles">Principles</a>
        </aside>
        <article className="prose">
          <div className="eyebrow"><span className="live" /> Public roadmap</div>
          <h1>What is live, what is next.</h1>
          <p className="lead">Database claims should be explicit. This page separates current behavior from future work.</p>

          <h2 id="now">Now</h2>
          <ul>
            <li>Self-serve shared signup returns a tenant API key once; repeating signup rotates and invalidates the previous key.</li>
            <li>PostgreSQL databases with a main branch, child branches, and per-tenant database and branch quotas.</li>
            <li>Governed SQL over HTTP for one parameterized read or DML statement, with plan-specific row and timeout limits.</li>
            <li>Asynchronous physical replication of each main branch to dark standbys on the other configured hosts.</li>
            <li>Operator-triggered promotion with observed lag/RPO evidence; there is no automatic failover.</li>
            <li>Audit records, encrypted branch credentials, and a global database capacity ceiling.</li>
          </ul>

          <h2 id="next">Next</h2>
          <ul>
            <li>Point-in-time recovery and WAL archiving. Replication is not a backup today.</li>
            <li>Opt-in read endpoints that expose replica lag and make the dark-standby tradeoff explicit.</li>
            <li>pgroll-style governed deploy requests for schema changes instead of direct DDL through the query endpoint.</li>
            <li>Self-serve billing, customer-visible usage operations, and published workload benchmarks.</li>
          </ul>

          <h2 id="later">Later</h2>
          <ul>
            <li>Additional regions and larger dedicated allocations.</li>
            <li>Higher-availability control-plane operation.</li>
            <li>Recovery automation only after its fencing and evidence model is proven.</li>
          </ul>

          <h2 id="principles">Principles</h2>
          <ul>
            <li>Dark standbys are not read replicas: they use <code>hot_standby=off</code> and are not query targets.</li>
            <li>Asynchronous replication reduces recovery loss but does not provide zero-RPO durability.</li>
            <li>Publish measurements and boundaries instead of implying guarantees we have not verified.</li>
          </ul>
        </article>
      </main>
      <SiteFooter />
    </>
  );
}
