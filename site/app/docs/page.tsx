import CopyButton from "../copy-button";
import { DocsClient } from "../docs-client";
import { SiteFooter, SiteNav } from "../site-chrome";

export const metadata = {
  title: "DevDocs — Mosaic Database",
  description: "Reference documentation for Mosaic Database tenants, branches, governed SQL, and replication boundaries.",
};

const Heading = ({ level, id, children }: { level: 2 | 3; id: string; children: string }) => {
  const Tag = `h${level}` as "h2" | "h3";
  return <Tag id={id}>{children}<a className="heading-anchor" href={`#${id}`} aria-label={`Link to ${children}`}>#</a></Tag>;
};

const CodeBlock = ({ value }: { value: string }) => (
  <div className="code-wrap"><CopyButton value={value} /><pre><code>{value}</code></pre></div>
);

const signup = `curl -fsS -X POST https://database-api.mosaicos.com/v1/public/signup \\
  -H "Content-Type: application/json" \\
  -d '{"email":"you@example.com","tenant_name":"agent-demo","plan":"shared"}'

{"status":"created","tenant_id":"ten_…","tenant_name":"agent-demo",
 "plan":"shared","key_name":"Self-serve key","api_key":"mdb_live_…",
 "token_prefix":"mdb_live_…","quickstart":{…}}`;

const quickstart = `export MOSAIC_ENDPOINT=https://database-api.mosaicos.com
export MOSAIC_TENANT_ID=ten_••••••••
export MOSAIC_API_KEY=mdb_live_••••••••

# Create a database. The main-branch password is returned once.
DB_ID=$(curl -fsS -X POST "$MOSAIC_ENDPOINT/v1/tenants/$MOSAIC_TENANT_ID/databases" \\
  -H "X-API-Key: $MOSAIC_API_KEY" -H "Content-Type: application/json" \\
  -d '{"name":"events"}' | jq -r .id)

# Query the main branch through the governed SQL endpoint.
curl -fsS -X POST "$MOSAIC_ENDPOINT/v1/tenants/$MOSAIC_TENANT_ID/databases/$DB_ID/query" \\
  -H "X-API-Key: $MOSAIC_API_KEY" -H "Content-Type: application/json" \\
  -d '{"sql":"SELECT 1 AS ok"}'`;

const createDatabase = `POST /v1/tenants/ten_…/databases
X-API-Key: mdb_live_…

{"name":"events"}

{"id":"db_…","name":"events","status":"ready",
 "main_branch":{"id":"br_…","name":"main","password":"…"}}`;

const query = `POST /v1/tenants/ten_…/databases/db_…/query
X-API-Key: mdb_live_…

{"sql":"SELECT id, payload FROM events WHERE id = $1","params":[42]}

{"rows":[[42,"…"]],"columns":["id","payload"],"row_count":1}`;

const branch = `POST /v1/tenants/ten_…/databases/db_…/branches
X-API-Key: mdb_live_…

{"name":"feature-search","parent":"main"}

{"id":"br_…","name":"feature-search","status":"stopped","parent":"main"}`;

const schema = `GET /v1/tenants/ten_…/databases/db_…/schema?branch=main
X-API-Key: mdb_live_…

{"columns":[{"table_schema":"public","table_name":"events",
 "column_name":"id","data_type":"integer"}]}`;

const mcp = `POST https://database-api.mosaicos.com/mcp
Authorization: Bearer mdb_live_…
Content-Type: application/json

{"jsonrpc":"2.0","id":1,"method":"tools/call",
 "params":{"name":"query","arguments":{"tenant_id":"ten_…",
 "database_id":"db_…","sql":"SELECT 1 AS ok"}}}`;

export default function DocsPage() {
  return (
    <>
      <SiteNav current="/docs" />
      <DocsClient>
        <aside className="toc" aria-label="Documentation sections">
          {["quickstart", "plans", "authentication", "api", "governance", "replication", "errors", "limits"].map((id) => (
            <a key={id} href={`#${id}`} data-toc-target={id} aria-current="false">{id[0].toUpperCase() + id.slice(1)}</a>
          ))}
        </aside>
        <article className="prose">
          <span className="badge"><span className="live" /> ALPHA API</span>
          <h1>DevDocs</h1>
          <p className="lead">
            Mosaic Database is managed PostgreSQL with instant branches and a governed HTTP surface.{" "}
            <a className="text-link" href="/start">Create a shared key</a> and treat the endpoint examples here as
            the current contract.
          </p>

          <section id="quickstart">
            <Heading level={2} id="quickstart-heading">Quickstart</Heading>
            <p>Signup is unauthenticated and returns the tenant API key exactly once. Store it before creating a database.</p>
            <CodeBlock value={signup} />
            <CodeBlock value={quickstart} />
            <p>An email that already has a tenant cannot sign up again. Use the existing key or contact Mosaic; this prevents an unverified email from taking over an account.</p>
          </section>

          <section id="plans">
            <Heading level={2} id="plans-heading">Plans</Heading>
            <p>These values come directly from the control plane&apos;s <code>PLANS</code> table.</p>
            <table>
              <thead><tr><th>Plan</th><th>Price</th><th>Databases</th><th>Branches</th><th>Rows/query</th><th>Timeout</th></tr></thead>
              <tbody>
                <tr><th>shared</th><td>$100/month</td><td>5</td><td>20</td><td>10,000</td><td>5 s</td></tr>
                <tr><th>dedicated</th><td>$500/month</td><td>20</td><td>100</td><td>100,000</td><td>30 s</td></tr>
              </tbody>
            </table>
            <p>Only <code>shared</code> is eligible for public self-serve signup. Dedicated capacity requires getting in touch.</p>
          </section>

          <section id="authentication">
            <Heading level={2} id="authentication-heading">Authentication</Heading>
            <p>
              Tenant routes accept <code>X-API-Key</code> or <code>Authorization: Bearer</code>. Keys use the{" "}
              <code>mdb_live_</code> prefix; only a SHA-256 hash is persisted. Keep the returned secret in a secret manager.
            </p>
          </section>

          <section id="api">
            <Heading level={2} id="api-heading">REST API</Heading>
            <p>The base URL is <code>https://database-api.mosaicos.com</code>. Requests and responses are JSON.</p>
            <Heading level={3} id="databases">Databases</Heading>
            <p>Creating a database provisions a main PostgreSQL branch. Repeating the same tenant/name returns the existing database with <code>reused: true</code>.</p>
            <CodeBlock value={createDatabase} />
            <Heading level={3} id="query">Query</Heading>
            <p>Query the selected branch with one SQL statement and optional positional parameters.</p>
            <CodeBlock value={query} />
            <Heading level={3} id="branches">Branches and schema</Heading>
            <p>Child branches are created from a parent and start on demand. Schema inspection runs through the same governed query path.</p>
            <CodeBlock value={branch} />
            <CodeBlock value={schema} />
            <Heading level={3} id="usage">Usage</Heading>
            <p><code>GET /v1/tenants/&#123;tenant_id&#125;/usage</code> reports the tenant plan and recorded usage events. The API also exposes database and branch listings.</p>
          </section>

          <section id="governance">
            <Heading level={2} id="governance-heading">SQL governance</Heading>
            <p>
              The query endpoint accepts one statement beginning with <code>SELECT</code>, <code>INSERT</code>,
              <code>UPDATE</code>, <code>DELETE</code>, <code>WITH</code>, <code>VALUES</code>, or <code>SHOW</code>.
              DDL, server-side commands, filesystem functions, foreign-server access, process control, and multiple
              statements are rejected before execution. Results are capped by the plan&apos;s row limit and statement timeout.
            </p>
          </section>

          <section id="replication">
            <Heading level={2} id="replication-heading">Replication and recovery</Heading>
            <p>
              Physical streaming replication is asynchronous. Each main branch has dark standbys on the other configured
              hosts, with <code>hot_standby=off</code>; they are not read endpoints. Promotion is operator-triggered,
              not automatic, and reports the last observed lag as RPO evidence.
            </p>
            <p>
              Replication is not a backup. PITR and WAL archiving are not available in this version. A global ceiling of
              50 total databases protects the replicated three-host deployment; a new database request at capacity returns
              <code>503</code>.
            </p>
          </section>

          <section id="errors">
            <Heading level={2} id="errors-heading">Errors</Heading>
            <table>
              <thead><tr><th>Status</th><th>Meaning</th></tr></thead>
              <tbody>
                <tr><th>400</th><td>Invalid request or SQL outside the governed grammar; dedicated public signup is not self-serve.</td></tr>
                <tr><th>401</th><td>Missing or invalid tenant API key.</td></tr>
                <tr><th>403</th><td>Tenant boundary or plan quota violation.</td></tr>
                <tr><th>404</th><td>Database, branch, or tenant resource was not found.</td></tr>
                <tr><th>429</th><td>Tenant request rate or signup abuse limit exceeded.</td></tr>
                <tr><th>503</th><td>Control-plane/database capacity or branch availability issue.</td></tr>
              </tbody>
            </table>
          </section>

          <section id="limits">
            <Heading level={2} id="limits-heading">Limits</Heading>
            <table>
              <thead><tr><th>Limit</th><th>Shared</th><th>Dedicated</th></tr></thead>
              <tbody>
                <tr><th>Databases per tenant</th><td>5</td><td>20</td></tr>
                <tr><th>Branches per tenant</th><td>20</td><td>100</td></tr>
                <tr><th>Rows per query</th><td>10,000</td><td>100,000</td></tr>
                <tr><th>Statement timeout</th><td>5 seconds</td><td>30 seconds</td></tr>
                <tr><th>Global databases</th><td colSpan={2}>50 by default, across all tenants</td></tr>
              </tbody>
            </table>
            <p>Live plan definitions are available from <code>GET /v1/plans</code>; deployment can tune the global ceiling.</p>
          </section>

          <section id="mcp">
            <Heading level={2} id="mcp-heading">MCP</Heading>
            <p>The stateless <code>POST /mcp</code> endpoint exposes <code>inspect_schema</code>, <code>query</code>, <code>create_branch</code>, and <code>list_branches</code>. It uses the same tenant key and governance rules.</p>
            <CodeBlock value={mcp} />
          </section>
        </article>
      </DocsClient>
      <SiteFooter />
    </>
  );
}
