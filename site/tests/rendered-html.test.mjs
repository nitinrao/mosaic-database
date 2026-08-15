import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function render(pathname = "/") {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}-${pathname}`);
  const { default: worker } = await import(workerUrl.href);
  return worker.fetch(
    new Request(`http://localhost${pathname}`, { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("renders the Mosaic Database landing page", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /Branchable Postgres for agents/);
  assert.match(html, /Replication is not a backup/);
  assert.match(html, /ALPHA/);
  assert.match(html, /no point-in-time recovery or WAL archiving yet/);
  assert.match(html, /only copy is this service/);
  assert.match(html, /database-api\.mosaicos\.com/);
  assert.doesNotMatch(html, /ClickHouse workloads|Your site is taking shape/);
});

test("serves every requested page", async () => {
  for (const route of ["/", "/docs", "/pricing", "/start", "/roadmap"]) {
    assert.equal((await render(route)).status, 200, `${route} is not served`);
  }
});

test("keeps the API contract and operational boundaries visible", async () => {
  const docs = await (await render("/docs")).text();
  assert.match(docs, /POST \/v1\/tenants/);
  assert.match(docs, /hot_standby=off/);
  assert.match(docs, /PITR and WAL archiving/);
  assert.match(docs, /10,000/);
  assert.match(docs, /100,000/);
  assert.match(docs, /MCP/);
  const pricing = await (await render("/pricing")).text();
  assert.match(pricing, /\$100 \/ month/);
  assert.match(pricing, /\$500 \/ month/);
  assert.match(pricing, /ceiling of 50 databases/);
});

test("renders signup reuse refusal and capacity guidance", async () => {
  const html = await (await render("/start")).text();
  assert.match(html, /ALPHA/);
  assert.match(html, /no point-in-time recovery or WAL archiving yet/);
  assert.match(html, /only copy is this service/);
  assert.match(html, /database-api\.mosaicos\.com\/v1\/public\/signup/);
  assert.match(html, /returned exactly once/);
  assert.match(html, /signup is refused/);
  assert.match(html, /capacity ceiling has been reached/);
});

test("includes the PostgreSQL service switcher entry", async () => {
  for (const route of ["/", "/docs", "/start"]) {
    const html = await (await render(route)).text();
    assert.match(html, /PostgreSQL/);
    assert.match(html, /https:\/\/database\.mosaicos\.com\//);
  }
});

test("publishes database crawler files", async () => {
  const robots = await readFile(new URL("../public/robots.txt", import.meta.url), "utf8");
  const sitemap = await readFile(new URL("../public/sitemap.xml", import.meta.url), "utf8");
  const llms = await readFile(new URL("../public/llms.txt", import.meta.url), "utf8");
  assert.match(robots, /https:\/\/database\.mosaicos\.com\/sitemap\.xml/);
  for (const path of ["/", "/docs", "/pricing", "/roadmap", "/start", "/llms.txt"]) {
    assert.ok(sitemap.includes(`<loc>https://database.mosaicos.com${path}</loc>`), `sitemap is missing ${path}`);
  }
  assert.match(llms, /PITR and WAL archiving are future work/);
});

test("sets security headers on rendered responses", async () => {
  const response = await render();
  assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  assert.match(response.headers.get("content-security-policy") ?? "", /https:\/\/sandbox\.mosaicos\.com/);
  assert.equal(response.headers.get("strict-transport-security"), "max-age=31536000; includeSubDomains");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.ok(response.headers.get("x-request-id"));
});

test("captures the signup form before awaiting the response", async () => {
  const source = await readFile(new URL("../app/start/page.tsx", import.meta.url), "utf8");
  assert.match(source, /const formElement = event\.currentTarget;/);
  assert.match(source, /new FormData\(formElement\)/);
  assert.doesNotMatch(source, /event\.currentTarget\.reset\(\)/);
});
