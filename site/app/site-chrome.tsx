import Link from "next/link";

import { FeedbackLink } from "./feedback-link";
import { ServiceSwitcher } from "./service-switcher";

// Keep the core navigation shape aligned with the other Mosaic service sites.
const links = [
  ["DevDocs", "/docs"],
  ["Pricing", "/pricing"],
  ["Roadmap", "/roadmap"],
] as const;

export function SiteNav({ current }: { current?: string }) {
  return (
    <header className="nav shell">
      <ServiceSwitcher>
        <span className="mark" aria-hidden="true">M</span>
        <span>Mosaic Database</span>
      </ServiceSwitcher>
      <nav aria-label="Primary">
        {links.map(([label, href]) => (
          <Link key={href} href={href} aria-current={current === href ? "page" : undefined}>
            {label}
          </Link>
        ))}
      </nav>
      <Link className="button small" href="/start">
        Get API key
      </Link>
    </header>
  );
}

export function SiteFooter() {
  return (
    <footer className="shell">
      <span>© 2026 Mosaic</span>
      <span>
        <Link href="/pricing">Pricing</Link> · <Link href="/roadmap">Roadmap</Link> ·{" "}
        <Link href="/docs">DevDocs</Link> ·{" "}
        <Link href="https://database-api.mosaicos.com/.well-known/mcp.json">MCP manifest</Link> ·{" "}
        <Link href="https://database-api.mosaicos.com/readyz">Status</Link> · <FeedbackLink />
      </span>
      <span>
        Mosaic Database is managed PostgreSQL with explicit replication and recovery boundaries.
      </span>
    </footer>
  );
}
