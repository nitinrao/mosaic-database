"use client";

import Link from "next/link";
import { useEffect, useId, useRef, useState, useSyncExternalStore } from "react";

// Every Mosaic site shows the same list; the current service is found by hostname so that
// this component carries no per-site value and can be copied between the sites unchanged.
export const SERVICES = [
  { name: "Sandbox", blurb: "Firecracker microVMs for agents", url: "https://sandbox.mosaicos.com/" },
  { name: "Object Storage", blurb: "S3-compatible, zero egress", url: "https://storage.mosaicos.com/" },
  { name: "Memory", blurb: "Durable recall for agents", url: "https://memory.mosaicos.com/" },
  { name: "ClickHouse®", blurb: "Managed columnar analytics", url: "https://clickhouse.mosaicos.com/" },
  { name: "PostgreSQL", blurb: "Branchable Postgres for agents", url: "https://database.mosaicos.com/" },
  { name: "Apache Kafka®", blurb: "Queues and streams over HTTP", url: "https://kafka.mosaicos.com/" },
  { name: "Observability", blurb: "Metrics, logs and traces", url: "https://observability.mosaicos.com/" },
] as const;

// The wordmark itself is the menu: a caret beside it is too small to find, and this
// site's home page is the menu's own current entry, so nothing becomes unreachable.
// `children` is the wordmark's contents, rendered inside the button.
export function ServiceSwitcher({ children }: { children: React.ReactNode }) {
  const menuId = useId();
  const root = useRef<HTMLDivElement>(null);
  const toggle = useRef<HTMLButtonElement>(null);
  const [open, setOpen] = useState(false);
  // One HTML document is rendered for every host, so the current service can only be known
  // on the client. The server snapshot is empty, which marks no entry and hydrates cleanly.
  const host = useSyncExternalStore(() => () => {}, () => location.hostname, () => "");

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [open]);

  const items = () => [...(root.current?.querySelectorAll<HTMLAnchorElement>(".switcher-item") ?? [])];

  return (
    <div
      className="switcher"
      ref={root}
      onKeyDown={(event) => {
        if (event.key === "Escape") {
          setOpen(false);
          toggle.current?.focus();
          return;
        }
        if (!open || (event.key !== "ArrowDown" && event.key !== "ArrowUp")) return;
        event.preventDefault();
        const links = items();
        const step = event.key === "ArrowDown" ? 1 : -1;
        const at = links.indexOf(document.activeElement as HTMLAnchorElement);
        // Focus can sit on the wordmark or the caret with the menu open, where indexOf is -1;
        // that has to mean "before the first item", not "one past the end".
        const next = at === -1 ? (step === 1 ? 0 : links.length - 1) : (at + step + links.length) % links.length;
        links[next]?.focus();
      }}
      // relatedTarget, not document.activeElement: during blur the browser has not yet moved
      // focus, so reading activeElement would close the menu on every tab between items.
      // A null relatedTarget means focus went nowhere at all, which is not a reason to close:
      // leaving is always either a tab to something or a pointerdown the effect above catches.
      onBlur={(event) => {
        if (event.relatedTarget && !root.current?.contains(event.relatedTarget)) setOpen(false);
      }}
    >
      {/* Safari does not focus a button when you press it, so with the menu open the press would
          blur the focused entry to nowhere, onBlur would close the menu, and the click would then
          read it as shut and reopen it. Taking focus makes the blur land inside the switcher. */}
      <button
        type="button"
        ref={toggle}
        className="brand switcher-toggle"
        aria-expanded={open}
        aria-haspopup="true"
        aria-controls={menuId}
        onPointerDown={() => toggle.current?.focus()}
        onClick={() => {
          const opening = !open;
          setOpen(opening);
          if (opening) queueMicrotask(() => (items().find((item) => item.getAttribute("aria-current")) ?? items()[0])?.focus());
        }}
      >
        {children}
        {/* The wordmark alone does not say the control opens anything. */}
        <span className="switcher-hint">Switch Mosaic service</span>
        <span className="switcher-caret" aria-hidden="true">
          ▾
        </span>
      </button>
      {/* Safari does not focus a link on press either, so pressing an entry blurs the focused
          one to nothing and the press never becomes a click. Focusing the pressed entry keeps
          the blur inside the switcher and lets the click through. */}
      <div
        className="switcher-menu"
        id={menuId}
        hidden={!open}
        onPointerDown={(event) => (event.target as Element).closest<HTMLAnchorElement>(".switcher-item")?.focus()}
      >
        <p className="switcher-label">Mosaic OS</p>
        {/* A preview or local host matches no service, so no entry would carry this site's
            home and the wordmark would stop leading anywhere. Give that host its own entry. */}
        {host && !SERVICES.some((service) => new URL(service.url).hostname === host) ? (
          <Link href="/" className="switcher-item" aria-current="true">
            <strong>Home</strong>
            <span>This site</span>
          </Link>
        ) : null}
        {SERVICES.map((service) => (
          <a
            key={service.url}
            href={service.url}
            className="switcher-item"
            aria-current={new URL(service.url).hostname === host ? "true" : undefined}
          >
            <strong>{service.name}</strong>
            <span>{service.blurb}</span>
          </a>
        ))}
      </div>
    </div>
  );
}
