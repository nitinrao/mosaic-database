"use client";

import { useEffect, useState, type ReactNode } from "react";

export function DocsClient({ children }: { children: ReactNode }) {
  useEffect(() => {
    const headings = [...document.querySelectorAll<HTMLElement>(".prose h2[id], .prose h3[id]")];
    const links = [...document.querySelectorAll<HTMLAnchorElement>(".toc a[data-toc-target]")];
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        if (!visible) return;
        const target = visible.target.id.replace(/-heading$/, "");
        for (const link of links) link.setAttribute("aria-current", link.dataset.tocTarget === target ? "true" : "false");
      },
      { rootMargin: "-24px 0px -70% 0px", threshold: [0, 1] },
    );
    for (const heading of headings) observer.observe(heading);
    return () => observer.disconnect();
  }, []);

  return <main className="docs shell">{children}</main>;
}

export function DocsTabs({ tabs }: { tabs: Record<string, ReactNode> }) {
  const names = Object.keys(tabs);
  const [selected, setSelected] = useState(names[0]);
  return (
    <div className="tab-shell">
      <div className="tab-list" role="tablist" aria-label="Mosaic Database interfaces">
        {names.map((name) => (
          <button
            className="tab-button"
            key={name}
            type="button"
            role="tab"
            aria-selected={selected === name}
            aria-controls={`tab-panel-${name.toLowerCase()}`}
            onClick={() => setSelected(name)}
          >
            {name}
          </button>
        ))}
      </div>
      {names.map((name) => (
        <section className="tab-panel" key={name} id={`tab-panel-${name.toLowerCase()}`} role="tabpanel" hidden={selected !== name}>
          {tabs[name]}
        </section>
      ))}
    </div>
  );
}
