"use client";

import { useState } from "react";

export default function CopyButton({ value }: { value: string }) {
  const [label, setLabel] = useState("Copy");
  return <button className="copy-button" type="button" onClick={async () => { await navigator.clipboard.writeText(value); setLabel("Copied"); setTimeout(() => setLabel("Copy"), 1200); }}>{label}</button>;
}
