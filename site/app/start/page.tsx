"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import CopyButton from "../copy-button";
import { ServiceSwitcher } from "../service-switcher";

type SignupResult = {
  tenant_id: string;
  tenant_name: string;
  api_key: string;
  key_name: string;
  plan: string;
  token_prefix: string;
  quickstart: { endpoint: string; command: string; docs_path: string; signup_path: string };
  status: "created";
};

const API_ENDPOINT = "https://database-api.mosaicos.com/v1/public/signup";

export default function StartPage() {
  const [state, setState] = useState<"idle" | "sending" | "success" | "error" | "capacity">("idle");
  const [errorMessage, setErrorMessage] = useState("");
  const [result, setResult] = useState<SignupResult | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setState("sending");
    setErrorMessage("");
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch(API_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...Object.fromEntries(form.entries()), plan: "shared" }),
      });
      const payload = await response.json().catch(() => ({}));
      if (response.status === 503) {
        setState("capacity");
        setErrorMessage(typeof payload.detail === "string" ? payload.detail : "Mosaic Database is currently at capacity.");
        return;
      }
      if (!response.ok) {
        setState("error");
        setErrorMessage(typeof payload.detail === "string" ? payload.detail : "That signup could not be completed.");
        return;
      }
      setResult(payload as SignupResult);
      setState("success");
      event.currentTarget.reset();
    } catch {
      setState("error");
      setErrorMessage("The signup service could not be reached. Please try again.");
    }
  }

  return (
    <main className="access-page shell">
      <ServiceSwitcher>
        <span className="mark" aria-hidden="true">M</span>
        <span>Mosaic Database</span>
      </ServiceSwitcher>
      <span className="badge alpha-badge">ALPHA</span>
      <div className="eyebrow"><span className="live" /> Self-serve shared signup</div>
      <h1>Create your PostgreSQL key.</h1>
      <p className="lead">
        Enter an email and Mosaic will create a shared tenant. The API key is returned exactly once. If you sign up
        again with the same email, signup is refused and the existing key remains unchanged. Use your existing key or contact Mosaic.
      </p>
      <p className="docs-note">This is early access: interfaces and the API surface may change. Replication and rehearsed failover exist, but there is no point-in-time recovery or WAL archiving yet, so do not keep data here whose only copy is this service.</p>
      <p className="result-note">Signup endpoint: <code>{API_ENDPOINT}</code>. A <code>503</code> response means the global database capacity ceiling has been reached.</p>

      <form className="access-form" onSubmit={submit}>
        <label>Work email<input name="email" type="email" required /></label>
        <label>Tenant name<input name="tenant_name" placeholder="Agent workspace" /></label>
        <label>Key name<input name="key_name" placeholder="Self-serve key" /></label>
        <p className="result-note">Plan: <strong>Shared · $100/month</strong>. Dedicated capacity is not self-serve; <a className="text-link" href="mailto:hello@mosaicos.com">get in touch</a>.</p>
        <button className="button" disabled={state === "sending"}>
          {state === "sending" ? "Creating…" : "Create API key"}
        </button>
        {state === "error" && <p className="form-error">{errorMessage}</p>}
        {state === "capacity" && <p className="form-error">Mosaic Database is at capacity. {errorMessage}</p>}
      </form>

      {result && (
        <section className="demo shell" aria-label="Signup result" style={{ marginTop: "36px" }}>
          <div className="demo-head">
            <span>Key created</span>
            <span>{result.tenant_name}</span>
          </div>
          <p className="result-note">
            This key is shown once. Store it in a secret manager; Mosaic retains only its hash.
          </p>
          <p className="form-success">API key: <code>{result.api_key}</code></p>
          <pre><CopyButton value={result.quickstart.command} /><code>{result.quickstart.command}</code></pre>
          <p className="result-note">The command above creates a database and queries its main branch through the governed API.</p>
        </section>
      )}
      <footer className="shell"><span>© 2026 Mosaic</span><span><Link href="/">Home</Link> · <Link href="/docs">DevDocs</Link></span><span>Managed PostgreSQL with explicit replication and recovery boundaries.</span></footer>
    </main>
  );
}
