import Link from "next/link";

export default function NotFound() {
  return (
    <main className="hero shell">
      <p className="kicker">404</p>
      <h1>Not found.</h1>
      <p className="lead">
        Return to <Link className="text-link" href="/">Mosaic Database</Link>, read the{" "}
        <Link className="text-link" href="/docs">DevDocs</Link>, or <Link className="text-link" href="/start">create an API key</Link>.
      </p>
    </main>
  );
}
