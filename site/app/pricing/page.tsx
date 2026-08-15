import { SiteFooter, SiteNav } from "../site-chrome";

export const metadata = {
  title: "Pricing — Mosaic Database",
  description: "Mosaic Database plans and the quotas enforced by the control plane.",
};

export default function PricingPage() {
  return (
    <>
      <SiteNav current="/pricing" />
      <main>
        <section className="hero shell">
          <div className="eyebrow"><span className="live" /> Transparent pricing</div>
          <h1>Two plans. Hard limits.</h1>
          <p className="lead">
            These are the values in the control plane today. Shared signup is self-serve; dedicated capacity is
            available by getting in touch with Mosaic.
          </p>
        </section>
        <section className="pricing pricing-table-only shell" id="pricing">
          <div className="pricing-table" role="region" aria-label="Mosaic Database pricing" tabIndex={0}>
            <table>
              <thead><tr><th>Plan</th><th>Monthly price</th><th>Databases</th><th>Branches</th><th>Query boundary</th></tr></thead>
              <tbody>
                <tr>
                  <th>Shared</th>
                  <td><strong>$100 / month</strong><small>Self-serve</small></td>
                  <td>5 per tenant</td>
                  <td>20 per tenant</td>
                  <td><strong>10,000 rows</strong><small>5 s statement timeout</small></td>
                </tr>
                <tr>
                  <th>Dedicated</th>
                  <td><strong>$500 / month</strong><small>Contact Mosaic</small></td>
                  <td>20 per tenant</td>
                  <td>100 per tenant</td>
                  <td><strong>100,000 rows</strong><small>30 s statement timeout</small></td>
                </tr>
              </tbody>
            </table>
          </div>
          <p className="pricing-note">
            The SQL endpoint accepts one statement at a time: parameterized reads and DML are governed by the plan row
            and timeout limits. DDL, server-side commands, filesystem access, and process-control capabilities are
            rejected. A separate global ceiling of 50 databases protects the three-host replicated deployment; it
            applies to every caller and returns <code>503</code> at capacity.
          </p>
          <div className="actions">
            <a className="button" href="/start">Create a shared key</a>
            <a className="text-link" href="/docs#limits">See the API limits →</a>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
