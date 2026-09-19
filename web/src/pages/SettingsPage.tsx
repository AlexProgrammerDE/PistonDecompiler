import { useQuery } from "@tanstack/react-query"
import { settingsQuery } from "@/lib/api"
import { ErrorNotice, LoadingRows } from "@/components/Feedback"
import { money } from "@/lib/format"
export function SettingsPage() {
  const query = useQuery(settingsQuery)
  const s = query.data
  return (
    <>
      <header className="page-header">
        <div>
          <h1>Configuration</h1>
          <p>Backend configuration and provider readiness.</p>
        </div>
      </header>
      <div className="page-body">
        <ErrorNotice error={query.error} />
        <section className="settings-section">
          <h2>Runtime</h2>
          {s ? (
            <dl className="property-list">
              <dt>Ghidra</dt>
              <dd>
                {s.ghidraConfigured ? "Ready" : "Set GHIDRA_HOME and restart"}
              </dd>
              <dt>AI provider</dt>
              <dd>
                {s.aiConfigured
                  ? "Ready"
                  : "Set the model, token prices, and API key"}
              </dd>
              <dt>Endpoint</dt>
              <dd className="break-all">{s.providerUrl}</dd>
              <dt>Map model</dt>
              <dd>{s.model || "Not configured"}</dd>
              <dt>Escalation model</dt>
              <dd>{s.escalationModel || "Disabled"}</dd>
              <dt>Concurrent requests</dt>
              <dd>{s.concurrency}</dd>
              <dt>Budget for new binaries</dt>
              <dd>{money(s.budgetUsd)}</dd>
              <dt>Input limit</dt>
              <dd>{s.maxInputBytes.toLocaleString()} bytes</dd>
              <dt>Asynchronous batches</dt>
              <dd>{s.batchEnabled ? "Enabled through CLI" : "Disabled"}</dd>
            </dl>
          ) : (
            <LoadingRows />
          )}
        </section>
        <section className="settings-section">
          <h2>Configure the backend</h2>
          <p>
            Copy <code>pistondecompiler.example.toml</code> to{" "}
            <code>pistondecompiler.toml</code>. Enter your provider, models, and
            current prices. Set the API key in the environment variable named by{" "}
            <code>ai.api_key_env</code>, then restart PistonDecompiler.
          </p>
          <p>
            API keys stay on the backend. Existing binary budgets remain fixed.
            Provider prices determine cost estimates, so use the rates for your
            actual endpoint.
          </p>
        </section>
      </div>
    </>
  )
}
