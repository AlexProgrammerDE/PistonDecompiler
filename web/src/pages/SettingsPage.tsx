import { useQuery } from "@tanstack/react-query"
import { settingsQuery } from "@/lib/api"
import { ErrorNotice, LoadingRows } from "@/components/Feedback"
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
              <dd>{s.aiConfigured ? "Ready" : "Set the model and API key"}</dd>
              <dt>Endpoint</dt>
              <dd className="break-all">{s.providerUrl}</dd>
              <dt>Map model</dt>
              <dd>{s.model || "Not configured"}</dd>
              <dt>Decision model</dt>
              <dd>{s.decisionModel || "Disabled"}</dd>
              {s.decisionModel ? (
                <>
                  <dt>Decision endpoint</dt>
                  <dd className="break-all">{s.decisionEndpoint}</dd>
                  <dt>Routing threshold</dt>
                  <dd>{s.decisionThreshold}</dd>
                </>
              ) : null}
              <dt>Escalation model</dt>
              <dd>{s.escalationModel || "Disabled"}</dd>
              <dt>Concurrent requests</dt>
              <dd>{s.concurrency}</dd>
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
            <code>pistondecompiler.toml</code>. Enter your provider and models.
            Set the API key in the environment variable named by{" "}
            <code>ai.api_key_env</code>, then restart PistonDecompiler.
          </p>
          <p>
            API keys stay on the backend. Cost tracking uses provider receipts.
            Configure spending limits in your provider account.
          </p>
        </section>
      </div>
    </>
  )
}
