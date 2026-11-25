import { SNARX_SCHEMA_VERSION, redactSecrets } from "@snarx/core";

export function App() {
  const sample = redactSecrets("Detected leaked token: sk-demo1234567890abcdef");

  return (
    <main
      style={{
        fontFamily: "system-ui, sans-serif",
        maxWidth: 720,
        margin: "3rem auto",
        padding: "0 1rem",
      }}
    >
      <h1>snarx workbench</h1>
      <p>
        Offline AI agent security &amp; time-travel policy debugger (schema v{SNARX_SCHEMA_VERSION}
        ).
      </p>
      <pre style={{ background: "#111", color: "#0f0", padding: "1rem", borderRadius: 8 }}>
        {sample.redacted}
      </pre>
    </main>
  );
}
