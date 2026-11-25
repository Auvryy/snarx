#!/usr/bin/env node
import { SNARX_SCHEMA_VERSION, redactSecrets } from "@snarx/core";

const args = process.argv.slice(2);
const command = args[0] ?? "help";

if (command === "--version" || command === "-v") {
  console.log(`snarx v${SNARX_SCHEMA_VERSION}`);
  process.exit(0);
}

if (command === "redact-check") {
  const input = args.slice(1).join(" ");
  const { redacted, matches } = redactSecrets(input);
  console.log(JSON.stringify({ redacted, matches }, null, 2));
  process.exit(0);
}

console.log(`snarx v${SNARX_SCHEMA_VERSION} — Local-first AI agent security sandbox & debugger

Usage:
  snarx proxy [--sandbox] -- <mcp-cmd>   Wrap an MCP stdio server (coming next)
  snarx scan <trace.snarx>               Evaluate deterministic security rules
  snarx redact-check <text>              Verify secret redaction locally
  snarx --version                        Show version
`);
