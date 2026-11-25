# snarx

[![CI](https://github.com/Auvryy/snarx/actions/workflows/ci.yml/badge.svg)](https://github.com/Auvryy/snarx/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

**Local-first security sandbox, MCP proxy, and offline time-travel policy debugger for AI coding agents** (Claude Code, OpenAI Codex CLI, Google Antigravity `agy`, Gemini CLI, and MCP servers).

> **Zero cloud uploads. Zero mandatory logins. Fail-closed Linux kernel containment.**

---

## Why `snarx`?

Local coding agents and Model Context Protocol (MCP) servers run directly on developer laptops with ambient access to `~/.ssh`, `~/.aws`, `.env`, and local shells. `snarx` gives you:

1. **Fail-Closed Linux Sandbox (`snarx proxy --sandbox`)** — Jails untrusted stdio MCP servers using a native Rust Landlock + Bubblewrap containment binary (`snarx-sandbox`), blocking sensitive paths and unauthorized egress.
2. **Live MCP Attack Detection** — Continuously SHA-256 hash-pins `tools/list` schemas to catch mid-session tool rug pulls, scans responses for invisible Unicode prompt injections, and auto-redacts leaked API keys (`sk-`, `ghp_`, `AKIA`, private keys) before writing tamper-evident `.snarx` bundles.
3. **Unified Multi-Agent Timeline** — Normalizes transcripts from Claude Code, Codex CLI, `agy`, and live MCP streams into one canonical format to pinpoint loops, token burn, and rogue tool calls.
4. **Offline Time-Travel Policy Workbench (`< 600 KB` gzipped)** — Drop a `.snarx` bundle into the 100% static browser workbench, verify its SHA-256 hash chain & Ed25519 signature via Web Crypto API, fork at any step `N`, run a custom JS policy rule inside an isolated **QuickJS-NG WASM Web Worker** (250 ms kill switch), and compare **Original Bad Path vs. Safe Blocked Path** without spending API tokens.

---

## Architecture

```text
[ Local AI Agent: Claude Code / Codex / agy / Gemini CLI ]
                         │
        (MCP stdio Proxy / Transcript Importer)
                         ▼
[ packages/cli  ──►  packages/sandbox-rs (Landlock + bwrap) ]
  1. Normalize events via packages/core (shared zero-IO engine)
  2. Continuous SHA-256 tool schema hash-pinning & hidden-Unicode scan
  3. Redact secrets BEFORE hashing/signing -> portable .snarx bundle
                         │
     (Drag-and-drop file OR locked 127.0.0.1 ephemeral bridge)
                         ▼
[ apps/web — Static Browser Workbench (< 600 KB gzipped, Offline) ]
  1. Verify Ed25519 signature & SHA-256 hash chain (Web Crypto API)
  2. Interactive DAG / timeline (@xyflow/react)
  3. Fork at step N -> QuickJS-NG WASM Worker (250 ms hard kill switch)
```

---

## Monorepo Layout

```text
snarx/
├── packages/
│   ├── core/          # Runtime-agnostic TypeScript core (schema, redactor, crypto, rules)
│   ├── cli/           # CLI & live MCP stdio proxy (snarx proxy / import / scan)
│   └── sandbox-rs/    # Native Rust Linux Landlock + bwrap fail-closed sandbox binary
├── apps/
│   └── web/           # Static React 19 + @xyflow/react + QuickJS-NG WASM workbench
├── docs/
│   └── adr/           # Architecture Decision Records
├── fixtures/          # Adversarial attack traces for deterministic tests & live demo
└── packaging/
    └── aur/           # Arch Linux PKGBUILD
```

---

## Local Development

### Prerequisites
- **Node.js** `>= 22` and **pnpm** `>= 10`
- **Rust** (`cargo` / `rustc`) for `packages/sandbox-rs`
- **Linux (`bwrap` + Landlock kernel)** for `--sandbox` containment

### Quick Start

```bash
pnpm install
pnpm check          # Biome lint + TypeScript typecheck + Vitest
pnpm build          # Build core, cli, and web workbench
pnpm build:sandbox  # Build native Rust snarx-sandbox binary
pnpm dev:web        # Launch the offline browser workbench locally
```

---

## Core Security Invariants

1. **Single Source of Truth:** Schema validation, redaction, hash-chaining, Ed25519 verification, and deterministic security rules live exclusively in `packages/core` (zero filesystem or child-process dependencies).
2. **Fail-Closed Sandboxing:** If kernel capabilities (unprivileged user namespaces or Landlock ABI) are unavailable, `snarx-sandbox` aborts with explicit remediation steps—never silently falling back to unprotected execution.
3. **Redaction Before Signing:** Secret patterns are scrubbed prior to hashing, signing, or exporting any `.snarx` file.
4. **Isolated Browser Policy Execution:** User-authored rules run strictly inside a QuickJS-NG WASM Web Worker with a hard 250 ms termination kill switch—never via `eval()` or `new Function()`.
5. **Locked Local Bridge:** Any CLI-to-browser bridge binds strictly to `127.0.0.1`, validates `Host`/`Origin`, and requires a per-session cryptographic bearer token.

---

## Contributing & Security

- Read [CONTRIBUTING.md](./CONTRIBUTING.md) for local setup, Conventional Commits, and PR guidelines.
- Read [SECURITY.md](./SECURITY.md) to report vulnerabilities or review our threat model.
- Read [docs/adr/](./docs/adr/) for key architectural trade-offs.
