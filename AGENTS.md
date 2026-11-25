# AGENTS.md — Repository Instructions for AI Coding Agents

This file defines mandatory workflow, git hygiene, architecture, and security rules for all AI coding agents working on **`snarx`** (Antigravity `agy`, Claude Code, OpenAI Codex CLI, Gemini CLI, Cursor, Copilot, etc.).

---

## 1. Git, Branching & Commit Rules (STRICT)

1. **NEVER push directly to `main`.**
   - Always create and work on a descriptive branch before making changes:
     - `feat/<short-name>` (e.g., `feat/core-hash-chain`)
     - `fix/<short-name>` (e.g., `fix/bwrap-userns-probe`)
     - `docs/<short-name>` (e.g., `docs/adr-bundle-budget`)
     - `ci/<short-name>` (e.g., `ci/bundle-size-gate`)
   - Changes merge into `main` **only via Pull Request** after CI passes.
2. **NEVER push automatically.**
   - Do not run `git push` unless the user explicitly asks you to push (and even then, only push feature/fix branches—never `main`).
3. **Always break work into small, atomic commits.**
   - Do not lump unrelated files or features into a single giant commit.
   - Each commit must have **one clear purpose** (e.g., separate schema/core logic, unit tests, CLI wiring, and docs into distinct commits when meaningful).
   - Use **Conventional Commits**:
     - `feat(core): add SHA-256 hash chain sealing`
     - `test(core): add rug-pull adversarial fixture tests`
     - `fix(sandbox-rs): fail closed when Landlock ABI is missing`
     - `docs(adr): record QuickJS-NG WASM worker decision`
     - `ci: enforce 600 KB gzipped web bundle budget`
4. **Never bypass git hooks or checks.**
   - Never use `git commit --no-verify`.

---

## 2. Verification Before Committing

Before committing any code change, run the relevant local checks and ensure they pass:

```bash
pnpm build          # Build packages/core, packages/cli, and apps/web
pnpm check          # Biome lint + TypeScript typecheck + Vitest
```

If `packages/sandbox-rs` was modified, also run:

```bash
cargo test --manifest-path packages/sandbox-rs/Cargo.toml
```

### Anti-Shortcut Rule
Never silence failures by adding `@ts-ignore`, `@ts-nocheck`, `biome-ignore`, `.skip()`, empty `catch {}` blocks, or weakening test assertions. Fix the root cause.

---

## 3. Monorepo Architecture & Boundaries

```text
packages/core        # Pure TypeScript, zero-IO single source of truth
packages/cli         # Node 22 CLI & live MCP stdio proxy (imports @snarx/core)
packages/sandbox-rs  # Native Rust Linux Landlock + bwrap fail-closed sandbox binary
apps/web             # Zero-login static React 19 + @xyflow/react + QuickJS WASM workbench
docs/adr             # Architecture Decision Records
fixtures             # Synthetic adversarial attack traces (NEVER real secrets)
```

### Hard Invariants
1. **`packages/core` must stay 100% runtime-agnostic.**
   - Never import `node:fs`, `node:child_process`, `node:path`, or browser DOM APIs in `packages/core`.
   - Use Web Crypto API (`crypto.subtle`) so hashing (`SHA-256`) and signing/verification (`Ed25519`) work identically in Node 22 and browsers.
2. **Fail-Closed Sandboxing (`packages/sandbox-rs`).**
   - Always probe Linux kernel capabilities (Landlock + unprivileged user namespaces) before launching untrusted MCP servers. If unavailable, abort with exit code `2` and clear remediation guidance—never silently fall back to unprotected execution.
3. **Redaction Before Signing.**
   - Secret patterns (`sk-`, `ghp_`, `AKIA`, private keys, bearer tokens) must always be redacted *before* hashing, signing, or writing any `.snarx` trace file.
4. **Isolated Browser Policy Execution (`apps/web`).**
   - User-edited policy scripts must run strictly inside a QuickJS-NG WASM Web Worker with a hard `250 ms` kill switch—never via `eval()`, `new Function()`, or main-thread execution.
5. **Locked Local Bridge.**
   - Any CLI-to-browser bridge must bind strictly to `127.0.0.1` (never `0.0.0.0`), validate `Host` and `Origin` allowlists, and require a per-session cryptographic bearer token.
6. **Strict Static Bundle Budget (`apps/web`).**
   - Keep production gzipped output **under 600 KB** (target `~550 KB`). Do not add heavy dependencies (DuckDB-Wasm, ELKjs) or anything requiring `COOP`/`COEP` shared-memory headers on static hosts.

---

## 4. Code Style & Tooling

- **Formatter & Linter:** Biome (`biome.json`) — 2 spaces, double quotes, semicolons, 100-char line width (4 spaces in Rust).
- **TypeScript:** Strict mode (`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`).
- **Keep scope tight:** Prefer small, well-tested vertical slices over speculative abstractions.
