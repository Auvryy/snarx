# ADR 0001: Hybrid TypeScript Monorepo + Native Rust Sandbox Binary

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

`snarx` spans three runtimes:
1. A local terminal CLI & transparent MCP stdio proxy
2. A Linux kernel containment layer (`Landlock` + `Bubblewrap`) for untrusted MCP servers
3. A zero-login, 100% offline static browser workbench (`< 600 KB` gzipped)

Writing everything in Rust would require either duplicating security rules/parsers in TypeScript for the web workbench or maintaining a heavy `wasm-bindgen` bridge. Conversely, writing Linux kernel Landlock syscalls in Node.js is fragile and indirect.

## Decision

We adopt a **hybrid monorepo**:
- **`packages/core` (Pure TypeScript):** Single source of truth for the `.snarx` trace schema, secret redaction, SHA-256 hash chaining, Ed25519 Web Crypto signing/verification, transcript normalization, and deterministic security rules. Zero Node/DOM dependencies.
- **`packages/cli` (TypeScript, Node 22):** CLI entrypoint and live MCP stdio JSON-RPC proxy importing `@snarx/core`.
- **`packages/sandbox-rs` (Rust):** A minimal, focused native binary (`snarx-sandbox`) responsible exclusively for probing Linux kernel capabilities (Landlock ABI + unprivileged user namespaces) and enforcing fail-closed filesystem/network containment.
- **`apps/web` (Vite + React 19 + `@xyflow/react` + QuickJS-NG WASM):** Zero-login static workbench importing `@snarx/core` directly.

## Consequences

- **Positive:** Zero parser or rule drift between CLI and browser; high solo build velocity; native kernel-level syscall safety in Rust where it matters most.
- **Negative:** Contributors building the Linux sandbox locally need the Rust toolchain (`cargo`), though non-sandbox CLI and web development only require Node 22 + pnpm.
