# Security Policy

## Threat Model & Scope

`snarx` is a local-first security sandbox, MCP proxy, and offline forensic debugger for AI coding agents. Security invariants are treated as hard requirements:

- **Fail-Closed OS Containment (`packages/sandbox-rs`):** When `--sandbox` is requested, `snarx` probes Linux kernel capabilities (Landlock ABI + unprivileged user namespaces) before launching untrusted MCP servers. If containment cannot be enforced, execution aborts rather than running unprotected.
- **No Silent Secret Leakage:** Secret patterns (`sk-`, `ghp_`, `AKIA`, private key headers, bearer tokens) are redacted *before* hashing, signing, or writing `.snarx` trace bundles.
- **WASM Policy Isolation (`apps/web`):** User-supplied policy rules execute inside a QuickJS-NG WebAssembly Web Worker with zero DOM/network access and a 250 ms termination kill switch.
- **DNS-Rebinding Protection:** Local CLI-to-browser bridges bind strictly to `127.0.0.1`, enforce strict `Host`/`Origin` allowlists, and require a short-lived cryptographic bearer token per session.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities (especially sandbox escapes, DNS-rebinding flaws, or WASM worker escapes).

Instead, report vulnerabilities privately via GitHub Security Advisories on `Auvryy/snarx` with:
1. A clear description of the vulnerability and affected package (`core`, `cli`, `sandbox-rs`, or `web`)
2. Minimal reproduction steps or proof-of-concept
3. Your OS/kernel version (if reporting a Linux sandbox issue)

We aim to acknowledge reports within 48 hours and coordinate a fix before public disclosure.
