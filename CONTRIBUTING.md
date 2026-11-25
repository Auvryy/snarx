# Contributing to snarx

Thank you for contributing to **snarx**!

## Development Setup

```bash
git clone git@github.com:Auvryy/snarx.git
cd snarx
pnpm install
pnpm check
```

To build or test the Rust Linux sandbox binary:

```bash
pnpm build:sandbox
pnpm test:sandbox
```

## Architecture Rules

1. **`packages/core` must stay runtime-agnostic.** Never import `node:fs`, `node:child_process`, or browser DOM APIs inside `packages/core`. It must run identically in Node 22 and modern browsers.
2. **Keep `apps/web` under 600 KB gzipped.** Avoid heavy dependencies (e.g., DuckDB-Wasm, ELKjs) or anything requiring `COOP`/`COEP` shared-memory headers on static hosts.
3. **Fail closed on security boundaries.** Never silently degrade `--sandbox` or bypass signature/hash verification.

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat(core): add invisible Unicode scanner`
- `fix(sandbox-rs): handle bwrap >= 0.12 userns probe on linux-hardened`
- `docs(adr): document hybrid TS + Rust architecture`
- `ci: add web bundle-size budget check`

## Pull Request Checklist

- [ ] `pnpm check` passes (Biome lint, TypeScript typecheck, Vitest)
- [ ] `pnpm test:sandbox` passes (if touching `packages/sandbox-rs`)
- [ ] New security rules include deterministic adversarial fixtures in `fixtures/`
- [ ] Any major architectural decision includes an ADR in `docs/adr/`
