# Changelog

All notable changes to **snarx** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial monorepo scaffold (`packages/core`, `packages/cli`, `packages/sandbox-rs`, `apps/web`).
- Project governance documentation (`README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`, `docs/adr/`).
- GitHub Actions CI workflow (Biome lint, TypeScript typecheck, Vitest, Rust cargo check/test, and web bundle-size budget check).
