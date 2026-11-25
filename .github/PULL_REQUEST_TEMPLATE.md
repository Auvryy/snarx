## Summary

<!-- Briefly describe what this PR changes and why. -->

## Type of Change

- [ ] Bug fix (`fix`)
- [ ] New feature (`feat`)
- [ ] Security rule / fixture (`feat(core)`)
- [ ] Linux sandbox (`packages/sandbox-rs`)
- [ ] Documentation / ADR (`docs`)

## Verification Checklist

- [ ] `pnpm check` passes locally
- [ ] `pnpm test:sandbox` passes (if touching `packages/sandbox-rs`)
- [ ] `packages/core` remains free of Node filesystem/child-process and DOM imports
- [ ] Web bundle stays within the `< 600 KB` gzipped budget
