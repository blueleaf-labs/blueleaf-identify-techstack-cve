# Contributing

Blueleaf Identify uses strict TypeScript, native ESM (`NodeNext`), and a layered architecture:
domain contracts are independent of infrastructure; application services own orchestration and
provider ports; adapters handle HTTP, CLI, API, configuration, and provider-specific formats. Keep
that dependency direction intact. CLI and API must continue to use the shared
`ScanApplicationService` rather than duplicating pipeline behavior.

## Development requirements

- Use Node.js 22 or newer and pnpm 10.
- Keep runtime dependencies minimal. Do not add a database, framework, or provider dependency
  without a concrete need and an update to the architecture/configuration documentation.
- Preserve versioned domain contracts and JSON Schemas. A breaking contract change requires a new
  schema version, compatibility notes, and release documentation.
- Keep target probing passive and bounded. Preserve DNS/IP validation, checked-IP pinning,
  redirect revalidation, TLS verification, timeouts, and response limits through every interface.
- Keep secrets out of source, fixtures, logs, test output, and command-line arguments. Use
  synthetic values for tests and protected configuration for local operation.
- Do not invent technology versions, package identity, advisory coverage, security conclusions,
  remediation commands, or fixed releases. Preserve unknown, conflicting, and unavailable states.
- Do not add crawling, JavaScript execution, form submission, brute forcing, port scanning,
  fuzzing, exploitation, remediation execution, or undocumented provider scraping.

## Tests and quality checks

Add or update deterministic tests for implemented behavior. Prefer mocked providers and local HTTP/TLS
fixtures; automated tests must not rely on public websites or live vulnerability databases. Keep
fixtures clearly test-only and never reuse fixture credentials outside tests.

Run the full validation set before submitting a change:

```sh
pnpm typecheck
pnpm lint
pnpm test
pnpm format:check
pnpm build
pnpm release:smoke
```

`pnpm release:smoke` expects a completed build. It checks the compiled CLI and local authenticated
API health/readiness; it does not probe an external target or publish a package. Use `pnpm format`
only when you intend to rewrite formatting, then review the resulting diff.

Update `PROJECT_CONTEXT.md`, `ARCHITECTURE.md`, the relevant guides under `docs/`, and
`CHANGELOG.md` when implementation, supported behavior, security boundaries, or public contracts
change. Keep README usage and `package.json` metadata aligned with the actual CLI, API, package
exports, and scripts. Before proposing a release, inspect the complete Git status and diff and
confirm no credentials, environment files, generated output, or local-only artifacts are included.
