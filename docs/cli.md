# CLI usage

The CLI calls the same `ScanApplicationService` used by the HTTP API. It accepts only the
implemented commands below; scan options are intentionally limited to JSON formatting.

```sh
pnpm start -- --help
pnpm start -- --version
pnpm start -- scan https://your-authorized-host.example/
pnpm start -- scan https://your-authorized-host.example/ --json
```

The release package includes the compiled `blueleaf` executable. After installing the package,
invoke the same commands as `blueleaf --help` or
`blueleaf scan https://your-authorized-host.example/ --json`. Replace the example hostname with a
target you own or are authorized to assess.
Package consumers may import the public TypeScript API from the package root after building; the
published package includes compiled ESM, declarations, JSON Schemas, and documentation.

Maintainers can verify the compiled CLI and API startup after a build with `pnpm release:smoke`.
It starts only a loopback API process, uses an ephemeral local test key, checks authenticated
health/readiness, and does not probe an external target. The API integration tests separately
verify the graceful shutdown function and active-scan cancellation.

Human output summarizes HTTP status, detected technologies and confidence, assessment state,
provider coverage, and per-technology remediation state. It does not print response headers,
cookies, body snippets, request secrets, or URL query/fragment values. `--json` writes the complete
versioned `ScanResult` matching [`schemas/scan-result.schema.json`](../schemas/scan-result.schema.json).
The target URL included in output has its query and fragment removed.

Exit codes:

| Code | Meaning                                                                                           |
| ---: | ------------------------------------------------------------------------------------------------- |
|    0 | Scan completed with supported assessment coverage. A finding does not make the scan command fail. |
|    1 | Scan completed with unknown, incomplete, stale, conflicting, unavailable, or manual-review data.  |
|    2 | Invalid usage/request or target rejected by policy.                                               |
|    3 | Operational failure such as timeout, TLS, network, or provider failure.                           |

Use only on systems you own or are authorized to assess. The workflow is a single bounded passive
HTTP/HTTPS probe; it does not crawl, submit forms, execute scripts, fuzz, exploit, brute-force, or
scan ports. Unknown or incomplete results do not indicate safety.
