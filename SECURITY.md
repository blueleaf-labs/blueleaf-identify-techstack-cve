# Security Policy

## Reporting a Vulnerability

Please do not report a suspected vulnerability in a public issue, pull request, discussion, or release comment. Reports should use a private channel so maintainers can investigate before details become public.

GitHub Private Vulnerability Reporting is enabled for this repository.

To report a suspected vulnerability, use the [Report a vulnerability](https://github.com/blueleaf-labs/blueleaf-identify-techstack-cve/security/advisories/new) feature under the repository's Security tab.

Reports submitted through this channel are private and available to repository maintainers. Please do not disclose vulnerability details publicly before coordinated disclosure.

Include enough detail to reproduce and assess the issue:

- Affected package version, runtime, operating system, and relevant configuration.
- The security impact and conditions required to trigger it.
- Concise reproduction steps or a minimal proof of concept, when safe to share.
- Relevant sanitized logs, error messages, or request/response excerpts.
- Any mitigation you have already tried.

Do not include unnecessary personal data, real user data, API keys, bearer tokens, passwords, private keys, production request headers, or other exposed production secrets. Redact secrets from proofs and logs before sending them.

Maintainers will acknowledge reports when practicable, assess severity and affected versions, coordinate a fix and disclosure with the reporter, and publish a security notice when appropriate.

There is no guaranteed response or resolution time. Please allow maintainers reasonable time to investigate and coordinate before public disclosure.

## Supported Versions

After v0.1.0 is published, the current `0.1.x` release line is the supported line. Please report issues against the latest published `0.1.x` version.

Older versions, unreleased snapshots, and development branches are not promised security fixes; maintainers may assess them to determine whether the current supported release is affected.

## Security Boundaries

Blueleaf Identify performs a bounded passive HTTP/HTTPS probe and analyzes the returned evidence. It is not a vulnerability scanner that exploits targets.

Scan only systems you own or are authorized to assess.

Unknown, incomplete, conflicting, stale, or unavailable results do not mean a target is secure.

See [docs/security.md](docs/security.md) for implemented application controls, their limitations, and infrastructure responsibilities.