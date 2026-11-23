# Security policy

## Purpose

Sentinel is a defensive security monitoring platform built for learning and demonstration. Use it only with synthetic data or logs you are authorized to process. It contains no offensive functionality and must not be adapted for unauthorized access, surveillance or attacks.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.1.x | Yes |
| 1.0.x | No (upgrade to 1.1) |

## Reporting a vulnerability

Please do not open a public issue for security problems.

1. Use GitHub's private vulnerability reporting (**Security > Report a vulnerability** on the repository page), or contact the maintainer through the email address on their GitHub profile.
2. Include the affected version or commit, steps to reproduce, the impact you observed and any suggested fix.
3. You will receive an acknowledgement within 7 days. Confirmed issues are fixed in a patch release and credited in the changelog unless you prefer otherwise.

Please test only against your own local installation, never against systems you do not own.

## Security design summary

- Argon2id password hashing, password policy, account lockout and login rate limiting.
- Short-lived JWT access tokens kept in memory; rotating HttpOnly, SameSite=Strict refresh cookies with reuse detection.
- Role-based access control enforced on every API endpoint and tested by calling endpoints directly.
- Parameterized queries, whitelisted sorting, strict request validation.
- Upload limits, no execution of uploaded content, CSV formula-injection protection, escaped PDF output.
- Security headers, strict Content Security Policy, explicit CORS origins, generic error responses.
- Append-only audit log enforced by a PostgreSQL trigger, with secrets redacted.
- Secrets only in environment variables; startup refuses placeholder signing keys.
- Optional external services are off by default and receive the minimum data required.
- Public demo: a shared Read-Only Viewer account with no usable password; its profile and password cannot be changed and its role is reset to Viewer on every start.
- Request bodies are capped while they stream in; per-account login limits do not depend on the client address.
- Production mode adds HSTS, hides the interactive API docs and serves the web app with a same-origin Content Security Policy.
- CI runs gitleaks over the full Git history, pip-audit, bandit and npm audit on every push.

Full details: [docs/security-design.md](docs/security-design.md).

## Known limitations

- Rate limiting is per process.
- No multi-factor authentication or single sign-on.
- HTTPS must be provided by a reverse proxy in real deployments; set `SENTINEL_COOKIE_SECURE=true` behind it.
- No independent security review has been performed.
