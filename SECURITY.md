# Security policy

## Supported versions

Security fixes target the latest published 0.x release.
Upgrade to the latest release before checking whether a problem still occurs.
Older releases do not receive separate maintenance updates.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/knowttl/ldap-axi/security/advisories/new) to report a suspected vulnerability privately.
If that form is unavailable, open an issue requesting a private reporting channel without including vulnerability details or sensitive data.

Include the affected version, operating system, Node version, impact, and minimal reproduction using synthetic data.
Do not include credentials, passwords, tickets, keytabs, credential caches, raw tokens, real directory identifiers, or captured directory content.
Coordinate public disclosure after a fix is available.

## Security boundaries

ldap-axi v1 implements directory reads only, with no directory mutation path.
Authentication still has server-side effects: a failed bind can increment account lockout counters.
Use an account with directory read access only and preserve TLS verification.
See the [v1 design](docs/design/v1.md#0-invariant-r-v1-is-read-only) for the enforced boundary and [support matrix](docs/support-matrix.md) for platform and native-provider limitations.

Windows credential-file ACLs are reported as unchecked; operators must restrict access to the owning account.
Native binaries use package-pinned SHA-256 digests and release provenance; they are not platform-code-signed, and installation does not independently verify attestations.
