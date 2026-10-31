# Safety and permissions

## Directory boundary

v1 is strictly read-only and requires only directory read access.
It implements no add, modify, modifyDN, rename, move, delete, password-set, password-reset, or write-capable extended operation.
No flag or environment setting unlocks writes; `LDAP_AXI_READ_ONLY=false` leaves this invariant intact.
`setup` writes only the explicitly selected local agent integration.
The sealed client admits only read operations and allowlisted controls and extended operations; see the [authoritative design](design/v1.md#3-read-only-posture-and-client-enforcement).

## Permission matrix

| Operation | Required permission or credential |
| --- | --- |
| Configured home, entry, user, group, computer and membership reads | Read access to selected base, entries, and attributes; no directory administrator role required |
| `server` | Access to advertised rootDSE facts |
| Ambient authentication | Existing Kerberos cache on Linux or signed-in domain context on Windows |
| Simple authentication | Directory identity permitted to bind and read |
| Offline commands and help | Local configuration access only; no directory permission |
| `setup` | Write access to selected local agent configuration |

Every connected invocation uses one authentication exchange with no retry or password fallback.
A failed AD bind can increment lockout counters; inspect configuration offline before connecting.
Directory requests and authentication go only to the selected server; referrals are reported without being chased.

## Transport and credentials

TLS verification stays enabled by default.
`--ca-file` appends to Node's bundled trust roots; `--ca-only` replaces them.
`NODE_EXTRA_CA_CERTS` extends Node's store and must be set before starting Node.
Keep verification enabled rather than using `--tls-no-verify`.
Simple bind over unprotected LDAP requires `--insecure-plaintext`; anonymous access requires `--anonymous`.
Plain `ldap://` GSSAPI requires confidentiality and needs no plaintext override.
LDAPS/StartTLS GSSAPI uses verified TLS with channel binding and no SASL security layer.

Passwords come only from environment or file SecretRefs, never argv, inline config, or credential-bearing URLs.
Resolved passwords are redacted; directory data and configured identities are output intentionally.
`userPassword` and `unicodePwd` are never requested, including through raw attributes.
POSIX secret files must be private and owned by the current user; Windows ACL checks are reported as `unchecked (windows)` and remain the operator's responsibility.
See [configuration](configuration.md#profiles) for profile and secret examples and [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Installation and evidence

Windows native installation may download a digest-verified binary from the matching GitHub release.
Native artifacts have release attestations but are not platform-code-signed; installation does not independently verify attestations.
Platform requirements and what is proved versus unproved belong in the [support matrix](support-matrix.md#what-is-proved-and-what-is-not).
