---
name: ldap-axi
description: "Read Active Directory and LDAPv3 directories safely with ldap-axi (read-only). Use for directory users, groups, computers, server capabilities, and authentication diagnostics."
user-invocable: false
---

# ldap-axi

Read Active Directory and LDAPv3 directories safely with ldap-axi (read-only).
The CLI is strictly read-only and never exposes a directory mutation operation.

## Workflow

Run `npx -y @knowttl/ldap-axi` for the current configured connection summary.
Run `npx -y @knowttl/ldap-axi entry search --help` to explore a directory safely
Use `npx -y @knowttl/ldap-axi user list`, `npx -y @knowttl/ldap-axi group list`, or `npx -y @knowttl/ldap-axi computer list` for typed reads.
Computer reads use AD machine accounts or a stated generic LDAPv3 device fallback; use `npx -y @knowttl/ldap-axi computer show <identifier-or-dn>` for details.
Run `npx -y @knowttl/ldap-axi server` for advertised rootDSE capabilities, naming contexts, limits, and detected or overridden flavor.
Run `npx -y @knowttl/ldap-axi auth status` to report the selected authentication, or `npx -y @knowttl/ldap-axi auth status --offline` to report it without binding.

## Command discovery

These implemented commands provide flags, defaults, and examples without connecting:

- `npx -y @knowttl/ldap-axi entry search --help`
- `npx -y @knowttl/ldap-axi entry show --help`
- `npx -y @knowttl/ldap-axi user list --help`
- `npx -y @knowttl/ldap-axi user show --help`
- `npx -y @knowttl/ldap-axi user groups --help`
- `npx -y @knowttl/ldap-axi group list --help`
- `npx -y @knowttl/ldap-axi group show --help`
- `npx -y @knowttl/ldap-axi group members --help`
- `npx -y @knowttl/ldap-axi computer list --help`
- `npx -y @knowttl/ldap-axi computer show --help`
- `npx -y @knowttl/ldap-axi auth status --help`
- `npx -y @knowttl/ldap-axi server --help`
- `npx -y @knowttl/ldap-axi profile list --help`
- `npx -y @knowttl/ldap-axi config path --help`

## Authentication

Authentication defaults to `auto` and attempts one ambient GSSAPI or Windows SSPI Negotiate context after the selected transport is ready, using TLS channel binding when TLS is present.
A provider, runtime, credential, target, context, TLS, or LDAP failure is terminal and never silently selects the configured password.
Use `--auth simple` for the existing LDAP simple bind and to preserve a configured service identity.
Simple authentication never enters the GSSAPI protected path.
Use `--anonymous` only when anonymous access is explicitly intended.
Credentials belong in `LDAP_AXI_BIND_DN` and `LDAP_AXI_BIND_PASSWORD` or a version 1 profile with `bindDn` and a `bindPassword` SecretRef, never argv.
Profiles live in the platform config directory's `ldap-axi/config.json`; use `npx -y @knowttl/ldap-axi config path` and `npx -y @knowttl/ldap-axi profile list` to discover them.
SecretRefs use `{env: NAME}` or `{file: absolutePath}`; password files must be private on POSIX, and Windows ACL permissions are reported unchecked because runtime platform tools are forbidden.

The URL scheme selects the GSSAPI transport and there is no fallback between them.
Verified LDAPS or StartTLS binds with TLS channel binding and no SASL security layer; plain `ldap://` binds with a mandatory confidentiality layer that wraps every post-bind LDAP message, and needs no `--insecure-plaintext`.
`--tls-no-verify` is still refused for a TLS GSSAPI bind.
Use `--tls-max-version 1.2` or the matching config setting only for verified LDAPS/StartTLS endpoints that require a TLS 1.2 cap.
`--gssapi-protection` is accepted only when it names the layer the URL scheme already requires.
The optional in-repository `kerberos@7.0.0` provider is loaded only from the sealed adapter.
Its verified patched prebuild or source fallback exposes actual confidentiality and integrity results, channel-binding application data, and protected post-bind LDAP transport.
Every Linux native path, including a verified prebuild, requires compatible system GSSAPI/Kerberos runtime libraries.
On Linux, libgssapi_krb5.so.2 must be discoverable by the dynamic loader; Nix and WSL users may need an environment wrapper or LD_LIBRARY_PATH, and unavailable libraries are reported as provider unavailable rather than treated as zero-config support.
Linux source fallback additionally needs Python, node-gyp, a C++ compiler, and Kerberos/GSS development headers; Windows source fallback needs node-gyp, MSVC, and the Windows SDK.
Provider or runtime unavailability is reported as `GSSAPI_UNAVAILABLE`; explicit `--auth simple` remains usable and does not load the provider.
Linux musl, Linux arm64, Windows arm64, and macOS are excluded.
See the [support matrix](https://github.com/knowttl/ldap-axi/blob/main/docs/support-matrix.md) for installation requirements and verified platform status.

Because `auto` may use the logged-in identity, operators who require the configured simple-bind identity must select `--auth simple` before running a command.
Offline checks do not prove ticket acquisition, AD acceptance, Windows behavior, channel-binding agreement, server security-layer acceptance, protected-transport interoperability, or bound identity.

## Safety

Do not use passwords, tickets, keytabs, cache contents, raw tokens, or directory captures on the command line or in fixtures.
ldap-axi does not shell out to platform tools and does not retry authentication.
All reads use bounded paging, preserve TLS verification, and report partial results honestly.
