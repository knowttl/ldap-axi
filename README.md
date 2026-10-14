# ldap-axi

An agent-facing CLI for reading LDAP directories from the shell, built to the
[AXI](https://agentskills.io) standard for CLI tools that autonomous agents drive through shell execution.

Active Directory and generic LDAPv3 are both first-class targets, and the tool runs on Linux and Windows.

## Status: stage 2 plus Phase B ambient GSSAPI authentication and `auth status`

Eight read commands ship - `entry search`, `entry show`, `user list`, `user show`, `user groups`, `group list`,
`group show`, `group members` - for both Active Directory and generic LDAPv3, plus the `auth status`
diagnostic and the home view.
`computer`, `server`, and `setup` are planned.
Authentication defaults to `auto`, which makes one ambient GSSAPI/SSPI attempt and never silently selects a
configured password; `--auth simple` preserves a configured service identity and never loads the native
provider.
The URL scheme selects the GSSAPI transport with no fallback: verified LDAPS or StartTLS binds with channel
binding and no SASL security layer, while plain `ldap://` binds with a mandatory confidentiality layer that
wraps every post-bind LDAP PDU.
The optional native provider is built from the in-repository `kerberos@7.0.0` source, is supported only on
Linux glibc x64 and Windows x64, and reports its absence as `GSSAPI_UNAVAILABLE` rather than failing the tool.
Offline tests do not prove ticket acquisition, AD wire acceptance, Windows SSPI behavior, server
security-layer acceptance, channel-binding agreement, protected-transport interoperability, or Who Am I
identity.

**[`docs/support-matrix.md`](docs/support-matrix.md) is the full status surface**: command states, platform and
native-provider matrix, Linux runtime-library requirements including the Nix/WSL `LD_LIBRARY_PATH` hazard,
release provenance, and what is proved versus unproved.

The npm package is `@knowttl/ldap-axi`; the executable remains `ldap-axi`.
Once published, install it with Node `>=24.11.0`:

```sh
npm install --global @knowttl/ldap-axi@0.1.1
ldap-axi auth status --offline
```

See the [support matrix](docs/support-matrix.md#installing-from-npm-before-native-release-assets-exist) for native installation requirements and the distinction between the 0.1.0 bootstrap and 0.1.1 release packages.

To work from a source checkout, install dependencies and run the required local gate:

```sh
npm install
npm run verify
```

For installation from a GitHub release archive on Windows or Linux, see
[release installation](docs/support-matrix.md#installing-a-github-release-archive).

The design is at [`docs/design/v1.md`](docs/design/v1.md), the authority for the command surface, the
read-only boundary, server-flavor detection, paging, output shape, TLS and credential rules, and the
client-library decision.
Every factual claim in it is cited to a source, and the claims marked "verified locally" were proved by
running code rather than read from documentation.

The required local check set is offline-only, uses wholly synthetic fixtures, and runs through one
`npm run verify` entry point.
Authentication selection defaults immediately to `auto` and accepts `--auth auto|gssapi|simple` or
`LDAP_AXI_AUTH`, with `--gssapi-service` and `LDAP_AXI_GSSAPI_SERVICE` for a host-based service override.
`--gssapi-protection none|confidentiality` and `LDAP_AXI_GSSAPI_PROTECTION` are accepted only when they name the layer the URL scheme already requires.
The URL scheme selects the GSSAPI layer: verified LDAPS or StartTLS negotiates no SASL security layer, while plain `ldap://` negotiates a mandatory confidentiality layer.
`auto` attempts one ambient GSSAPI/SSPI preparation after the selected transport is ready, applying TLS channel binding when TLS is present, and fails terminally when the provider,
runtime, ambient credential, target, or context is unavailable; it never silently selects the configured password.
Use `--auth simple` to preserve a configured service identity; simple authentication never enters the GSSAPI protected path.
Use `--anonymous` only for an explicit anonymous invocation.
The source package includes a Linux glibc x64 N-API 9 prebuild produced on Rocky Linux 8.10 and verified by its package-pinned SHA-256 digest.
The Linux prebuild requires glibc 2.28 or newer, a libstdc++ providing GLIBCXX_3.4.25 or newer, compatible Kerberos/GSS runtime libraries, and Node 24.11.0 or newer.
CI rejects artifacts requiring symbols newer than GLIBC_2.28 or GLIBCXX_3.4.25 and load-tests the same artifact on Node 24.11.0 and the current Node 24 release.
When a target prebuild is not bundled, installation fetches only the binary from the matching versioned GitHub release and verifies it against the digest pinned inside the published package before loading it.
Every prebuild retrieval, manifest, digest, or native verification failure is cleaned up and falls back to one source-build attempt in automatic mode; forced prebuild mode fails closed.
GitHub-hosted native runners build and behavior-test Linux glibc x64 and Windows x64 artifacts and forced-source consumers from the release commit.
See [release and provenance](docs/support-matrix.md#release-and-provenance) for the tag workflow's publication contract.
Tagged binaries and the package receive GitHub artifact provenance attestations, but the binaries are not Authenticode or platform-code-signed and package installation does not independently verify the attestation.
Linux musl, Linux arm64, Windows arm64, and macOS are rejected rather than sent through an unqualified native build.
The source fallback is supported only on Linux glibc x64 and Windows x64.
Every Linux native path, including a verified prebuild, requires compatible system Kerberos/GSS runtime libraries.
Linux source builds additionally need Python, the installed node-gyp dependency, a C++ compiler, and Kerberos/GSS development headers.
Windows source builds need node-gyp, MSVC, and the Windows SDK.
node-gyp may download matching Node headers when they are not already cached, so source fallback is not an offline guarantee.
The root build dependencies add roughly 10 MB unpacked to a clean dependency tree, and the bundled Linux binary adds about 272 KB.
Explicit simple mode does not load the provider and remains available when native installation fails.
Offline tests do not prove ticket acquisition, AD wire acceptance, Windows SSPI behavior, server security-layer
acceptance, channel-binding agreement, protected-transport interoperability, or Who Am I identity.
The opt-in `npm run test:local-directory` suite needs Linux and Docker and stays outside `npm run verify`.
See [the local-directory design](docs/design/v1.md#184-the-local-test-directory-is-the-drift-check) for its mocks and isolation rules, and [the support matrix](docs/support-matrix.md#what-is-proved-and-what-is-not) for qualified behavior and remaining limits.
The manual live smoke script (`npm run smoke:live -- --url ldaps://server:636`) requires a read-only directory
credential and `LDAP_AXI_LIVE=1`, runs one fixed read-only sequence, writes a redacted evidence file outside
this repository, stays outside the required check, and never runs automatically.

The captain-authorized native prebuild workflow and the manually dispatched local-directory workflow are the only
GitHub Actions workflows.
Neither receives directory credentials, and neither runs a live-directory test.

## Read-only

**ldap-axi v1 is read-only.**
It requires only directory read access, and it implements no add, modify, modifyDN, rename, move, delete,
password-set, password-reset, or write-capable extended operation.

This is an architectural invariant, not a default posture.

Read-only in LDAP is harder than it looks, and the design does not rely on the shape of an operation's name:

- **Extended operation is one protocol operation whose safety is entirely an OID.**
  `1.3.6.1.4.1.1466.20037` is StartTLS and changes nothing; `1.3.6.1.4.1.4203.1.11.1` is RFC 3062 Password
  Modify and changes a credential.
  So extended operations are denied by default and admitted by a two-OID allowlist.
- **Bind changes no entry and still has side effects.**
  A failed bind against Active Directory increments `badPwdCount` and can lock an account out, so the design
  permits exactly one bind per invocation and offers no credential-probing surface.
- **A control can carry semantics its operation does not**, so the control list is closed too.

Enforcement lives in a sealed client module that never exposes the underlying LDAP client, rather than in
command-layer discipline.
See `docs/design/v1.md` §0, §1.5, §3, and §4.

An ldap-axi release that needs directory write access is wrong.

## Planned v1 surface

Four read nouns - `entry`, `user`, `group`, `computer` - plus `server`, `auth status`, and `setup` helpers.
`entry search`, `entry show`, `user list`, `user show`, `user groups`, `group list`, `group show`,
`group members`, and `auth status` are implemented; `computer list`, `computer show`, `server`, and `setup`
remain planned.

The design states per command which behavior is flavor-neutral and which is flavor-specific, and every group
membership result reports whether it is transitive and how it was derived, because a direct-membership answer
mistaken for a transitive one is a security-relevant error.

See `docs/design/v1.md` §1 for what ships, what is deferred, and why, and §5.4 for the flavor table.

## Relationship to trxo/ldap-mcp

[`trxo/ldap-mcp`](https://github.com/trxo/ldap-mcp) is used as a behavioral, domain, and scope reference only.
It is not a fork base, not a dependency, and not part of ldap-axi at runtime.

`docs/design/v1.md` §1.1 tabulates every deliberate divergence from it with the reason, including read-only by
architecture rather than by an unset flag, structured output instead of prose-wrapped JSON, decoded binary
attributes, in-process bounded paging instead of draining every page into memory, and no secret on the command
line.

## License

[MIT](LICENSE), copyright knowttl.
