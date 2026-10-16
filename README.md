# ldap-axi

An agent-facing CLI for reading LDAP directories from the shell, built to the
[AXI](https://agentskills.io) standard for CLI tools that autonomous agents drive through shell execution.

Active Directory and generic LDAPv3 are both first-class targets, and the tool runs on Linux and Windows.

## Install

Once 0.1.5 is published, install it with Node 24.11.0 or newer:

```sh
npm install --global @knowttl/ldap-axi@0.1.5
ldap-axi auth status --offline
```

See the [support matrix](docs/support-matrix.md#installing-from-npm-before-native-release-assets-exist) for native installation requirements and the distinction between bootstrap and tag-workflow packages.
The executable is `ldap-axi`.
Run `ldap-axi` with no arguments for the offline home view; see [skill installation hints](docs/design/v1.md#141-the-home-view) for its optional agent-host guidance.
Until 0.1.5 is published, use a source checkout:

```sh
git clone https://github.com/knowttl/ldap-axi.git
cd ldap-axi
npm ci
npm run build
node dist/src/cli.js config path
node dist/src/cli.js profile list
node dist/src/cli.js auth status --offline
```

When following the setup below from this checkout, replace `ldap-axi` with `node dist/src/cli.js` and run it from the checkout directory.
See [the support matrix](docs/support-matrix.md) for command status, supported platforms, native-provider installation, release provenance, and proved versus unproved behavior.
The [v1 design](docs/design/v1.md) defines the read-only boundary and command contracts.

## Simple-bind credentials

ldap-axi uses the version 1 profiles envelope defined in [the credential contract](docs/design/v1.md#111-credential-standard-profiles-and-secretrefs).
Run `ldap-axi config path` to find the file.
On Linux it is `$XDG_CONFIG_HOME/ldap-axi/config.json` when XDG_CONFIG_HOME is absolute, otherwise `~/.config/ldap-axi/config.json`.
On Windows it is `%APPDATA%\ldap-axi\config.json`; XDG variables are ignored.
There is no configuration discovery from the working directory.
Use `--config <path>` or `LDAP_AXI_CONFIG` to select another file.

Create the config directory with mode `0700` and the config file with mode `0600` on POSIX.
This retains ldap-axi's stricter private-config rule.
A synthetic example:

```json
{
  "version": 1,
  "defaultProfile": "work",
  "profiles": {
    "work": {
      "url": "ldaps://dc01.example.test:636",
      "auth": "simple",
      "bindDn": "uid=reader,dc=example,dc=test",
      "bindPassword": { "env": "LDAP_AXI_BIND_PASSWORD" },
      "caFile": "/absolute/path/corporate-root.pem"
    }
  }
}
```

Supply the referenced password variable through your secret manager or a secure terminal prompt, then run:

```sh
ldap-axi profile list
ldap-axi auth status --offline --profile work
ldap-axi user list --profile work --limit 10
```

`auth status --offline` reports selection and provenance without connecting or binding.
A live `auth status` performs one bind, so failed credentials can affect account lockout counters.
Use a directory account with read access only.

A password can also use a file SecretRef, such as `{"file":"/absolute/path/password"}`; use an absolute drive path on Windows.
Keep password files private (`0600` or `0400` on POSIX).
See [the credential contract](docs/design/v1.md#111-credential-standard-profiles-and-secretrefs) for reference defaults, file decoding, and accepted paths, and [file provenance](docs/design/v1.md#113-file-provenance-checks-and-the-windows-gap-stated-honestly) for the enforced checks.
Inline passwords, stored secrets, password flags, and credentials in LDAP URLs are refused.
ldap-axi does not store passwords or implement `auth login`.

**Windows exception to the credential standard:** runtime subprocesses and platform tools are forbidden by ldap-axi's architecture, so it cannot verify DACLs using PowerShell or `icacls`.
The operator must restrict file and directory ACLs to the owning account.
When simple authentication reads a password-file reference, `auth status` reports its permissions as `unchecked (windows)`, never as verified.

See [the credential contract](docs/design/v1.md#111-credential-standard-profiles-and-secretrefs) for profile selection, source isolation, environment fields, and precedence.
When supplying only `LDAP_AXI_BIND_PASSWORD` for a file profile, select it explicitly with `--profile` or `LDAP_AXI_PROFILE`; an unselected half env credential pair is an error.
For an env profile, set `LDAP_AXI_URL` (or pass `--url`), `LDAP_AXI_AUTH=simple`, `LDAP_AXI_BIND_DN`, and `LDAP_AXI_BIND_PASSWORD`.

Legacy top-level config and `credentials.env` formats are never used for authentication.
See [the migration contract](docs/design/v1.md#111-credential-standard-profiles-and-secretrefs) for when `CONFIG_MOVED` requires conversion to profiles and SecretRefs.
Config-path overrides and the deprecated alias are documented in [config locations](docs/design/v1.md#152-config-and-credential-locations).

For artium-axi, the package ships [axi-credential.schema.json](axi-credential.schema.json) with `bindPassword` marked `x-secret`.
A host can write a single `artium` profile under private HOME/XDG directories and inject `{"env":"ARTIUM_SECRET_0"}` without translating credentials.
The artium-axi adapter is delivered separately.

## Kerberos single sign-on on Linux

Authentication defaults to `auto`, which uses the ambient Kerberos credential and makes no password fallback.
It does not open simple-bind password files.
Use the server's real FQDN and explicitly select GSSAPI when following the earlier simple-bind setup:

```sh
ldap-axi auth status --offline --auth gssapi --url ldap://dc01.example.test:389
ldap-axi user list --auth gssapi --url ldap://dc01.example.test:389 --limit 10
```

Plain `ldap://` with GSSAPI negotiates mandatory confidentiality and encrypts every post-bind LDAP message.
It needs no CA file and no `--insecure-plaintext`.
Verified LDAPS or StartTLS uses TLS channel binding and no SASL security layer, with no transport fallback.
Simple bind over plaintext still requires explicit `--insecure-plaintext`.
Use `--auth simple` or a profile with `auth: "simple"` when a configured service identity is required.
Use `--anonymous` only for an explicitly anonymous invocation.

A Linux SSO host needs:

1. Linux glibc x64, glibc 2.28 or newer, Node 24.11.0 or newer, and the compatible C++ runtime described in the [support matrix](docs/support-matrix.md).
   musl and arm64 are rejected by design.
2. Loader-visible `libgssapi_krb5.so.2`, `libkrb5.so.3`, `libk5crypto.so.3`, `libcom_err.so.2`, `libkrb5support.so.0`, and `libkeyutils.so.1`.
   Debian/Ubuntu supplies these through `libgssapi-krb5-2`; RHEL/Rocky/Fedora uses `krb5-libs`.
   ldap-axi itself does not require a `kinit` binary.
   `krb5-user` or `krb5-workstation` is needed only when the operator wants `kinit`/`klist`.
3. A valid ticket in the default credential cache.
   Domain-joined hosts using sssd, realmd, or winbind normally obtain a logon TGT.
   MIT Kerberos resolves FILE, KEYRING, or KCM caches; KCM also needs `sssd-kcm` running.
   Live verification tested a FILE cache only.
4. A `krb5.conf` mapping the server hostname to its realm.
   Joined hosts normally already have this configuration.
5. A URL using the DC's FQDN matching its `ldap/<fqdn>` SPN.
   ldap-axi requests `ldap@<url-host>` without its own canonicalization.
   Avoid aliases, short names, and IP addresses; an IP-literal URL requires `--gssapi-service`.
   MIT's default `qualify_shortname` was observed to turn `localhost` into `ldap/localhost.@REALM`.
   Real FQDNs avoid that short-name trap.
6. For LDAPS or StartTLS, Node must trust the DC certificate.
   Use `--ca-file /absolute/path/corporate-root.pem`, a profile's `caFile`, or `NODE_EXTRA_CA_CERTS`.
   Node does not use `/etc/ssl/certs` by default.
   `--ca-file` appends to Node's roots; `--ca-only` replaces them.

For Nix/WSL, never prepend a whole system library directory to `LD_LIBRARY_PATH`.
Follow the [support matrix's Kerberos-soname shim instructions](docs/support-matrix.md) to avoid loading an incompatible system libuv into Node.
Provider or runtime absence is `GSSAPI_UNAVAILABLE`; failures are terminal and never switch to a password.

## Single sign-on on Windows

On Windows x64, ambient authentication uses the signed-in account's SSPI Negotiate context.
Sign in with a domain account, use the DC's real FQDN, and ensure the machine can reach the directory and domain authentication services.
The operating system chooses the package within one GSS-SPNEGO exchange; ldap-axi does not assert Kerberos rather than NTLM.
Windows SSO remains unproven by a live Windows run.

The `@knowttl/ldap-axi@0.1.0` bootstrap package ships only the Linux prebuild and needs a source fallback on Windows.
Tag-workflow packages pin the Windows prebuild digest and retrieve the binary from the matching versioned GitHub release without requiring MSVC or the Windows SDK.
If the verified prebuild cannot be installed, automatic mode attempts one source build requiring MSVC and the Windows SDK.
The source fallback also needs node-gyp's prerequisites, including Python.
See the [support matrix](docs/support-matrix.md) for installation paths and exact support limits.

```powershell
ldap-axi auth status --offline --auth gssapi --url ldap://dc01.example.test:389
ldap-axi user list --auth gssapi --url ldap://dc01.example.test:389 --limit 10
```

The same scheme-selected confidentiality and TLS trust rules apply on Windows.
For LDAPS/StartTLS, supply a trusted CA with `--ca-file C:\certs\corporate-root.pem` or `NODE_EXTRA_CA_CERTS`; keep verification enabled.

## Development

```sh
npm install
npm run verify
```

For installation from a GitHub release archive on Windows or Linux, see [release installation](docs/support-matrix.md#installing-a-github-release-archive).

The required checks are offline and use synthetic fixtures.
The opt-in Linux/Docker `npm run test:local-directory` suite stays outside that gate.
Manual live verification is described in [the design](docs/design/v1.md#19-live-tests-never-in-ci) and is never run automatically.
Only the native-prebuild and manual local-directory GitHub Actions workflows are authorized; neither receives directory credentials.

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

See [the support matrix](docs/support-matrix.md#command-surface) for implemented and planned commands, including offline configuration discovery.

The design states per command which behavior is flavor-neutral and which is flavor-specific, and every group
membership result reports whether it is transitive and how it was derived, because a direct-membership answer
mistaken for a transitive one is a security-relevant error.

See `docs/design/v1.md` §1 for scope and deferral rationale, and §5.4 for the flavor table.

## Relationship to trxo/ldap-mcp

[`trxo/ldap-mcp`](https://github.com/trxo/ldap-mcp) is used as a behavioral, domain, and scope reference only.
It is not a fork base, not a dependency, and not part of ldap-axi at runtime.

`docs/design/v1.md` §1.1 tabulates every deliberate divergence from it with the reason, including read-only by
architecture rather than by an unset flag, structured output instead of prose-wrapped JSON, decoded binary
attributes, in-process bounded paging instead of draining every page into memory, and no secret on the command
line.

## License

[MIT](LICENSE), copyright knowttl.
