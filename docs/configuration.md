# Configuration

Contents: [Paths and precedence](#paths-and-precedence) · [Profiles](#profiles) · [Settings](#settings) · [Authentication](#authentication) · [Environment and installation](#environment-and-installation).

## Paths and precedence

Run `ldap-axi config path` for the actual location without reading credentials.
`--config` overrides `LDAP_AXI_CONFIG`, then the deprecated `LDAP_AXI_CONFIG_FILE` alias, then the platform default.
The deprecated alias emits a warning on stderr when selected; use `LDAP_AXI_CONFIG` instead.
On non-Windows systems the default is `$XDG_CONFIG_HOME/ldap-axi/config.json` when XDG_CONFIG_HOME is absolute, otherwise `~/.config/ldap-axi/config.json`.
Windows uses `%APPDATA%\ldap-axi\config.json`, falling back to `~/AppData/Roaming/ldap-axi/config.json`, and ignores XDG for directory configuration.
Configuration is never discovered from the working directory.

`--profile` takes precedence over `LDAP_AXI_PROFILE`.
Without either, environment connection fields select an environment profile; otherwise `defaultProfile` or a sole saved profile is selected.
Multiple saved profiles without a default require explicit selection.
CLI connection overrides apply to the selected profile.
Environment connection fields do not override an explicitly selected file profile.
A half environment DN/password pair fails with `CREDENTIAL_INCOMPLETE` without fallback.

## Profiles

Create the containing directory privately (`0700` on POSIX), then save this envelope at the reported config path.
Use mode `0600` on POSIX and restrict the file ACL to your account on Windows.
Replace the synthetic hostname with your directory's real FQDN.

```json
{
  "version": 1,
  "defaultProfile": "work",
  "profiles": {
    "work": {
      "url": "ldaps://directory.example.test:636",
      "auth": "gssapi"
    }
  }
}
```

With an existing Kerberos ticket or domain sign-in and a trusted certificate:

```sh
ldap-axi auth status --offline --profile work
ldap-axi user list --profile work --fields name,dn --limit 1
```

The bounded read has this shape with a synthetic directory fixture:

```text
count: 1 of 1 total
users[1]{name,dn}:
  Example,"CN=Example,DC=example,DC=test"
tls_verified: true
```

`ldap-axi profile list` prints this exact output for the profile above without resolving passwords:

```text
profiles[1]{name,url,auth}:
  work,"ldaps://directory.example.test:636",gssapi
help[1]: "Run `ldap-axi auth status --offline --profile <name>` to inspect a profile"
```

For simple authentication, use a service account permitted to bind and read:

```json
{
  "version": 1,
  "defaultProfile": "work",
  "profiles": {
    "work": {
      "url": "ldaps://directory.example.test:636",
      "auth": "simple",
      "bindDn": "uid=reader,dc=example,dc=test",
      "bindPassword": { "env": "LDAP_AXI_BIND_PASSWORD" }
    }
  }
}
```

Supply `LDAP_AXI_BIND_PASSWORD` through a secret manager or hidden terminal prompt, then use the same commands with `--profile work`.
Never paste passwords into shell commands or chat.
A file SecretRef also works: `{"file":"/absolute/path/password"}` with mode `0600` or `0400` on POSIX and an absolute drive path on Windows.
Windows ACL checks are reported as unchecked; the operator must restrict access.
Ambient authentication leaves file-profile password references unresolved.
There is no password flag or `auth login` command.
See the [credential schema](../axi-credential.schema.json) for allowed profile fields.

## Settings

The [README environment table](../README.md#configuration) lists runtime variables and defaults.

| Flag | Profile key | Behavior |
| --- | --- | --- |
| `--url` | `url` | Required directory endpoint for connected commands |
| `--base` | `base` | Otherwise naming-context discovery; disambiguate with `DC=example,DC=test` |
| `--auth` | `auth` | `auto` (default), `gssapi`, or `simple` |
| `--start-tls` | `startTls` | Upgrade `ldap://`; default false |
| `--ca-file` | `caFile` | Absolute CA path; append to Node trust roots |
| `--ca-only` | None | Replace trust roots with `--ca-file` certificates; default false |
| `--tls-no-verify` | None | Disable certificate verification; default false |
| `--tls-max-version 1.2` | `tlsMaxVersion` | Optional TLS 1.2 cap; otherwise runtime maximum |
| `--insecure-plaintext` | None | Permit unprotected LDAP; default false |
| `--anonymous` | None | Explicit anonymous access; default false |
| `--gssapi-service` | `gssapiService` | Default `ldap@URL-host` |
| `--gssapi-protection` | `gssapiProtection` | Assert the scheme-required `none` or `confidentiality` layer |
| `--page-size` | `pageSize` | 1..1000; AD/AD LDS default 1000, otherwise 500 |
| None | `flavor` | `ad`, `adlds`, `ldapv3`; otherwise detection |
| No credential flags | `bindDn`, `bindPassword` | Identity and SecretRef for simple authentication |

Boolean environment settings accept `1`, `true`, `0`, or `false`, case-insensitively.
For list budgets, fields, raw attributes, and per-command flags, see the [generated command reference](commands.md).

## Authentication

| Selection | Identity | Transport |
| --- | --- | --- |
| `auto` (default) | One ambient GSSAPI/SSPI attempt; no password fallback | Scheme-selected |
| `gssapi` | Linux Kerberos or Windows SSPI Negotiate | Plain LDAP requires SASL confidentiality; LDAPS/StartTLS uses verified TLS, channel binding, and no SASL layer |
| `simple` | Explicit configured identity and resolved password | Prefer LDAPS or StartTLS |
| `--anonymous` | Explicit anonymous access | Prefer LDAPS or StartTLS |

`ldap-axi auth status --offline` reports selection and recorded provider installation without connecting, binding, loading the provider, or validating tickets.
Inspect `native_provider_installation` and `native_provider_detail`; npm success alone does not prove native installation succeeded.
Follow the [Linux Kerberos](kerberos.md) or [Windows](windows.md) runbook for native prerequisites and diagnosis.

## Environment and installation

`LDAP_AXI_CREDENTIALS_FILE` selects the legacy `credentials.env` detection path, defaulting to the platform config directory.
When no config is present, an existing legacy file produces `CONFIG_MOVED`; its credentials are never loaded.
`LDAP_AXI_READ_ONLY` is validated as a boolean but cannot change v1's read-only behavior.
Environment SecretRefs may name any variable, so secrets are not limited to `LDAP_AXI_BIND_PASSWORD`.

| Install variable | Behavior | Default |
| --- | --- | --- |
| `LDAP_AXI_NATIVE_MODE` | `auto`, `prebuild`, `source`, or `off` | `auto`: verified prebuild, then one source build |
| `LDAP_AXI_NATIVE_RELEASE_ASSET_URL` | Override prebuild download URL; pinned digest still required | Matching version's GitHub release asset |
| `LDAP_AXI_NATIVE_RELEASE_TOKEN` | Bearer token for prebuild download | Unset |
| `LDAP_AXI_KERBEROS_INCLUDE_DIR` | Override native source-build include directory | Build configuration defaults |

Agent setup roots and removal instructions live in [agent setup](agent-setup.md).
Host-detection variables affect only optional skill-install hints, never directory credentials or permissions.
`CLAUDECODE=1`, `OPENCODE=1`, `PI_CODING_AGENT=true`, or a nonempty `CODEX_THREAD_ID`/`CODEX_SESSION_ID` selects host discovery in that order.
`PI_CODING_AGENT_DIR` defaults to `~/.pi/agent`; `ProgramData` defaults to `C:/ProgramData` for Windows managed skill roots.
`LDAP_AXI_GSSAPI_TRACE=1` enables redacted timing diagnostics on stderr.
For platform libraries, installation evidence, and release provenance, see the [support matrix](support-matrix.md).
