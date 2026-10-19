# ldap-axi

Read Active Directory and LDAPv3 directories from the shell with structured output for agents and the humans running them.

[![npm](https://img.shields.io/npm/v/%40knowttl%2Fldap-axi)](https://www.npmjs.com/package/@knowttl/ldap-axi)
[![Node](https://img.shields.io/node/v/%40knowttl%2Fldap-axi)](package.json)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![AXI](https://img.shields.io/badge/AXI-TOON-blue)](https://github.com/kunchenguid/axi)
[![Release provenance](https://img.shields.io/badge/release-attested-blue)](docs/support-matrix.md#release-and-provenance)

```sh
ldap-axi user list --profile work --fields name,dn --limit 1
```

Actual [TOON](https://toonformat.dev) output from the built CLI with a synthetic directory fixture:

```text
count: 1 of 1 total
users[1]{name,dn}:
  Example,"CN=Example,DC=example,DC=test"
tls_verified: true
```

[Quickstart](#quickstart) • [Use with your agent](#use-with-your-agent) • [Features](#features) • [Safety](#safety) • [Configuration](#configuration) • [Commands](#commands)

## Why this exists

Raw LDAP reads require filters, paging, binary decoding, and directory-specific membership rules before an agent can answer a simple account question.
ldap-axi provides typed reads and bounded TOON output through a shell executable, following [AXI](https://github.com/kunchenguid/axi), with no MCP server to run.
It supports both AD and generic LDAPv3 while making flavor-specific behavior explicit.

## Features

- **Typed reads:** users, groups, computers, arbitrary entries, and rootDSE server capabilities.
- **Account decoding:** AD SIDs, GUIDs, FILETIME values, account state, and group types.
- **Membership:** direct and nested reads with the method and transitivity reported in output.
- **Bounded paging:** one page by default, explicit row budgets for longer reads, and partial-result metadata.
- **Authentication:** ambient Kerberos or Windows SSPI, explicit simple bind, and explicit anonymous access.
- **Agent integration:** offline session context and an installable skill for Claude Code, Codex, and OpenCode.

## Quickstart

Requires **Node 24.11.0 or newer**.
Ambient authentication requires Linux glibc x64 (glibc >=2.28, GLIBCXX >=3.4.25 and Kerberos runtime libraries) or Windows x64.
Other platforms can use explicit simple authentication; native GSSAPI is unavailable there.
See the [support matrix](docs/support-matrix.md#platforms) for exact platform and validation limits.

```sh
npm install --global @knowttl/ldap-axi
ldap-axi auth status --offline
ldap-axi config path
```

The offline report makes no connection and no bind.
Check `native_provider_installation` and `native_provider_detail`: npm success alone does not prove the optional native provider installed.
An unavailable provider leaves simple authentication usable; follow the [Linux Kerberos](docs/kerberos.md) or [Windows](docs/windows.md) runbook for diagnosis.
Offline status does not load the provider or validate tickets.

Create the file reported by `config path` with this minimal profile, replacing the synthetic server with your directory's real FQDN:

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

On POSIX, create the containing directory with mode `0700` and the file with `0600`.
On Windows, restrict their ACLs to your account.
With an existing Kerberos ticket or domain sign-in and a trusted server certificate:

```sh
ldap-axi profile list
ldap-axi auth status --offline --profile work
ldap-axi user list --profile work --fields name,dn --limit 1
```

The first command prints this exact output for the profile above:

```text
profiles[1]{name,url,auth}:
  work,"ldaps://directory.example.test:636",gssapi
help[1]: "Run `ldap-axi auth status --offline --profile <name>` to inspect a profile"
```

The user read produces the TOON shape shown above; your entries and completeness metadata depend on the directory.
If naming-context discovery is ambiguous, add `base` to the profile or pass `--base "DC=example,DC=test"`.
For a private CA, add `caFile` with its absolute path or use `NODE_EXTRA_CA_CERTS` before starting Node.
`--ca-file` appends to Node's trust roots; `--ca-only` replaces them.

<details>
<summary>Use a simple-bind service account instead</summary>

Replace the `work` profile with the following, using your server and read-only account:

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

Supply `LDAP_AXI_BIND_PASSWORD` through a secret manager or a hidden terminal prompt, then run the same commands with `--profile work`.
Do not paste passwords into shell commands or chat.
A file SecretRef is also supported: `{"file":"/absolute/path/password"}`, with mode `0600` or `0400` on POSIX and an absolute drive path on Windows.
There is no password flag or `auth login` command.

</details>

## Use with your agent

Install the offline session integration for the agent you use:

```sh
ldap-axi setup --app claude --hook
ldap-axi setup --app codex --hook
ldap-axi setup --app opencode --hook
```

Each integration injects the compact offline home view, including configured connection state and command discovery, without contacting a directory.
Claude and Codex use native SessionStart hooks; OpenCode uses a managed system-context plugin.
Install only the desired target.
Rerun setup after moving the executable to repair its path.

For on-demand guidance, install the skill independently or add `--skill` to a setup command:

```sh
npx skills add knowttl/ldap-axi --skill ldap-axi
ldap-axi setup --app codex --skill
ldap-axi setup --app codex --hook --skill --check
```

`--check` never writes and exits 1 for missing or stale selected integrations.
The skill contains static command and authentication guidance, with no local credentials.
See [agent setup](docs/agent-setup.md) for host requirements, paths, and manual removal.

## Safety

**v1 is strictly read-only.**
It implements no directory add, modify, rename, move, delete, password change, or write-capable extended operation.
There is no switch that unlocks directory writes.
`setup` writes only the explicitly selected local agent integration.

| Operation | Required permission or credential |
| --- | --- |
| Entry, user, group, computer and membership reads | Read access to the selected base, entries, and requested attributes; no directory administrator role required |
| `server` | Access to advertised rootDSE facts |
| Ambient authentication | Existing Kerberos credential cache on Linux or signed-in domain context on Windows |
| Simple authentication | Directory identity permitted to bind and read |
| Offline commands and help | Local configuration access only; no directory permission |
| `setup` | Write access to the selected local agent configuration |

Every connected invocation uses one authentication exchange, with no retry or password fallback.
A failed AD bind can increment lockout counters, so validate configuration offline first.
Anonymous access requires `--anonymous`.
TLS verification stays enabled by default; simple bind over unencrypted LDAP requires `--insecure-plaintext`.

Passwords come only from environment or file SecretRefs, never argv, inline config, or credential-bearing URLs.
Resolved password values are redacted from CLI output; directory data and configured identities are output intentionally.
Windows password-file ACLs are reported as `unchecked (windows)` and must be restricted by the operator.

Directory commands send authentication exchanges and LDAP requests to the selected server; referrals are reported without being chased.
Offline commands do not contact the directory.
Windows native installation may download a digest-verified binary from the matching GitHub release.
Native artifacts have release attestations, but are not platform-code-signed, and installation does not independently verify attestations.
See the [security policy](SECURITY.md) and [support matrix](docs/support-matrix.md#what-is-proved-and-what-is-not).
Live Windows SSPI and a completed GSSAPI bind against a production AD controller remain unproved; offline and disposable-directory tests do not establish those claims.

## Configuration

Run `ldap-axi config path` for the actual location.
Linux uses `$XDG_CONFIG_HOME/ldap-axi/config.json` when XDG_CONFIG_HOME is absolute, otherwise `~/.config/ldap-axi/config.json`.
Windows uses `%APPDATA%\ldap-axi\config.json` and ignores XDG variables.
Configuration is never discovered from the working directory.

| Flag | Environment | Profile key / behavior |
| --- | --- | --- |
| `--config` | `LDAP_AXI_CONFIG` | Select config file |
| `--profile` | `LDAP_AXI_PROFILE` | Select a named profile; envelope `defaultProfile` otherwise |
| `--url` | `LDAP_AXI_URL` | `url` |
| `--base` | `LDAP_AXI_BASE` | `base`; otherwise naming-context discovery |
| `--auth` | `LDAP_AXI_AUTH` | `auth`: `auto`, `gssapi`, `simple` |
| `--start-tls` | `LDAP_AXI_START_TLS` | `startTls` |
| `--ca-file` | `LDAP_AXI_CA_FILE` | `caFile`: absolute CA path |
| `--tls-max-version 1.2` | `LDAP_AXI_TLS_MAX_VERSION` | `tlsMaxVersion`: optional TLS 1.2 cap |
| `--page-size` | `LDAP_AXI_PAGE_SIZE` | `pageSize`: 1..1000; AD default 1000, LDAPv3 default 500 |
| No secret flag | `LDAP_AXI_BIND_DN`, `LDAP_AXI_BIND_PASSWORD` | `bindDn`, `bindPassword` SecretRef |
| `--fields`, `--attributes` | None | Output fields and safe raw attributes on supported commands |
| `--limit`, `--max-rows`, `--all` | None | Bound list output; `--all` needs an explicit row budget |

Select a file profile explicitly when supplying its password via the environment.
Otherwise environment connection fields form a separate profile; a half DN/password pair fails with `CREDENTIAL_INCOMPLETE` and never falls back to another source.
CLI overrides apply to the selected profile.
See the [credential schema](axi-credential.schema.json) for the machine-readable envelope.

| Authentication | Identity | Transport |
| --- | --- | --- |
| `auto` (default) | One ambient GSSAPI/SSPI attempt; no configured-password fallback | Scheme-selected, as below |
| `gssapi` | Linux Kerberos or Windows SSPI Negotiate | Plain `ldap://`: mandatory SASL confidentiality; LDAPS/StartTLS: verified TLS with channel binding and no SASL layer |
| `simple` | Explicit configured service identity; no native provider required | Prefer LDAPS or StartTLS |
| `--anonymous` | Explicit anonymous access | Prefer LDAPS or StartTLS |

For native prerequisites and troubleshooting, use the [Linux Kerberos](docs/kerberos.md) and [Windows](docs/windows.md) runbooks.

## Commands

<!-- BEGIN GENERATED COMMANDS -->
| Command | Help summary |
| --- | --- |
| [`entry search`](docs/commands.md#entry-search) | Search directory entries. |
| [`entry show`](docs/commands.md#entry-show) | entry show &lt;dn&gt; [--attributes a,b] |
| [`user list`](docs/commands.md#user-list) | List user accounts. |
| [`user show`](docs/commands.md#user-show) | Show one user by DN or identifier. |
| [`user groups`](docs/commands.md#user-groups) | List the groups a user belongs to. |
| [`group list`](docs/commands.md#group-list) | List groups. |
| [`group show`](docs/commands.md#group-show) | Show one group by DN or identifier. |
| [`group members`](docs/commands.md#group-members) | List a group's members. |
| [`computer list`](docs/commands.md#computer-list) | List computers (AD machine accounts; LDAPv3 device fallback). |
| [`computer show`](docs/commands.md#computer-show) | Show one computer by DN or exact identifier (AD: sAMAccountName or cn; LDAPv3: cn, using objectClass=device). |
| [`auth status`](docs/commands.md#auth-status) | Reports the one selected authentication contract: credential provenance, native provider status, mechanism, SASL security layer, and TLS channel binding. |
| [`server`](docs/commands.md#server) | Report rootDSE capabilities and server flavor. |
| [`profile list`](docs/commands.md#profile-list) | profile list [--config &lt;path&gt;] |
| [`config path`](docs/commands.md#config-path) | config path [--config &lt;path&gt;] |
| [`setup`](docs/commands.md#setup) | Install or repair explicitly selected local agent integrations. No directory connection. |
<!-- END GENERATED COMMANDS -->

The table and [full command reference](docs/commands.md) are generated from the CLI's command registry and executable help.
Run `ldap-axi <command> --help` for flags, defaults, and examples without connecting.
Run `ldap-axi` with no arguments for the offline home view.

Additional reads with the same profile:

```sh
ldap-axi group members engineering --profile work --fields name,dn --max-rows 25
ldap-axi entry search --profile work --filter "(objectClass=person)" --attributes cn,mail --max-rows 25
ldap-axi computer list --profile work --limit 10
ldap-axi server --profile work
```

Use an identifier or DN from your own directory in place of `engineering`.

List commands read one page by default; `--all --max-rows 2000` requests a longer bounded read.
Inspect `count`, `partial`, `incomplete`, `stop_reason`, and membership `method`/`transitive` metadata before treating results as complete.
Referrals are never chased and resumable cursors are unsupported.
Unknown flags fail before connecting.
Structured errors use `error`, `code`, and optional `help` on stdout; diagnostics use stderr.
Exit codes are 0 for success, 1 for operational errors, and 2 for validation errors or incomplete credentials; `setup --check` also uses 1 for drift.

## Contributing

```sh
npm ci
npm run verify
```

Checks run locally on Node >=24.11.0 with synthetic fixtures, including generated reference and skill drift checks.
See [Contributing](CONTRIBUTING.md), [Security](SECURITY.md), and the generated [Changelog](CHANGELOG.md).

## License

[MIT](LICENSE).

If this project saved you time or helped your workflow, please consider giving it a ⭐ on GitHub to help others find it!
