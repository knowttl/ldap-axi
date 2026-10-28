# ldap-axi

Read Active Directory and LDAPv3 directories from the shell

[![npm](https://img.shields.io/npm/v/%40knowttl%2Fldap-axi)](https://www.npmjs.com/package/@knowttl/ldap-axi) [![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE) [![Node](https://img.shields.io/node/v/%40knowttl%2Fldap-axi)](https://nodejs.org/) [![npm provenance](https://img.shields.io/npm/provenance/%40knowttl%2Fldap-axi)](https://www.npmjs.com/package/@knowttl/ldap-axi#provenance) [![AXI](https://img.shields.io/badge/AXI-TOON-blue)](https://github.com/kunchenguid/axi)

[Why](#why-this-exists) · [Quickstart](#quickstart) · [Agents](#use-with-your-agent) · [Coverage](#what-it-covers) · [Safety](#safety) · [Configuration](#configuration) · [Output](#output-and-exit-codes) · [Troubleshooting](#troubleshooting) · [Contributing](#contributing) · [Security](#security) · [License](#license)

## Why this exists

Raw LDAP reads require filters, paging, binary decoding, and directory-specific membership rules before an agent can answer a simple account question.
ldap-axi gives agents and the humans running them typed reads, bounded [TOON](https://toonformat.dev) output, and next-step hints through a shell executable.
Verified TLS and a strictly read-only directory boundary keep reads predictable without granting directory write capabilities.

## Quickstart

Requires **Node 24.11.0 or newer**; see the [platform and native-provider requirements](docs/support-matrix.md#platforms).

```sh
npm install --global @knowttl/ldap-axi
ldap-axi
# Without a global install:
npx -y @knowttl/ldap-axi
```

The home view never connects; its output includes:

```text
description: Read Active Directory and LDAPv3 directories safely with ldap-axi (read-only)
credentials: not configured
```

Run `ldap-axi config path`, then create that file with this profile and replace the synthetic host:

```json
{"version":1,"defaultProfile":"work","profiles":{"work":{
  "url":"ldaps://directory.example.test:636","auth":"gssapi"
}}}
```

Restrict the file to your account (`0600` on POSIX; private ACLs on Windows).
With an existing Kerberos ticket or domain sign-in and a trusted certificate, run `ldap-axi user list --profile work --fields name,dn --limit 1`.
See [configuration and simple-bind profiles](docs/configuration.md#profiles), [Linux Kerberos](docs/kerberos.md), and [Windows setup](docs/windows.md).

## Use with your agent

Install the offline session integration for your selected agent:

```sh
ldap-axi setup --app claude --hook
ldap-axi setup --app codex --hook
ldap-axi setup --app opencode --hook
```

Each injects the offline home view without connecting or granting directory permissions.
For on-demand guidance and the full command reference, install the [skill](skills/ldap-axi/SKILL.md):

```sh
npx skills add knowttl/ldap-axi --skill ldap-axi
```

Append `--skill` to setup to install both; `--check` checks selected integrations without writing and exits 1 for drift.
To remove hooks, delete only the `ldap-axi offline home` entry in Claude's `settings.json` or Codex's `hooks.json`; for OpenCode remove `plugins/ldap-axi.js` in its configuration root.
See [agent setup](docs/agent-setup.md) for roots, host requirements, repair, and skill removal.

<a id="features"></a>
<a id="commands"></a>

## What it covers

<!-- BEGIN GENERATED COMMANDS -->
| Group | Purpose | Read/write | Reference |
| --- | --- | --- | --- |
| `entry` | Search and show arbitrary entries | Read | [Commands](docs/commands.md#entry-search) |
| `user` | Read accounts and group membership | Read | [Commands](docs/commands.md#user-list) |
| `group` | Read groups and their members | Read | [Commands](docs/commands.md#group-list) |
| `computer` | Read machine accounts and devices | Read | [Commands](docs/commands.md#computer-list) |
| `auth` | Inspect authentication selection and status | Read; --offline stays local | [Commands](docs/commands.md#auth-status) |
| `server` | Read rootDSE capabilities and flavor | Read | [Commands](docs/commands.md#server) |
| `profile` | List configured profiles without resolving secrets | Local read | [Commands](docs/commands.md#profile-list) |
| `config` | Locate the configuration file | Local read | [Commands](docs/commands.md#config-path) |
| `setup` | Install or repair selected agent integrations | Local write; --check reads | [Commands](docs/commands.md#setup) |
<!-- END GENERATED COMMANDS -->

The table is generated from the command registry; the [full generated leaf reference](docs/commands.md) includes flags, defaults, and examples.
Run `ldap-axi <command> --help` without connecting.

## Safety

**v1 is strictly read-only by default and always.**
It implements no directory add, modify, rename, move, delete, password change, or write-capable extended operation.
There is no `--confirm` or environment gate that unlocks directory writes; `LDAP_AXI_READ_ONLY=false` cannot enable them.
`setup` writes only explicitly selected local agent integrations.
Each connected invocation makes one authentication exchange with no retry or password fallback; failed AD binds can increment lockout counters.
TLS verification stays enabled by default; anonymous access requires `--anonymous`.
Passwords come from environment or file SecretRefs, never argv, inline config, or credential-bearing URLs.
Windows file ACLs are reported as unchecked and must be restricted by the operator.
See the [safety and permissions matrix](docs/safety.md) and [validation evidence](docs/support-matrix.md#what-is-proved-and-what-is-not).

## Configuration

Run `ldap-axi config path` for the actual location; configuration is never discovered from the working directory.

| OS | Default config path |
| --- | --- |
| Linux and other non-Windows systems | `$XDG_CONFIG_HOME/ldap-axi/config.json` if absolute; otherwise `~/.config/ldap-axi/config.json` |
| Windows | `%APPDATA%\ldap-axi\config.json`; falls back to `~/AppData/Roaming/ldap-axi/config.json` |

Explicit `--profile` or `LDAP_AXI_PROFILE` selects a file profile; otherwise environment connection fields form a separate profile before `defaultProfile` or a sole saved profile.
CLI overrides apply to the selected profile.
See [configuration](docs/configuration.md) for flags, profile keys, precedence, and installation variables.

| Variable | Purpose and default when unset |
| --- | --- |
| `LDAP_AXI_CONFIG` | Config path; platform path above |
| `LDAP_AXI_CONFIG_FILE` | Deprecated config-path alias; prefer `LDAP_AXI_CONFIG` |
| `LDAP_AXI_PROFILE` | Named profile; selection described above |
| `LDAP_AXI_URL` | Directory URL; profile or required for connected reads |
| `LDAP_AXI_BASE` | Search base; profile or naming-context discovery |
| `LDAP_AXI_AUTH` | `auto`, `gssapi`, `simple`; profile or `auto` |
| `LDAP_AXI_FLAVOR` | `ad`, `adlds`, `ldapv3`; profile or detection |
| `LDAP_AXI_START_TLS` | Boolean StartTLS selection; profile or false |
| `LDAP_AXI_CA_FILE` | Additional CA file; profile or Node trust roots |
| `LDAP_AXI_TLS_MAX_VERSION` | Optional `1.2` cap; profile or runtime maximum |
| `LDAP_AXI_PAGE_SIZE` | 1..1000; profile or 1000 for AD/AD LDS, 500 otherwise |
| `LDAP_AXI_GSSAPI_SERVICE` | Service principal; profile or `ldap@URL-host` on Linux, `ldap/URL-host` on Windows |
| `LDAP_AXI_GSSAPI_PROTECTION` | Scheme-required layer assertion; profile or scheme selection |
| `LDAP_AXI_BIND_DN`, `LDAP_AXI_BIND_PASSWORD` | Simple-bind identity and secret; no default identity |
| `LDAP_AXI_CREDENTIALS_FILE` | Legacy detection path; config directory's `credentials.env`, rejected if found without config |
| `LDAP_AXI_READ_ONLY` | Boolean compatibility setting; always read-only |
| `LDAP_AXI_GSSAPI_TRACE` | Redacted timing diagnostics on stderr when `1`; disabled otherwise |
| `NODE_EXTRA_CA_CERTS` | Node additional CA file; unset |
| `APPDATA`, `XDG_CONFIG_HOME` | Platform configuration roots; paths above |
| `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `OPENCODE_CONFIG_DIR` | Agent setup roots; [defaults](docs/agent-setup.md) |
| `PATH` | Executable lookup for hooks; absolute executable fallback |
| `CLAUDECODE`, `OPENCODE`, `PI_CODING_AGENT`, `CODEX_THREAD_ID`, `CODEX_SESSION_ID` | Host detection for optional skill hints; absent means no detected host |
| `PI_CODING_AGENT_DIR`, `ProgramData` | Skill-discovery roots; `~/.pi/agent` and `C:/ProgramData` |
| `LDAP_AXI_NATIVE_MODE` | Native install mode; `auto` |
| `LDAP_AXI_NATIVE_RELEASE_ASSET_URL`, `LDAP_AXI_NATIVE_RELEASE_TOKEN` | Install download override and authentication; matching public release, no token |
| `LDAP_AXI_KERBEROS_INCLUDE_DIR` | Native source-build include override; pinned build defaults |

## Output and exit codes

Data and structured errors (`error`, `code`, optional `help`) use TOON on stdout; diagnostics use stderr.
Lists read one page by default; `--all --max-rows 2000` requests a longer bounded read.
Inspect `count`, `partial`, `incomplete`, `stop_reason`, and membership `method`/`transitive` before treating results as complete.
Referrals are reported without being chased; resumable cursors and `--full` are unsupported.
See the [command reference](docs/commands.md) for examples and command-specific limits.

| Exit | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Operational error, or `setup --check` drift |
| 2 | `VALIDATION_ERROR` or `CREDENTIAL_INCOMPLETE` |

## Troubleshooting

| Symptom | Next step |
| --- | --- |
| Native provider unavailable | Run `ldap-axi auth status --offline`; follow [Linux](docs/kerberos.md) or [Windows](docs/windows.md) diagnosis |
| `TLS_UNTRUSTED` | Add a trusted root with `--ca-file` or `NODE_EXTRA_CA_CERTS`; see [TLS rules](docs/safety.md#transport-and-credentials) |
| Ambiguous naming contexts | Set profile `base` or `--base "DC=example,DC=test"` |
| `CREDENTIAL_INCOMPLETE` | Supply both identity and password; select a file profile explicitly when using its environment SecretRef |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development, offline verification, generation, and releases, and [AGENTS.md](AGENTS.md) for project constraints.

## Security

Report vulnerabilities using [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
