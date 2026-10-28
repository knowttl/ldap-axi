---
name: ldap-axi
description: "Read Active Directory and LDAPv3 directories safely with ldap-axi (read-only). Use for directory users, groups, computers, server capabilities, and authentication diagnostics."
user-invocable: false
---

# ldap-axi investigation guide

Read Active Directory and LDAPv3 directories safely with ldap-axi (read-only).
Start with the relevant read below; no preliminary help call is needed.
Use the compact investigation guide in the ldap-axi skill; reserve --help for a failed or unfamiliar command
Examples use a preconfigured synthetic profile named `work`; select your approved profile instead.
With a global install, replace `npx -y @knowttl/ldap-axi` with `ldap-axi`.

## Investigation reads

Each line is a complete example.
List selectors `--name`, AD-only `--sam`/`--upn`, and LDAPv3-only `--uid` accept patterns; quote wildcard patterns in the shell.
Show and membership commands accept an exact identifier or DN, not a wildcard.

| Task | Example |
| --- | --- |
| Find computers | `npx -y @knowttl/ldap-axi computer list --profile work --name 'workstation*' --fields name,dn --limit 10` |
| Inspect one computer | `npx -y @knowttl/ldap-axi computer show workstation --profile work --fields name,dn --attributes description` |
| Find users | `npx -y @knowttl/ldap-axi user list --profile work --name 'Alice*' --fields name,dn --limit 10` |
| Inspect one user | `npx -y @knowttl/ldap-axi user show alice --profile work --fields name,dn,account_state` |
| Resolve a user's groups | `npx -y @knowttl/ldap-axi user groups alice --profile work --fields name,dn --max-rows 25` |
| Find groups | `npx -y @knowttl/ldap-axi group list --profile work --name 'Engineering*' --fields name,dn --limit 10` |
| Inspect one group | `npx -y @knowttl/ldap-axi group show engineering --profile work --fields name,dn,member_count` |
| Resolve direct members | `npx -y @knowttl/ldap-axi group members engineering --profile work --fields name,dn --max-rows 25` |
| Resolve nested members (AD only) | `npx -y @knowttl/ldap-axi group members engineering --profile work --nested --fields name,dn --max-rows 25` |
| Search arbitrary entries | `npx -y @knowttl/ldap-axi entry search --profile work --filter '(objectClass=person)' --attributes cn,mail --max-rows 25` |
| Read a known DN | `npx -y @knowttl/ldap-axi entry show CN=Alice,DC=example,DC=test --profile work --attributes cn,mail` |
| Read server capabilities/flavor | `npx -y @knowttl/ldap-axi server --profile work` |
| Diagnose authentication | `npx -y @knowttl/ldap-axi auth status --profile work` |
| Inspect auth without binding | `npx -y @knowttl/ldap-axi auth status --profile work --offline` |

AD user identifiers are sAMAccountName or UPN; LDAPv3 uses uid.
Groups use cn or AD sAMAccountName; computers use cn or AD sAMAccountName (include its trailing dollar sign when supplied).
LDAPv3 computer reads use objectClass=device.
User lists also support `--disabled`, `--enabled`, and `--locked`; LDAPv3 lock state is a ppolicy candidate, not proof of a current lock.

## One invocation instead of hand-written loops

Use show directly for known identifiers; no list-first lookup is needed.
Replace list-then-show loops with supported `--fields` or raw `--attributes` on the list itself.
Start with name,dn; AD computer lists also offer dns_host_name,enabled, AD user lists sam,upn,enabled,locked,last_logon, and LDAPv3 user lists uid,mail,account_state.
Computer operating_system and operating_system_version are show fields; request raw operatingSystem,operatingSystemVersion on lists if needed.
User groups handles lookup and membership resolution: AD prefers transitive tokenGroups including the primary group; inspect method/transitive because fallback can be direct.
AD user groups also accepts `--nested` for transitive fallback expansion.
Group members `--nested` expands AD membership; LDAPv3 nesting is unsupported.
AD group members omits primary-group-only members and reports partial results; group show member_count has the same limitation and a 10,000-value cap.
Membership defaults to at most 1000 AD or 500 LDAPv3 rows; set `--max-rows` explicitly.
Reads finish synchronously; there is no start/poll workflow or general batch-show command.

## Keep output bounded

Typed lists default to one page; `--limit N` reads across pages up to N rows.
Alternatively use `--all --max-rows N` on lists or entry search; `--all` requires a bound.
Without `--all`, `--max-rows` alone does not request later list/search pages.
`--page-size` sets LDAP page size (1..1000; defaults AD 1000, LDAPv3 500 unless configured), not total output.
Typed reads use `--fields`; raw entry reads use `--attributes` (default objectClass,cn), not `--fields` or `--limit`.
Attribute wildcards and password attributes are forbidden.
Use `--base DN`, list/search `--scope base|one|sub`, and narrow `--filter` values to constrain searches.
Filters use RFC 4515 syntax; escape literal metacharacters rather than interpolating untrusted values.
TOON data and structured errors appear on stdout.
Check count, partial, incomplete, stop_reason, unresolved, method, and transitive before claiming completeness; exit 0 can contain partial results.
Referrals are reported without being chased; resumable cursors are unsupported.
Empty reads cannot distinguish absent entries from entries hidden by access control.

## Safety and authentication

Directory read allowlist: entry search, entry show, user list, user show, user groups, group list, group show, group members, computer list, computer show, server, auth status.
Local reads: home (no arguments), profile list, config path, and auth status with `--offline`.
No directory mutation commands or flags unlock writes.
Exclude setup from investigation allowlists: it writes selected local agent integrations unless `--check` is used.
Each connected invocation performs one authentication exchange; failed AD binds can increment lockout counters.
Do not retry authentication blindly.
Default `--auth auto` selects ambient Kerberos/SSPI, never password fallback; use `--auth simple` when the approved identity is the configured simple-bind account.
Credentials belong in environment variables or private file SecretRefs, never argv; anonymous access requires explicit `--anonymous`.
Verified LDAPS/StartTLS uses channel binding and no SASL layer; plain LDAP GSSAPI requires confidentiality, with no transport fallback.
Keep TLS verification enabled.
See [configuration](https://github.com/knowttl/ldap-axi/blob/main/docs/configuration.md) and the [support matrix](https://github.com/knowttl/ldap-axi/blob/main/docs/support-matrix.md) for credential and native-provider setup.

## Failures and help

Use help to recover from a failed or unfamiliar command, not to begin an investigation.
Top-level `--help` returns the command overview and authentication notes; group help (for example computer) lists subcommands; leaf help gives syntax, flags, fields/defaults, and examples (entry show has a shorter synopsis).
Help never connects; the [command reference](https://github.com/knowttl/ldap-axi/blob/main/docs/commands.md) is generated from leaf help.
Exit codes: 0 success, 2 usage/validation (including CREDENTIAL_INCOMPLETE), 1 other failures.

| Code | Next action |
| --- | --- |
| VALIDATION_ERROR | Correct the named flag, field, filter, or argument; ambiguous identifiers require a DN. |
| NOT_FOUND | Check identifier, base, flavor, and read visibility. |
| PROFILE_NOT_FOUND / PROFILE_AMBIGUOUS | Select a configured profile explicitly. |
| CONFIG_INVALID / CONFIG_INSECURE / CREDENTIAL_INCOMPLETE / AUTH_REQUIRED | Repair config, private-file permissions, or the complete approved credential pair before binding. |
| GSSAPI_UNAVAILABLE / GSSAPI_CREDENTIAL_UNAVAILABLE | Check provider/runtime installation or ambient credential availability. |
| GSSAPI_PREPARATION_FAILED / GSSAPI_NEGOTIATION_FAILED | Inspect the reported target, credential, or protection problem; no fallback occurred. |
| AUTH_FAILED / ACCOUNT_LOCKED / ACCOUNT_DISABLED / ACCOUNT_EXPIRED / PASSWORD_EXPIRED | Stop and escalate the account/credential problem; do not probe alternatives. |
| TLS_UNTRUSTED / TLS_REQUIRED / STRONGER_AUTH_REQUIRED | Repair trust or approved encrypted transport; do not disable verification. |
| INSUFFICIENT_ACCESS | Request approved read access or narrow the query. |
| UNSUPPORTED_BY_SERVER | Remove the flavor-specific option; generic nesting is unsupported. |
| SERVER_LIMIT / OPERATION_TIMEOUT | Narrow base/filter or lower the bound; inspect retained partial data. |
| SERVER_UNREACHABLE / SERVER_BUSY | Check endpoint availability before another invocation. |
