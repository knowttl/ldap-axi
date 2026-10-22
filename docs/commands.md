# Command reference

Generated from executable help by `npm run skill:generate`; do not edit by hand.

## entry search

```text
Search directory entries.
Usage: ldap-axi entry search [flags]
Flags:
  --help  show this help
  --config  <path> select a credential-standard config file (default: LDAP_AXI_CONFIG, then platform config directory)
  --url  <ldap[s]://host:port> directory URL (default: environment or config)
  --base  <dn> search base (default: environment, config, or server naming contexts)
  --start-tls  upgrade ldap:// using StartTLS (default: environment or config, otherwise false)
  --ca-file  <pem> append a trusted CA (default: environment or config, otherwise bundled roots)
  --ca-only  trust only --ca-file certificates (default: false)
  --tls-no-verify  disable certificate verification (default: false)
  --tls-max-version  <1.2> cap verified TLS to TLS 1.2 (default: environment or config, otherwise runtime maximum)
  --insecure-plaintext  allow plaintext LDAP (default: false)
  --anonymous  bind anonymously (default: false)
  --profile  <name> select a saved profile (default: environment profile, defaultProfile, or sole saved profile)
  --auth  <auto|gssapi|simple> authentication selection (default: auto; environment or config overrides)
  --gssapi-service  <service@fqdn> override the URL-derived GSSAPI service (default: ldap@URL-host; environment or config overrides)
  --gssapi-protection  <none|confidentiality> required GSSAPI protection; the URL scheme selects it (default: none over TLS, confidentiality over plain LDAP)
  --filter  <RFC4515> LDAP filter (default: (objectClass=*))
  --scope  <base|one|sub> search scope (default: sub)
  --attributes  <name,...> requested attributes (default: objectClass,cn); wildcards are forbidden
  --page-size  <1..1000> LDAP page size (default: AD 1000, LDAPv3 500; config overrides)
  --max-rows  <n> maximum output rows (default: one page)
  --all  read all pages; requires --max-rows (default: false)
Defaults: base is selected from config or the server naming contexts.
Authentication defaults to auto and attempts one ambient GSSAPI context; failures are terminal and never select a password.
Use --auth simple to preserve a configured bind identity.
The URL scheme selects the GSSAPI transport: verified TLS binds with no SASL security layer, plain ldap:// with a mandatory confidentiality layer.
Filters use RFC 4515 prefix operators & | !; escape literal * ( ) \ and NUL in values.
Examples:
  ldap-axi entry search --filter "(objectClass=person)" --attributes cn,mail --max-rows 25
  ldap-axi entry search --base "DC=example,DC=test" --scope one --all --max-rows 2000
```

## entry show

```text
entry show <dn> [--attributes a,b]
Defaults to objectClass,cn; attribute wildcards are forbidden.
Authentication defaults to auto and attempts one ambient GSSAPI context; failures are terminal and never select a password.
Use --auth simple to preserve a configured bind identity.
The URL scheme selects the GSSAPI transport: verified TLS binds with no SASL security layer, plain ldap:// with a mandatory confidentiality layer.
Use --tls-max-version 1.2 for verified TLS 1.2-only directory endpoints.
Example: ldap-axi entry show "CN=Example,DC=example,DC=test"
```

## user list

```text
List user accounts.
LDAPv3 users are inetOrgPerson or posixAccount entries; use ldap-axi entry search for account + simpleSecurityObject service accounts.
Usage: ldap-axi user list [flags]
Flags:
  --help  show this help
  --config  <path> select a credential-standard config file (default: LDAP_AXI_CONFIG, then platform config directory)
  --url  <ldap[s]://host:port> directory URL (default: environment or config)
  --base  <dn> search base (default: environment, config, or server naming contexts)
  --start-tls  upgrade ldap:// using StartTLS (default: environment or config, otherwise false)
  --ca-file  <pem> append a trusted CA (default: environment or config, otherwise bundled roots)
  --ca-only  trust only --ca-file certificates (default: false)
  --tls-no-verify  disable certificate verification (default: false)
  --tls-max-version  <1.2> cap verified TLS to TLS 1.2 (default: environment or config, otherwise runtime maximum)
  --insecure-plaintext  allow plaintext LDAP (default: false)
  --anonymous  bind anonymously (default: false)
  --profile  <name> select a saved profile (default: environment profile, defaultProfile, or sole saved profile)
  --auth  <auto|gssapi|simple> authentication selection (default: auto; environment or config overrides)
  --gssapi-service  <service@fqdn> override the URL-derived GSSAPI service (default: ldap@URL-host; environment or config overrides)
  --gssapi-protection  <none|confidentiality> required GSSAPI protection; the URL scheme selects it (default: none over TLS, confidentiality over plain LDAP)
  --disabled  include disabled accounts (LDAPv3: permanent ppolicy locks)
  --enabled  include enabled accounts (LDAPv3: exclude permanent ppolicy locks)
  --locked  include current AD locks or recorded LDAPv3 ppolicy lock candidates
  --all  read all pages up to --max-rows or --limit
  --name  <pattern> match cn
  --sam  <pattern> AD only: match sAMAccountName
  --upn  <pattern> AD only: match userPrincipalName
  --uid  <pattern> LDAPv3 only: match uid
  --filter  <RFC4515> add a raw LDAP filter
  --scope  <base|one|sub> search scope (default: sub)
  --max-rows  <n> maximum output rows
  --page-size  <1..1000> LDAP page size (default: AD 1000, LDAPv3 500; config overrides)
  --limit  <n> alias for bounded list output
  --fields  <name,...> select output fields
  --attributes  <name,...> request and emit raw attributes
Active Directory fields: sam, upn, name, dn, enabled, locked, last_logon, object_sid, when_created, description, display_name, memberOf
Active Directory defaults: sam, name, enabled, last_logon
LDAPv3 fields: uid, name, mail, enabled, locked, account_state, dn, entry_uuid, when_created
LDAPv3 defaults: uid, name, mail, enabled, locked, account_state
Examples:
  ldap-axi user list --disabled --max-rows 25
  ldap-axi user list --name Alice --fields name,dn --limit 50
```

## user show

```text
Show one user by DN or identifier.
LDAPv3 users are inetOrgPerson or posixAccount entries; use ldap-axi entry search for account + simpleSecurityObject service accounts.
Usage: ldap-axi user show <identifier-or-dn> [flags]
Flags:
  --help  show this help
  --config  <path> select a credential-standard config file (default: LDAP_AXI_CONFIG, then platform config directory)
  --url  <ldap[s]://host:port> directory URL (default: environment or config)
  --base  <dn> search base (default: environment, config, or server naming contexts)
  --start-tls  upgrade ldap:// using StartTLS (default: environment or config, otherwise false)
  --ca-file  <pem> append a trusted CA (default: environment or config, otherwise bundled roots)
  --ca-only  trust only --ca-file certificates (default: false)
  --tls-no-verify  disable certificate verification (default: false)
  --tls-max-version  <1.2> cap verified TLS to TLS 1.2 (default: environment or config, otherwise runtime maximum)
  --insecure-plaintext  allow plaintext LDAP (default: false)
  --anonymous  bind anonymously (default: false)
  --profile  <name> select a saved profile (default: environment profile, defaultProfile, or sole saved profile)
  --auth  <auto|gssapi|simple> authentication selection (default: auto; environment or config overrides)
  --gssapi-service  <service@fqdn> override the URL-derived GSSAPI service (default: ldap@URL-host; environment or config overrides)
  --gssapi-protection  <none|confidentiality> required GSSAPI protection; the URL scheme selects it (default: none over TLS, confidentiality over plain LDAP)
  --fields  <name,...> select output fields
  --attributes  <name,...> request and emit raw attributes
Active Directory fields: dn, sam, upn, name, enabled, account_state, password_last_set, account_expires, last_logon, object_sid, object_guid, when_created, when_changed, description, display_name, memberOf
Active Directory defaults: dn, sam, upn, name, enabled, account_state, password_last_set, account_expires, last_logon, object_sid, object_guid, when_created, when_changed, description, display_name, memberOf
LDAPv3 fields: dn, uid, name, mail, enabled, locked, account_state, uid_number, gid_number, home_directory, login_shell, gecos, entry_uuid, when_created, when_changed
LDAPv3 defaults: dn, uid, name, mail, enabled, locked, account_state, uid_number, gid_number, home_directory, login_shell, gecos, entry_uuid, when_created, when_changed
Examples:
  ldap-axi user show alice --fields name,dn
  ldap-axi user show uid=alice,ou=people,dc=example,dc=test --attributes mail
```

## user groups

```text
List the groups a user belongs to.
LDAPv3 users are inetOrgPerson or posixAccount entries; use ldap-axi entry search for account + simpleSecurityObject service accounts.
Usage: ldap-axi user groups <identifier-or-dn> [flags]
Flags:
  --help  show this help
  --config  <path> select a credential-standard config file (default: LDAP_AXI_CONFIG, then platform config directory)
  --url  <ldap[s]://host:port> directory URL (default: environment or config)
  --base  <dn> search base (default: environment, config, or server naming contexts)
  --start-tls  upgrade ldap:// using StartTLS (default: environment or config, otherwise false)
  --ca-file  <pem> append a trusted CA (default: environment or config, otherwise bundled roots)
  --ca-only  trust only --ca-file certificates (default: false)
  --tls-no-verify  disable certificate verification (default: false)
  --tls-max-version  <1.2> cap verified TLS to TLS 1.2 (default: environment or config, otherwise runtime maximum)
  --insecure-plaintext  allow plaintext LDAP (default: false)
  --anonymous  bind anonymously (default: false)
  --profile  <name> select a saved profile (default: environment profile, defaultProfile, or sole saved profile)
  --auth  <auto|gssapi|simple> authentication selection (default: auto; environment or config overrides)
  --gssapi-service  <service@fqdn> override the URL-derived GSSAPI service (default: ldap@URL-host; environment or config overrides)
  --gssapi-protection  <none|confidentiality> required GSSAPI protection; the URL scheme selects it (default: none over TLS, confidentiality over plain LDAP)
  --nested  AD only: expand transitive membership
  --max-rows  <n> maximum output rows
  --page-size  <1..1000> LDAP page size (default: AD 1000, LDAPv3 500; config overrides)
  --fields  <name,...> select output fields
Active Directory fields: name, dn, sam, type
Active Directory defaults: name, dn, type
LDAPv3 fields: name, dn, type
LDAPv3 defaults: name, dn, type
Examples:
  ldap-axi user groups alice --fields name,dn
  ldap-axi user groups alice --nested --max-rows 100
```

## group list

```text
List groups.
Usage: ldap-axi group list [flags]
Flags:
  --help  show this help
  --config  <path> select a credential-standard config file (default: LDAP_AXI_CONFIG, then platform config directory)
  --url  <ldap[s]://host:port> directory URL (default: environment or config)
  --base  <dn> search base (default: environment, config, or server naming contexts)
  --start-tls  upgrade ldap:// using StartTLS (default: environment or config, otherwise false)
  --ca-file  <pem> append a trusted CA (default: environment or config, otherwise bundled roots)
  --ca-only  trust only --ca-file certificates (default: false)
  --tls-no-verify  disable certificate verification (default: false)
  --tls-max-version  <1.2> cap verified TLS to TLS 1.2 (default: environment or config, otherwise runtime maximum)
  --insecure-plaintext  allow plaintext LDAP (default: false)
  --anonymous  bind anonymously (default: false)
  --profile  <name> select a saved profile (default: environment profile, defaultProfile, or sole saved profile)
  --auth  <auto|gssapi|simple> authentication selection (default: auto; environment or config overrides)
  --gssapi-service  <service@fqdn> override the URL-derived GSSAPI service (default: ldap@URL-host; environment or config overrides)
  --gssapi-protection  <none|confidentiality> required GSSAPI protection; the URL scheme selects it (default: none over TLS, confidentiality over plain LDAP)
  --all  read all pages up to --max-rows or --limit
  --name  <pattern> match cn
  --sam  <pattern> AD only: match sAMAccountName
  --filter  <RFC4515> add a raw LDAP filter
  --scope  <base|one|sub> search scope (default: sub)
  --max-rows  <n> maximum output rows
  --page-size  <1..1000> LDAP page size (default: AD 1000, LDAPv3 500; config overrides)
  --limit  <n> alias for bounded list output
  --fields  <name,...> select output fields
  --attributes  <name,...> request and emit raw attributes
Active Directory fields: sam, name, dn, group_scope, security_enabled
Active Directory defaults: sam, name, group_scope, security_enabled
LDAPv3 fields: name, dn, object_class
LDAPv3 defaults: name, object_class
Examples:
  ldap-axi group list --name Engineering --fields name,dn
  ldap-axi group list --all --max-rows 2000
```

## group show

```text
Show one group by DN or identifier.
Usage: ldap-axi group show <identifier-or-dn> [flags]
Flags:
  --help  show this help
  --config  <path> select a credential-standard config file (default: LDAP_AXI_CONFIG, then platform config directory)
  --url  <ldap[s]://host:port> directory URL (default: environment or config)
  --base  <dn> search base (default: environment, config, or server naming contexts)
  --start-tls  upgrade ldap:// using StartTLS (default: environment or config, otherwise false)
  --ca-file  <pem> append a trusted CA (default: environment or config, otherwise bundled roots)
  --ca-only  trust only --ca-file certificates (default: false)
  --tls-no-verify  disable certificate verification (default: false)
  --tls-max-version  <1.2> cap verified TLS to TLS 1.2 (default: environment or config, otherwise runtime maximum)
  --insecure-plaintext  allow plaintext LDAP (default: false)
  --anonymous  bind anonymously (default: false)
  --profile  <name> select a saved profile (default: environment profile, defaultProfile, or sole saved profile)
  --auth  <auto|gssapi|simple> authentication selection (default: auto; environment or config overrides)
  --gssapi-service  <service@fqdn> override the URL-derived GSSAPI service (default: ldap@URL-host; environment or config overrides)
  --gssapi-protection  <none|confidentiality> required GSSAPI protection; the URL scheme selects it (default: none over TLS, confidentiality over plain LDAP)
  --fields  <name,...> select output fields
  --attributes  <name,...> request and emit raw attributes
Active Directory fields: dn, sam, name, group_type_raw, group_type_unsigned, group_scope, security_enabled, builtin_local, group_type_flags, group_type_unknown_bits, group_type_valid, group_type_anomalies, member_count, object_sid, object_guid, when_created, when_changed
Active Directory defaults: dn, sam, name, group_type_raw, group_type_unsigned, group_scope, security_enabled, builtin_local, group_type_flags, group_type_unknown_bits, group_type_valid, group_type_anomalies, member_count, object_sid, object_guid, when_created, when_changed
LDAPv3 fields: dn, name, object_class, member_form, member_count, entry_uuid, when_created, when_changed
LDAPv3 defaults: dn, name, object_class, member_form, member_count, entry_uuid, when_created, when_changed
Examples:
  ldap-axi group show engineering --fields name,dn
  ldap-axi group show cn=engineering,ou=groups,dc=example,dc=test --attributes description
```

## group members

```text
List a group's members.
Usage: ldap-axi group members <identifier-or-dn> [flags]
Flags:
  --help  show this help
  --config  <path> select a credential-standard config file (default: LDAP_AXI_CONFIG, then platform config directory)
  --url  <ldap[s]://host:port> directory URL (default: environment or config)
  --base  <dn> search base (default: environment, config, or server naming contexts)
  --start-tls  upgrade ldap:// using StartTLS (default: environment or config, otherwise false)
  --ca-file  <pem> append a trusted CA (default: environment or config, otherwise bundled roots)
  --ca-only  trust only --ca-file certificates (default: false)
  --tls-no-verify  disable certificate verification (default: false)
  --tls-max-version  <1.2> cap verified TLS to TLS 1.2 (default: environment or config, otherwise runtime maximum)
  --insecure-plaintext  allow plaintext LDAP (default: false)
  --anonymous  bind anonymously (default: false)
  --profile  <name> select a saved profile (default: environment profile, defaultProfile, or sole saved profile)
  --auth  <auto|gssapi|simple> authentication selection (default: auto; environment or config overrides)
  --gssapi-service  <service@fqdn> override the URL-derived GSSAPI service (default: ldap@URL-host; environment or config overrides)
  --gssapi-protection  <none|confidentiality> required GSSAPI protection; the URL scheme selects it (default: none over TLS, confidentiality over plain LDAP)
  --nested  AD only: expand transitive membership
  --max-rows  <n> maximum output rows
  --page-size  <1..1000> LDAP page size (default: AD 1000, LDAPv3 500; config overrides)
  --fields  <name,...> select output fields
Active Directory fields: sam, name, dn, type
Active Directory defaults: sam, name, type
LDAPv3 fields: uid, name, dn, type
LDAPv3 defaults: uid, name, type
Examples:
  ldap-axi group members engineering --fields name,dn
  ldap-axi group members engineering --nested --max-rows 100
```

## computer list

```text
List computers (AD machine accounts; LDAPv3 device fallback).
Usage: ldap-axi computer list [flags]
Flags:
  --help  show this help
  --config  <path> select a credential-standard config file (default: LDAP_AXI_CONFIG, then platform config directory)
  --url  <ldap[s]://host:port> directory URL (default: environment or config)
  --base  <dn> search base (default: environment, config, or server naming contexts)
  --start-tls  upgrade ldap:// using StartTLS (default: environment or config, otherwise false)
  --ca-file  <pem> append a trusted CA (default: environment or config, otherwise bundled roots)
  --ca-only  trust only --ca-file certificates (default: false)
  --tls-no-verify  disable certificate verification (default: false)
  --tls-max-version  <1.2> cap verified TLS to TLS 1.2 (default: environment or config, otherwise runtime maximum)
  --insecure-plaintext  allow plaintext LDAP (default: false)
  --anonymous  bind anonymously (default: false)
  --profile  <name> select a saved profile (default: environment profile, defaultProfile, or sole saved profile)
  --auth  <auto|gssapi|simple> authentication selection (default: auto; environment or config overrides)
  --gssapi-service  <service@fqdn> override the URL-derived GSSAPI service (default: ldap@URL-host; environment or config overrides)
  --gssapi-protection  <none|confidentiality> required GSSAPI protection; the URL scheme selects it (default: none over TLS, confidentiality over plain LDAP)
  --all  read all pages up to --max-rows or --limit
  --name  <pattern> match cn
  --sam  <pattern> AD only: match sAMAccountName
  --filter  <RFC4515> add a raw LDAP filter
  --scope  <base|one|sub> search scope (default: sub)
  --max-rows  <n> maximum output rows
  --page-size  <1..1000> LDAP page size (default: AD 1000, LDAPv3 500; config overrides)
  --limit  <n> alias for bounded list output
  --fields  <name,...> select output fields
  --attributes  <name,...> request and emit raw attributes
Active Directory fields: sam, name, dn, dns_host_name, enabled
Active Directory defaults: sam, name, dns_host_name, enabled
LDAPv3 fields: name, dn, description
LDAPv3 defaults: name, dn
Examples:
  ldap-axi computer list --name workstation* --fields name,dn
  ldap-axi computer list --all --max-rows 2000
```

## computer show

```text
Show one computer by DN or exact identifier (AD: sAMAccountName or cn; LDAPv3: cn, using objectClass=device).
Usage: ldap-axi computer show <identifier-or-dn> [flags]
Flags:
  --help  show this help
  --config  <path> select a credential-standard config file (default: LDAP_AXI_CONFIG, then platform config directory)
  --url  <ldap[s]://host:port> directory URL (default: environment or config)
  --base  <dn> search base (default: environment, config, or server naming contexts)
  --start-tls  upgrade ldap:// using StartTLS (default: environment or config, otherwise false)
  --ca-file  <pem> append a trusted CA (default: environment or config, otherwise bundled roots)
  --ca-only  trust only --ca-file certificates (default: false)
  --tls-no-verify  disable certificate verification (default: false)
  --tls-max-version  <1.2> cap verified TLS to TLS 1.2 (default: environment or config, otherwise runtime maximum)
  --insecure-plaintext  allow plaintext LDAP (default: false)
  --anonymous  bind anonymously (default: false)
  --profile  <name> select a saved profile (default: environment profile, defaultProfile, or sole saved profile)
  --auth  <auto|gssapi|simple> authentication selection (default: auto; environment or config overrides)
  --gssapi-service  <service@fqdn> override the URL-derived GSSAPI service (default: ldap@URL-host; environment or config overrides)
  --gssapi-protection  <none|confidentiality> required GSSAPI protection; the URL scheme selects it (default: none over TLS, confidentiality over plain LDAP)
  --fields  <name,...> select output fields
  --attributes  <name,...> request and emit raw attributes
Active Directory fields: sam, name, dn, dns_host_name, enabled, operating_system, operating_system_version, last_logon, object_sid, object_guid, when_created, when_changed
Active Directory defaults: sam, name, dn, dns_host_name, enabled, operating_system, operating_system_version, last_logon, object_sid, object_guid, when_created, when_changed
LDAPv3 fields: name, dn, description, entry_uuid, when_created, when_changed
LDAPv3 defaults: name, dn, description, entry_uuid, when_created, when_changed
Examples:
  ldap-axi computer show workstation --fields name,dn
  ldap-axi computer show cn=workstation,ou=devices,dc=example,dc=test --attributes description
```

## auth status

```text
Reports the one selected authentication contract: credential provenance, native provider status, mechanism, SASL security layer, and TLS channel binding.
Usage: ldap-axi auth status [flags]
Flags:
  --help  show this help
  --config  <path> select a credential-standard config file (default: LDAP_AXI_CONFIG, then platform config directory)
  --url  <ldap[s]://host:port> directory URL (default: environment or config)
  --base  <dn> search base (default: environment, config, or server naming contexts)
  --start-tls  upgrade ldap:// using StartTLS (default: environment or config, otherwise false)
  --ca-file  <pem> append a trusted CA (default: environment or config, otherwise bundled roots)
  --ca-only  trust only --ca-file certificates (default: false)
  --tls-no-verify  disable certificate verification (default: false)
  --tls-max-version  <1.2> cap verified TLS to TLS 1.2 (default: environment or config, otherwise runtime maximum)
  --insecure-plaintext  allow plaintext LDAP (default: false)
  --anonymous  bind anonymously (default: false)
  --profile  <name> select a saved profile (default: environment profile, defaultProfile, or sole saved profile)
  --auth  <auto|gssapi|simple> authentication selection (default: auto; environment or config overrides)
  --gssapi-service  <service@fqdn> override the URL-derived GSSAPI service (default: ldap@URL-host; environment or config overrides)
  --gssapi-protection  <none|confidentiality> required GSSAPI protection; the URL scheme selects it (default: none over TLS, confidentiality over plain LDAP)
  --offline  report authentication selection without connecting or binding (default: false)
Defaults: one bind against the configured URL, and the server-resolved identity when the server advertises RFC 4532 Who Am I.
--offline reports the selection without contacting the directory and performs no bind.
Examples:
  ldap-axi auth status --profile production
  ldap-axi auth status --offline --url ldaps://directory.example.test
```

## server

```text
Report rootDSE capabilities and server flavor.
Usage: ldap-axi server [flags]
Flags:
  --help  show this help
  --config  <path> select a credential-standard config file (default: LDAP_AXI_CONFIG, then platform config directory)
  --url  <ldap[s]://host:port> directory URL (default: environment or config)
  --base  <dn> search base (default: environment, config, or server naming contexts)
  --start-tls  upgrade ldap:// using StartTLS (default: environment or config, otherwise false)
  --ca-file  <pem> append a trusted CA (default: environment or config, otherwise bundled roots)
  --ca-only  trust only --ca-file certificates (default: false)
  --tls-no-verify  disable certificate verification (default: false)
  --tls-max-version  <1.2> cap verified TLS to TLS 1.2 (default: environment or config, otherwise runtime maximum)
  --insecure-plaintext  allow plaintext LDAP (default: false)
  --anonymous  bind anonymously (default: false)
  --profile  <name> select a saved profile (default: environment profile, defaultProfile, or sole saved profile)
  --auth  <auto|gssapi|simple> authentication selection (default: auto; environment or config overrides)
  --gssapi-service  <service@fqdn> override the URL-derived GSSAPI service (default: ldap@URL-host; environment or config overrides)
  --gssapi-protection  <none|confidentiality> required GSSAPI protection; the URL scheme selects it (default: none over TLS, confidentiality over plain LDAP)
Defaults: one selected authentication exchange; no search base is required.
Reports advertised facts only; absent optional attributes are omitted, and absent limit values are reported as not advertised.
A configured flavor override is explicit alongside the detected flavor.
Examples:
  ldap-axi server --profile production
  ldap-axi server --url ldaps://directory.example.test --anonymous
```

## profile list

```text
profile list [--config <path>]
List configured profile names, URLs and auth modes without resolving secrets.
Defaults: LDAP_AXI_CONFIG, then the platform config directory.
Examples: ldap-axi profile list
          ldap-axi profile list --config /private/config.json
```

## config path

```text
config path [--config <path>]
Show the config path without reading credentials.
Defaults: LDAP_AXI_CONFIG, then the platform config directory.
Examples: ldap-axi config path
          ldap-axi config path --config /private/config.json
```

## setup

```text
Install or repair explicitly selected local agent integrations. No directory connection.
Usage: ldap-axi setup --app <claude|codex|opencode> [--skill] [--hook] [--check]
Flags:
  --app  required agent target; no automatic host selection
  --skill  install the shipped static skill (default: false)
  --hook  install offline home via SessionStart or an OpenCode plugin (default: false)
  --check  report missing or stale integrations without writing (default: false)
  --help  show this reference
Select at least one of --skill or --hook. Repeating setup repairs owned files and preserves unrelated settings.
Examples:
  ldap-axi setup --app claude --hook --skill
  ldap-axi setup --app codex --skill --check
```
