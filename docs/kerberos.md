# Linux Kerberos authentication

Use Node >=24.11.0 on Linux glibc x64, glibc >=2.28, and a C++ runtime providing GLIBCXX_3.4.25 or newer.
Native GSSAPI is unavailable on musl, arm64, and macOS; explicit `--auth simple` does not require the native provider.
See the [support matrix](support-matrix.md#native-provider-installation-and-loading) for prebuilds and source fallback.

## Prerequisites

1. Install loader-visible `libgssapi_krb5.so.2`, `libkrb5.so.3`, `libk5crypto.so.3`, `libcom_err.so.2`, `libkrb5support.so.0`, and `libkeyutils.so.1`.
   Debian/Ubuntu supplies them through `libgssapi-krb5-2`; RHEL/Rocky/Fedora uses `krb5-libs`.
2. Obtain a valid ticket in the default credential cache through your normal domain sign-in or approved ticket workflow.
   ldap-axi does not invoke `kinit`; operator use of `kinit`/`klist` requires `krb5-user` or `krb5-workstation`.
   MIT Kerberos supports FILE, KEYRING, and KCM caches; KCM requires a running cache service such as `sssd-kcm`.
   Only FILE caches have live verification on record.
3. Configure realm mapping in `krb5.conf` and use the directory's real FQDN matching its `ldap/<fqdn>` SPN.
   ldap-axi requests `ldap@<url-host>` without its own canonicalization.
   Avoid short names and aliases; IP literals require `--gssapi-service`.
4. For TLS, trust the server certificate through `--ca-file`, profile `caFile`, or `NODE_EXTRA_CA_CERTS`.
   Node's default trust store does not include every corporate system root.

## Diagnose offline, then read

```sh
ldap-axi auth status --offline --auth gssapi --url ldap://directory.example.test:389
ldap-axi user list --auth gssapi --url ldap://directory.example.test:389 --limit 10
```

Replace the synthetic hostname with your real directory FQDN before the connected command.
Plain LDAP with GSSAPI requires SASL confidentiality and encrypts all post-bind messages; it needs no CA file or `--insecure-plaintext`.
LDAPS or StartTLS instead requires verified TLS, uses channel binding, and selects no SASL security layer.
There is no transport downgrade or password fallback.
`--gssapi-protection` can only assert the protection already selected by the scheme.

Offline status reports recorded installation and planned authentication, without loading the provider or testing a ticket.
`GSSAPI_UNAVAILABLE` names a missing runtime soname when one can be identified.
Native installation failure is non-fatal to npm; inspect `native_provider_installation` and `native_provider_detail` instead of relying on npm's exit code.
Automatic installation tries one supported source build if the verified prebuild cannot be installed.
Source builds need Python, node-gyp, a C++ compiler, and Kerberos/GSS development headers.
`LDAP_AXI_NATIVE_MODE=prebuild` disables that source fallback; `off` skips native installation.

For Nix/WSL, never prepend a whole system library directory to `LD_LIBRARY_PATH`: Node may load an incompatible system libuv and fail before ldap-axi starts.
Use the [six-soname shim](support-matrix.md#linux-runtime-libraries-and-the-nixwsl-hazard) only when your loader needs it.

## Validation limits

Offline tests and disposable Samba/OpenLDAP suites cover different contracts from a production bind.
A completed GSSAPI bind against a production AD controller is not proved.
See the [evidence table](support-matrix.md#what-is-proved-and-what-is-not) before interpreting offline success as service interoperability.
