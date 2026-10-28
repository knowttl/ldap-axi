# Windows installation and authentication

Use Node >=24.11.0 and Windows x64 for the native provider.
Windows arm64 cannot use native GSSAPI; explicit simple authentication remains available.

```powershell
npm install --global @knowttl/ldap-axi
ldap-axi auth status --offline
ldap-axi config path
```

The package installer retrieves the Windows prebuild from the matching versioned GitHub release and verifies its package-pinned SHA-256 digest.
This needs HTTPS access to GitHub release downloads, but no compiler when the verified prebuild succeeds.
Automatic mode attempts one source build if the prebuild cannot be installed; source fallback requires Python, node-gyp, MSVC, and the Windows SDK.
Set `LDAP_AXI_NATIVE_MODE` to `prebuild` to prohibit source fallback, or `off` to skip native installation.
Native installation failure is non-fatal to npm.
Check `native_provider_installation` and `native_provider_detail` in offline status; this does not load the provider or prove a bind.
See [release-archive installation](support-matrix.md#installing-a-github-release-archive) for the alternative package source.

## Domain sign-in

Ambient authentication uses the signed-in account's SSPI Negotiate context.
Sign in with a domain account, use the directory's real FQDN, and ensure directory and domain authentication services are reachable.
The operating system chooses the package inside one GSS-SPNEGO exchange; ldap-axi does not claim it always selects Kerberos rather than NTLM.

```powershell
ldap-axi auth status --offline --auth gssapi --url ldap://directory.example.test:389
ldap-axi user list --auth gssapi --url ldap://directory.example.test:389 --limit 10
```

Replace the synthetic hostname before the connected command.
Plain LDAP uses mandatory SASL confidentiality; LDAPS/StartTLS uses verified TLS with channel binding and no SASL security layer.
For a corporate CA, use `--ca-file C:\certs\corporate-root.pem` or set `NODE_EXTRA_CA_CERTS` before starting Node.
Keep TLS verification enabled.
Authentication failures are terminal with no password fallback or retry.

## Configuration and file permissions

Configuration lives at `%APPDATA%\ldap-axi\config.json`; use `config path` to resolve it.
Follow the [configuration profiles](configuration.md#profiles) for ambient or simple authentication.
File SecretRefs require an absolute drive path.
Restrict config directories and password files with Windows ACLs to the owning account.
Password-file permissions are reported as `unchecked (windows)`: POSIX mode checks cannot establish Windows ACL security.

## Validation limits

No domain-joined Windows SSPI run is on record.
Packaged native consumer checks and offline tests do not establish live Windows authentication or directory interoperability.
See the [support matrix](support-matrix.md#what-is-proved-and-what-is-not) for the evidence and remaining limits.
