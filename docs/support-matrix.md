# ldap-axi support matrix

What ships, what is planned, where it runs, and what has actually been proved.
This file is the single status surface for the project; `README.md` states the invariants and links here.
`docs/design/v1.md` remains the authority for why each row is what it is.

## Command surface

| Command | State |
| --- | --- |
| `entry search`, `entry show` | Implemented |
| `user list`, `user show`, `user groups` | Implemented |
| `group list`, `group show`, `group members` | Implemented |
| `computer list`, `computer show` | Planned |
| `auth status` | Implemented, including the non-connecting `--offline` report |
| `server`, `setup` | Planned |

Implemented commands cover Active Directory and generic LDAPv3, decoded account state, SID/GUID/FILETIME and
`groupType` handling, nested and direct membership, and the partial/incomplete result contract.
See `docs/design/v1.md` §1 for what is deferred and why, and §5.4 for the per-command flavor table.

## Authentication

| Mode | Selection | State |
| --- | --- | --- |
| `auto` | Default; `--auth auto` or `LDAP_AXI_AUTH` | One ambient GSSAPI/SSPI attempt after the transport is ready, then terminal failure; it never silently selects a configured password |
| `gssapi` | `--auth gssapi` | The URL scheme selects the transport with no fallback: verified LDAPS or StartTLS binds with channel binding and no SASL security layer, while plain `ldap://` binds with a mandatory confidentiality layer; `--gssapi-protection` is accepted only when it names the layer the scheme already requires (`docs/design/v1.md` §10.7) |
| `simple` | `--auth simple` | Preserves a configured service identity and never loads the native provider |
| anonymous | `--anonymous` | Explicit only, never a fallback |

`--gssapi-service` and `LDAP_AXI_GSSAPI_SERVICE` override the host-based service name.
Use `--tls-max-version 1.2` only for verified LDAPS or StartTLS endpoints that require a TLS 1.2 cap.
Credential rules, including the never-on-argv guarantee, are in `docs/design/v1.md` §11.

## Platforms

| Target | Offline commands, simple auth, TLS | Native GSSAPI provider |
| --- | --- | --- |
| Linux glibc x64 | Supported | Bundled digest-pinned prebuild, or a supported source build |
| Windows x64 | Supported | Target-native prebuild consumed from the matching GitHub release, or a supported source build |
| Linux musl, Linux arm64, Windows arm64, macOS | Supported, unverified beyond the two targets above | Rejected before any build; explicit simple mode keeps working |

Node `>=24.11.0` is required on every platform.
The Linux prebuild additionally requires glibc 2.28 or newer and a libstdc++ providing GLIBCXX_3.4.25 or newer.

## Native provider installation and loading

Installation records its outcome in `build/native-status.json`, and the provider loader treats that record as
the source of truth: a recorded `unavailable` installation is refused, a recorded `installed` installation must
load `build/Release/kerberos.node`, and only an installation that never ran admits the verified bundled
prebuild.
Native installation failure is non-fatal; a later provider or runtime load failure is reported as the stable
`GSSAPI_UNAVAILABLE` code.
`LDAP_AXI_NATIVE_MODE` accepts `off` to skip native installation, `prebuild` to require a verified prebuild
with no source fallback, and `source` to force the supported source build.
`LDAP_AXI_KERBEROS_INCLUDE_DIR` passes a nonstandard Kerberos header location to a source build.
Linux source builds need Python, the installed node-gyp dependency, a C++ compiler, and Kerberos/GSS
development headers; Windows source builds need node-gyp, MSVC, and the Windows SDK.

### Installing a GitHub release archive

Once the tested `v0.1.2` release assets are published, download `knowttl-ldap-axi-0.1.2.tgz` from the
[GitHub release](https://github.com/knowttl/ldap-axi/releases/tag/v0.1.2), then run the following from the download directory with Node `>=24.11.0`.
Use the packaged `.tgz` asset, which contains the release-pinned native digests; GitHub's automatically generated source archives and a source checkout do not contain the Windows release digest.

Windows x64 (PowerShell):

```powershell
$env:LDAP_AXI_NATIVE_MODE = 'prebuild'
npm install --global ./knowttl-ldap-axi-0.1.2.tgz
Remove-Item Env:LDAP_AXI_NATIVE_MODE
ldap-axi auth status --offline
```

Linux glibc x64:

```sh
LDAP_AXI_NATIVE_MODE=prebuild npm install --global ./knowttl-ldap-axi-0.1.2.tgz
ldap-axi auth status --offline
```

On Windows the install script downloads `kerberos-win32-x64.node` from the matching versioned release and checks its SHA-256 digest against the archive's `prebuilds/manifest.json` before loading it.
This path needs HTTPS access to GitHub release downloads, but does not need MSVC or the Windows SDK.
On Linux the archive bundles `kerberos-linux-glibc-x64.node` with a pinned digest, so no separate native download or compiler is needed.
The Linux ABI and runtime-library requirements above still apply.
The release also carries both `.node` assets and their `.node.sha256` files for inspection; users do not need to copy these files into the installation manually.

`prebuild` mode prevents a source-build fallback, but native installation failure remains non-fatal to npm.
Check `auth status --offline` for `native_provider_installation: installed` and `native_provider_detail: verified prebuild`; npm installation success alone does not prove native installation succeeded.
This offline command makes no directory connection and does not prove ambient credentials or a successful directory bind.
Without `LDAP_AXI_NATIVE_MODE=prebuild`, automatic mode attempts one source build if the verified prebuild cannot be installed, requiring the build tools listed above.
Explicit `--auth simple` remains available if the native provider is unavailable.

### Installing from npm before native release assets exist

See [the README](../README.md) for the npm package name and common installation commands.
The 0.1.0 bootstrap package retains the source tree's bundled Linux prebuild and Linux-only digest manifest.
It does not provide a compiler-free Windows native installation: without a pinned Windows manifest entry, automatic mode needs MSVC and the Windows SDK for its source fallback.
Publishing Windows release assets later cannot add a digest to an already-published npm package.
Packages published through the tag workflow contain both release-pinned digests and support the same compiler-free installation as the [release-packed archive](#installing-a-github-release-archive).

## Linux runtime libraries, and the Nix/WSL hazard

Every Linux native path, including a verified prebuild, needs the system Kerberos/GSS runtime libraries to be
discoverable by the dynamic loader.
When one is missing, ldap-axi names it exactly: `GSSAPI_UNAVAILABLE` carries the failing soname, for example
`libgssapi_krb5.so.2`, as its first remedy, and `LDAP_AXI_GSSAPI_TRACE=1` records the same value on
`gssapi-provider-load-result`.
Only a value matching a shared-library soname is reported; the addon path and the rest of the loader's prose
stay redacted.

**Do not point `LD_LIBRARY_PATH` at the whole system library directory when Node itself comes from Nix.**
Measured on a Nix-managed WSL2 host, `LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu npm --version` fails with
`symbol lookup error: undefined symbol: uv_tcp_keepalive_ex`, because the Nix `nodejs-slim` binary then picks
up the system `libuv` instead of its own.
That failure has nothing to do with ldap-axi and happens before any ldap-axi code runs.

The safe form is a directory that contains only the Kerberos/GSS libraries, as symlinks:

```sh
mkdir -p ~/.local/lib/ldap-axi-krb5
for lib in libgssapi_krb5.so.2 libkrb5.so.3 libk5crypto.so.3 libcom_err.so.2 libkrb5support.so.0 libkeyutils.so.1; do
  ln -sf "/usr/lib/x86_64-linux-gnu/$lib" ~/.local/lib/ldap-axi-krb5/
done
LD_LIBRARY_PATH=~/.local/lib/ldap-axi-krb5 ldap-axi entry search --help
```

A Node that is not from Nix, or a distribution whose loader configuration already covers these libraries,
needs none of this.

## Library surface

The package provides the `ldap-axi` executable after installation.
The supported surface is the package-root `openDirectory` export and the sealed read-only `Directory` it
returns.
The `exports` map rejects package-specifier deep imports, including provider, socket, SASL sender, and
protected-transport modules.
A hostile same-user process that absolute-path-imports private installed files, or loads the native addon
directly, is outside the threat model and needs process or operating-system isolation this package does not
claim.

## Release and provenance

Two captain-authorized workflows run in GitHub Actions and no other: the native prebuild workflow and the
manually dispatched local-directory workflow.
Neither receives directory credentials, and neither runs a live-directory test.
On a version tag the native prebuild workflow pins both build-job digests, packs and publishes with npm
provenance through the configured npm trusted publisher, attests the binaries and the package, and attaches the matching assets to the release.
The binaries are not Authenticode or platform-code-signed, and package installation does not independently
verify the attestation.

## What is proved, and what is not

| Claim | Evidence |
| --- | --- |
| Offline command surface, decoders, escaping, paging, TLS options, credential rules | `npm run verify`, wholly synthetic fixtures (`docs/design/v1.md` §18) |
| Real AD flavor detection, paging, referral reporting, `objectSid`/`objectGUID`/FILETIME/`userAccountControl` decoding, `tokenGroups` membership | Proved against an ephemeral Samba AD DC by the opt-in `npm run test:local-directory` (`docs/design/v1.md` §18.4) |
| Identifier-based `user show` / `group show` at an AD domain root, where the server returns continuation references | Offline regression only (`docs/design/v1.md` §5.5 rule 4, §18.5). The reference shape is the one `npm run test:local-directory` observes; no live re-proof is on record for the resolution path |
| A signed or sealed SASL layer over a TLS connection | **Refused by the server**, which is why D1 option C selects no SASL layer over TLS. Measured against Samba 4.19.5, and Windows AD applies the same rule (`docs/design/v1.md` §10.7, §20 item 8) |
| Generic ppolicy permanent lock state and schema-gated filters | Proved against real OpenLDAP by the opt-in local-directory suite, with focused offline timestamp regressions (`docs/design/v1.md` §7.1, §18.4) |
| ldap-axi's no-layer GSSAPI bind over TLS | Samba 4.19.5 answers `STRONGER_AUTH_REQUIRED` (result 8); the opt-in OpenLDAP/MIT KDC mock proves successful LDAPS and StartTLS binds; the production DC in the Phase 0 report answers success (`docs/design/v1.md` §18.4, §21) |
| Generic memberships and plain-LDAP Kerberos confidentiality interoperability | Proved against the real OpenLDAP/MIT KDC mock by the opt-in local-directory suite (`docs/design/v1.md` §18.4) |
| AD accepts the channel-bound GSSAPI bind ldap-axi sends over LDAPS | Live Phase 0 discovery against a production domain controller, 2026-09-17 (`docs/design/v1.md` §21) |
| A completed ldap-axi GSSAPI bind against a real AD domain controller | **Not proved.** Phase 0 found the client rejecting AD's non-minimal BER length encoding at SASL round 2 |
| Windows SSPI behavior against a real domain | **Not proved.** No domain-joined Windows run is on record; the remaining proof is one domain-joined Windows x64 run of the packaged release under `LDAP_AXI_GSSAPI_TRACE=1`, recording the SSPI package the operating system selected inside the GSS-SPNEGO exchange (`docs/design/v1.md` §20.1) |
| Server security-layer acceptance, protected-transport interoperability, Who Am I identity | **Not proved** by offline tests |

The manual live smoke script (`npm run smoke:live -- --url ldaps://server:636`) requires a read-only directory
credential and `LDAP_AXI_LIVE=1`, runs one fixed read-only sequence, writes a redacted evidence file outside
this repository, stays outside `npm run verify`, and never runs automatically (`docs/design/v1.md` §19.5).
