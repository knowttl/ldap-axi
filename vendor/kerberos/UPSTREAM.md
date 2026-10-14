# ldap-axi Kerberos provider provenance

This directory carries the source package for `kerberos@7.0.0` from the MongoDB Node.js team.
The upstream package is Apache-2.0 licensed; its complete license text is in `LICENSE`.
The upstream repository is https://github.com/mongodb-js/kerberos at tag `v7.0.0`.
The npm tarball integrity is `sha512-Q8yUNeCM5fSXkURaa05WugXFsH6c57hDHDmsupMFCPaQEPym9FGwFp/2XSTcMuLldtEeBOsQ/9VGQ55lfHTT3Q==`.

The source is vendored because ldap-axi must not load the unmodified registry prebuild after changing the native API.
This directory is inert source rather than a second npm dependency.
The ldap-axi package root owns its build, package-relative load, source fallback, and patched prebuild verification.

The ldap-axi changes expose per-operation integrity and confidentiality, wrap-size limits, and binary channel-binding input through the restricted provider API.
Native error objects also retain unsigned numeric `gssMajor`/`gssMinor` on POSIX and `sspiCode` on Windows, so the adapter can distinguish unavailable or expired credentials without parsing native prose.

To update it, download the exact upstream npm tarball for the new version, compare every retained file with the upstream tag, reapply only the ldap-axi native and declaration changes, update the root lockfile, and run the clean packed-consumer tests.
Produce each prebuild on its named target and review its provenance before claiming coverage.
Commit a bundled development artifact with its SHA-256 manifest entry; it has no signature or attestation.
The tag workflow instead pins its native build outputs into the packed manifest and gives the release assets GitHub artifact provenance, but no platform code signature.
