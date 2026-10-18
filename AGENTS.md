# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## v1 is read-only, and this is not negotiable

**ldap-axi v1 requires only directory read access and implements no add, modify, modifyDN, rename, move,
delete, password-set, password-reset, or write-capable extended operation.**
This is a binding architectural invariant throughout v1.
No agent may relax it; if a task seems to require a mutation, stop and escalate.

Four consequences that catch people out, and LDAP is worse for this than any sibling project:

- **Read-only is semantic, not operation-name-based.**
  Extended operation is a single LDAP operation whose safety depends entirely on its OID: StartTLS
  (`1.3.6.1.4.1.1466.20037`) changes nothing, RFC 3062 Password Modify (`1.3.6.1.4.1.4203.1.11.1`) changes a
  credential.
  Extended operations are therefore denied by default and admitted by a two-OID allowlist.
- **A blanket ban on `exop` breaks encryption.**
  `ldapts` implements `startTLS()` by calling its own `exop()`, so the allowlist must be a filter, not a ban.
- **Bind changes no entry and still has server-side effects.**
  A failed bind on Active Directory increments `badPwdCount` and can lock the account out.
  One bind per invocation, no retry, no fallback ladder, `autoRebind` off, and no credential-probing surface.
- **A `Client` handed to a command module is a hole.**
  `ldapts`'s `Client` prototype exposes `add`, `modify`, `modifyDN`, `del`, `exop`, and a runtime-reachable
  `_send`, because TypeScript `private` is erased at compile time.
  The sealed client keeps the instance module-private and never returns it; a `Proxy` forwarding unknown
  properties would not be safe.

See `docs/design/v1.md` §0 (the invariant), §1.5 (excluded capability classes), §2.2 (the admission rule),
§3 (the sealed client, the OID allowlist, the control allowlist), and §19 (live-test boundary).

## The v1 design is authoritative

`docs/design/v1.md` is the committed design: command surface, flavor detection, AD and generic LDAPv3
semantics, injection safety, paging, TLS, credentials, error envelope, TOON output, cross-platform rules,
client-library evaluation, fixtures, and live-test boundaries.
Read it before adding or changing any command surface, and update it in the same change when the surface
moves.
Its §20 records open questions; check there before re-deriving a decision that was already argued, and its
§21 cites every source, so a claim can be re-verified rather than trusted.
§20.1 records the resolved design constraints and their enforcement, §20.2 the questions still recorded rather
than answered, and §21 opens with the only live-directory evidence this project has.
`docs/support-matrix.md` is the status surface - command states, platforms, native-provider rules, the Linux
runtime-library requirements, and what is proved versus unproved - so status belongs there, not in `README.md`.

Stage 1 and stage 2 are implemented: the `src/` foundation, `entry search`, `entry show`, `user list`,
`user show`, `user groups`, `group list`, `group show`, and `group members` all ship, and Phase 4 adds
`auth status` plus the home view, `computer list` / `computer show` ship, and `server` reports cached rootDSE facts, with the remaining v1 command surface (`setup`)
deferred to later stages.
`auth status` is the one authentication diagnostic: it reports credential provenance, the recorded native
provider status from `build/native-status.json`, the scheme-selected mechanism, the SASL security layer, and
the TLS channel binding, and `--offline` reports that selection with no connection and no bind.
The home view lists the implemented commands and never connects.
`scripts/live-smoke.mjs` (`npm run smoke:live`) is the manual live check: `LDAP_AXI_LIVE=1`, one fixed
read-only sequence, GSSAPI tracing, and a redacted evidence file written outside the repository
(`docs/design/v1.md` §19.5).
Phase B adds the auth planner, the in-repository patched optional `kerberos@7.0.0` provider, RFC 4752 security-layer negotiation, and sealed binary GSSAPI/SASL transport;
the package root verifies a target prebuild or falls back to `vendor/kerberos` source, loads it only from `src/directory/gssapi.ts`, and keeps the protected client transport behind the directory boundary.
`build/native-status.json` is the provider loader's source of truth, not a report: a recorded `unavailable` install is refused, a recorded `installed` install must load `build/Release/kerberos.node`, and only a missing status file admits the verified bundled prebuild.
This is the narrow exception to the native-addon, `node-gyp`, and `node:child_process` bans: only package install and target-native prebuild scripts may run the pinned build tool, while runtime directory code and external LDAP or platform tools remain forbidden.
`npm run verify` is the single entry point for the complete local required-check set described in
`docs/design/v1.md` §18.5 and §19.4.
The opt-in `npm run test:local-directory` (Linux and Docker only) provisions an ephemeral Samba AD DC plus an OpenLDAP/MIT KDC mock and is
the real-directory drift check described in §18.4; it stays outside `npm run verify`.

- **Identifier resolution for `user show` / `group show`** is one contract, in `src/directory/identity.ts`:
  a syntactically valid DN (per the RFC 4514 parser in `src/directory/dn.ts`) gets one base-scope read with
  required object-shape validation and no fallback; a non-DN identifier gets one exact escaped flavor-specific
  search.
  Zero matches is `NOT_FOUND`, one is returned, and two or more is `VALIDATION_ERROR` requiring a DN.
  There is no preferred match, no retry across identifier forms, and no selector flag.
  Cardinality counts only the entries the searched server returned: AD's domain-root continuation references
  are reported in the `NOT_FOUND` help, never chased and never treated as an incomplete search, while a
  terminal result code 10 or a server limit still raises `SERVER_LIMIT` (`docs/design/v1.md` §5.5 rule 4).
- **AD's ranged-attribute retrieval (`member;range=0-1499`) has an `ldapts` quirk that looks like a bug in
  this project if you don't know it.**
  `SearchEntry.toObject()` fills in an empty array for every *requested* attribute name that has no exact key
  in the response, so requesting bare `member` against a group AD ranges produces **both** an empty
  `member: []` **and** a populated `member;range=0-1499: [...]` on the same entry.
  `src/directory/membership.ts`'s `readMultivaluedAttribute` scans for the ranged key first and ignores the
  spurious empty bare key; do not "fix" this by trusting `values(entry, attribute)` directly on a group's
  membership attribute.
- **`primaryGroupID` resolution reuses the bind account's own domain SID trick**: strip the last sub-authority
  from a user's `objectSid` to get the domain SID, then append `primaryGroupID` as the new RID.
  This avoids a second rootDSE round trip and is why `sidWithRid`/`domainSid` live in `src/directory/sid.ts`.

## Sharp edges verified by running code, not by reading docs

Each is owned by `docs/design/v1.md` and pinned by a regression in §18.5.

- **A real directory refuses a SASL security layer on a TLS connection, which is why D1 option C selects no
  layer over TLS.**
  `source4/ldap_server/ldap_bind.c` refuses sign or seal over TLS unconditionally, with no server-side option,
  and Windows Active Directory applies the same rule, so the TLS transport negotiates **no** SASL security
  layer (see the URL-scheme sharp edge below and `docs/design/v1.md` §10.7).
  Servers still diverge on the resulting no-layer TLS bind: measured by `npm run test:local-directory`, Samba
  4.19.5 answers `STRONGER_AUTH_REQUIRED` (result 8) while the production DC in the Phase 0 report answers
  success, so the Samba portion cannot prove the TLS bind end to end.
- **Only a real server proves the client's own entry handling.**
  `RecordedDirectory` replaces `LdapDirectory.rootDSE()`, which is why a read of a property that
  `searchPaginated` entries never carry survived the whole offline suite.
  Reach for `test/local-directory/` or a served BER entry when a change touches the real client.
- **Empty SASL continuation encoding is load-bearing.**
  `docs/design/v1.md` §10.6 owns the wire contract, and §18.5 names its sealed verified-TLS regression.
- **Active Directory never emits minimal BER lengths.**
  Every LDAPMessage length arrives in four-octet long form (`30 84 00 00 00 32`), including values under 128,
  so a decoder that enforces DER-minimal encoding stalls a live bind at SASL round 2 while round 1 succeeds.
  RFC 4511 §5.1 requires a definite length, not a minimal one; only the bounded frame limit may reject one.
- **The GSSAPI transport is chosen by URL scheme, with no fallback** (`docs/design/v1.md` §10.7, D1 option C).
  `ldaps://` and StartTLS bind with channel binding and select **no** SASL security layer; plain `ldap://`
  binds with a **mandatory confidentiality** layer, wraps every post-bind PDU, and therefore does not require
  `--insecure-plaintext`.
  `--gssapi-protection` no longer selects the layer: it is accepted only when it names the layer the scheme
  already requires.
- **`ldapts`'s `escapeFilter` is a tagged template function, and misusing it fails silently.**
  `escapeFilter\`(cn=${value})\`` escapes correctly per RFC 4515.
  `escapeFilter(value)` returns the string's **first character** and does not throw, because a string indexed
  as a `TemplateStringsArray` yields `value[0]`.
  This project therefore owns its own `filterValue` and `dnValue` escapers, tested against the byte table, and
  a lint rule rejects any non-tagged reference to the library helper.
- **`tlsOptions.ca` replaces Node's trust store; `NODE_EXTRA_CA_CERTS` extends it.**
  Measured: `tls.connect` to a public host with `ca` set to one corporate root fails with
  `UNABLE_TO_GET_ISSUER_CERT_LOCALLY`, while the same connection under `NODE_EXTRA_CA_CERTS` succeeds.
  So `--ca-file` **appends** to `tls.rootCertificates`; only `--ca-only` replaces.
- **Node does not use the system trust store.**
  On this machine Node's bundled store carries 120 certificates and none is the corporate root, while
  `/etc/ssl/certs/ca-certificates.crt` carries 122 including it.
  An LDAPS failure inside a corporate network is usually this, not a server problem, so `TLS_UNTRUSTED` names
  the CA remedies.
- **`ldapts`'s `startTLS()` passes `socket` without a host identity**, so certificate hostname verification on
  that path depends on the caller supplying `host` from the URL.
  Pass `servername` for DNS hosts only; IP literals must omit SNI.
- **`ldapts` sets `secure = isSecureProtocol || hasTlsOptions`**, so passing `tlsOptions` alongside an
  `ldap://` URL silently attempts implicit TLS on port 389. TLS options go to the constructor only for
  `ldaps://`, and to `startTLS()` otherwise.
- **`search()` with `paged: true` buffers every page into one array.** Only `searchPaginated()` is used.
- **`ldapts` does not publicly expose RFC 2696 request or response cookies.** v1 paging is in-process only;
  `--cursor` is deliberately rejected, and any future resumable-cursor work needs a maintained client with a
  supported public cookie API rather than private internals.
- **Active Directory silently truncates at `MaxPageSize` (default 1000) without the paged control.**
  Not an error - a plausible-looking, quietly incomplete result. Paging is unconditional; there is no flag to
  disable it.
- **`@toon-format/toon` 2.3.1 does quote comma-bearing values inside inline arrays.**
  The fleet's mangling note applies to the hand-formatted `help[N]:` block, which bypasses `encode()`, not to
  encoded row data. The keyed tabular form is still unavailable at 2.3.1.
- **`axi-sdk-js` 0.1.8 does not export `renderError`.** Return a string or object to `runAxiCli` and throw
  `AxiError`; pass an own `formatError`, because `exitCodeForError` maps only literal `VALIDATION_ERROR` to
  exit 2 and this project has many exit-2 codes.

## Two decoding traps that produce confidently wrong answers

- **`LOCKOUT` and `PASSWORD_EXPIRED` must not be read from `userAccountControl`.**
  On Windows Server 2003 and later domains they are superseded by `msDS-User-Account-Control-Computed`.
  Reading them from the raw bitfield is wrong on every modern domain and looks right in a self-authored
  fixture.
- **`memberOf` omits the user's primary group** (typically Domain Users, RID 513), because it is a computed
  back-link. `user groups` defaults to `tokenGroups`, which includes it; the `memberOf` fallback must resolve
  `primaryGroupID` explicitly and report the composite method.

FILETIME sentinels `0` and `9223372036854775807` mean unset and never; converting them naively renders 1601
and 30828. `objectGUID` is mixed-endian, so a straight hex dump does not match AD tooling.

## Cross-platform is a requirement, not a nice-to-have

v1 must run on Linux and Windows.
Native addons, `node-gyp`, and `node:child_process` are forbidden except for the package install and target-native prebuild scripts described above.
Runtime code must never shell out to `ldapsearch`, `ldp.exe`, `dsquery`, PowerShell, or any other platform tool, and the architecture test rejects `node:child_process` throughout `src/`.
Compose paths with `node:path`; resolve config under `%APPDATA%` on Windows and XDG elsewhere.

**Never prepend a whole system library directory to `LD_LIBRARY_PATH` to find the Kerberos runtime.**
A Nix-provided Node then loads the system `libuv` and dies with `undefined symbol: uv_tcp_keepalive_ex` before
any ldap-axi code runs.
`test/offline/package.test.ts` links only the six Kerberos/GSS sonames into a shim directory for this reason,
and `docs/support-matrix.md` documents the same pattern for operators.
A Linux provider load that fails on a missing library names that exact soname in `GSSAPI_UNAVAILABLE`.

The POSIX `0600` credential-file check cannot be replicated on Windows, where security is ACL-based.
It is **skipped and reported as unchecked** rather than silently claimed. Do not "fix" that by adding a
vacuous mode test.

## Credential rules

- Secrets reach ldap-axi through the environment or a `0600` file, **never** through `argv`.
  A flag-registration guard rejects any flag whose name looks like a secret, and a test asserts declaring
  `--bind-password` throws.
- A half credential pair is `CREDENTIAL_INCOMPLETE` when resolving an env profile or simple authentication; no other source is consulted as a fallback, and ambient auth leaves file-profile passwords unresolved (§11.1).
- Anonymous bind is explicit via `--anonymous`, never a silent fallback when a credential fails to resolve.
- `userPassword` and `unicodePwd` are on a never-request denylist; naming one in `--attributes` is refused.
- No credential, password, DN from a real directory, SID, GUID, or captured directory content belongs in this
  repository, including fixtures.
  See `docs/design/v1.md` §11 and §18.3.

## Build to the AXI skill

Every agent-facing surface in this repo follows the AXI standard (TOON on stdout, minimal schemas, structured
errors on stdout, content-first home view, fail-loud on unknown flags).
Read the `axi` skill at `~/.pi/agent/skills/axi/SKILL.md` and the TOON spec it points to before building or
reviewing any CLI behavior here.
`azure-axi`, `awx-axi`, and `falcon-axi` are the sibling references for these patterns; `docs/design/v1.md`
§21 closes with where their assumptions do **not** transfer to LDAP.

## GitHub Actions boundary

The native prebuild workflow may build and behavior-test the Linux glibc x64 and Windows x64 provider artifacts, run `npm run verify` on the Windows runner, attest tagged artifacts, and attach them to the matching GitHub release.
The local-directory workflow runs `docs/design/v1.md` §18.4's suites from a manual workflow dispatch only.
Neither may ever receive directory credentials or run live-directory tests.
Only these workflows and the release-please workflow, limited to version pull requests on `main` until native-release integration lands, are authorized, and the architecture lint enforces that list.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
The Markdown sentence rule means each sentence starts on its own physical line; a sentence may wrap across
following lines, but two sentences must not share one physical line.
