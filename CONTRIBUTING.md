# Contributing

Use Node 24.11.0 or newer on Linux or Windows.
For native-provider build prerequisites and platform limits, see the [support matrix](docs/support-matrix.md).

## Development checks

```sh
npm ci
npm run verify
```

`npm run verify` runs typechecking, ESLint, architecture lint, the build, offline tests including packed-package consumer checks, and generated-guidance drift verification.
`npm run lint` checks maintained JavaScript and TypeScript with ESLint and then runs the architecture checks.
Vendored sources, native prebuilds, and generated build and test output are excluded from ESLint.
Use `npm run lint:architecture` to run only the architecture checks.
The required checks run locally and use synthetic fixtures.
Run them before submitting a pull request.
Do not add GitHub test CI or CI badges as a substitute for local verification.
Existing native release automation is described in the [support matrix](docs/support-matrix.md#release-and-provenance).

Regenerate both committed skill copies, the README command-group table, and the full leaf reference in `docs/commands.md` with `npm run skill:generate` after changing their source guidance or CLI help.
Run `npm run skill:check` to check all generated guidance for missing or stale output without rewriting it.
See the [skill design](docs/design/v1.md#172-session-hook-and-skill) for the generation contract.

The optional `npm run test:local-directory` suite requires Linux and Docker and provisions disposable Samba AD and OpenLDAP/MIT KDC directories.
It is separate from `npm run verify`.
For no-mistakes pipeline validation, follow the restrictions in [the pipeline settings](.no-mistakes.yaml).
Real-directory checks require explicit opt-in and read-only credentials under the [live-test boundaries](docs/design/v1.md#19-safe-live-test-boundaries).
Never use real directory content, credentials, DNs, SIDs, GUIDs, tickets, or captured tokens in fixtures, logs, issues, or pull requests.

## Change requirements

Keep changes focused and describe the problem, resulting behavior, and local validation in the pull request.
Read the [v1 design](docs/design/v1.md) before changing a command contract and update it with any surface change.
Keep command and platform status in the [support matrix](docs/support-matrix.md).

v1 is strictly read-only and requires only directory read access.
Preserve the sealed directory boundary, operation and OID allowlists, one-bind authentication contract, TLS verification, and fail-closed credential selection.
Runtime code must not invoke platform tools or subprocesses.
The only native build exception is package installation and target-native prebuild production using the pinned build tool.

## Release changes

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for commits and squash-merge pull request titles, for example `fix: reject invalid filters` or `feat: add server inspection`.
Use `!` or a `BREAKING CHANGE:` footer for incompatible changes.
Release Please uses those messages to open a version pull request against `main`, updating `package.json`, `package-lock.json`, `.release-please-manifest.json`, and the generated `CHANGELOG.md` together.
Do not create or edit `CHANGELOG.md` by hand.
Review the generated version and notes before merging a release pull request.

Merging the version pull request starts the [release and provenance workflow](docs/support-matrix.md#release-and-provenance).
Release Please transitions the merged pull request from `autorelease: pending` to `autorelease: tagged`.

Add optional curated release notes at `docs/releases/<version>.md` in the version pull request, without the `v` prefix.
The matching file becomes the GitHub release body; when absent, generated release notes are retained.
An empty or unreadable notes file fails the release.

For recovery without a workflow fix, rerun the failed workflow.
To use a merged workflow fix, dispatch `Native prebuilds` from `main` with the existing version tag as the required `tag` input (for example, `v0.2.0`).
See the [release contract](docs/support-matrix.md#release-and-provenance) for commit checks, asset reuse, and publication recovery requirements.

## Compatibility

Deprecated aliases remain available for one minor release before removal.
For example, an alias deprecated in 0.1.x remains through that minor series and may be removed in 0.2.0.
Document replacements and removals in the release notes.
This policy does not remove any current alias.

## Security reports

Follow [SECURITY.md](SECURITY.md) for vulnerabilities rather than opening a public issue with sensitive details.
