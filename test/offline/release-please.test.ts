import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parse } from "yaml";
import { Manifest } from "release-please/build/src/manifest.js";
import { buildStrategy } from "release-please/build/src/factory.js";
import { parseConventionalCommits } from "release-please/build/src/commit.js";
import type { Scm } from "release-please/build/src/scm.js";
import type { PullRequest } from "release-please/build/src/pull-request.js";
import { TagName } from "release-please/build/src/util/tag-name.js";

async function fixture(pullRequests: PullRequest[] = []) {
  // Only the remote repository boundary is replaced; versioning and release planning are real.
  const github = {
    repository: { owner: "example", repo: "ldap-axi", defaultBranch: "main" },
    async getFileJson(path: string) { return JSON.parse(await readFile(path, "utf8")); },
    async getFileContentsOnBranch(path: string) {
      const parsedContent = await readFile(path, "utf8");
      return { parsedContent, content: Buffer.from(parsedContent).toString("base64"), sha: "fixture" };
    },
    async *pullRequestIterator() { yield* pullRequests; },
  } as unknown as Scm;
  const manifest = await Manifest.fromManifest(github, "main");
  const strategy = await buildStrategy({ ...manifest.repositoryConfig["."], github, targetBranch: "main" });
  return { manifest, strategy };
}

test("a conventional fix plans the next package version and generated changelog", async () => {
  const { manifest, strategy } = await fixture();
  const pkg = JSON.parse(await readFile("package.json", "utf8"));
  const previous = manifest.releasedVersions["."];
  assert.equal(previous.toString(), pkg.version);
  const candidate = await strategy.buildReleasePullRequest(parseConventionalCommits([
    { sha: "a".repeat(40), message: "fix: reject invalid filters", files: ["src/cli.ts"] },
  ]), { tag: new TagName(previous), sha: "b".repeat(40), notes: "previous release" });
  assert.ok(candidate);
  const expected = `${previous.major}.${previous.minor}.${previous.patch + 1}`;
  assert.equal(candidate.version?.toString(), expected);
  const updates = new Map(candidate.updates.map(update => [update.path, update]));
  assert.equal(JSON.parse(updates.get("package.json")!.updater.updateContent(JSON.stringify(pkg))).version, expected);
  const lock = await readFile("package-lock.json", "utf8");
  assert.equal(JSON.parse(updates.get("package-lock.json")!.updater.updateContent(lock)).packages[""].version, expected);
  assert.match(updates.get("CHANGELOG.md")!.updater.updateContent(undefined), /reject invalid filters/);
});

test("a merged version PR plans exactly one draft with the package version tag", async () => {
  const { manifest, strategy } = await fixture();
  const candidate = await strategy.buildReleasePullRequest(parseConventionalCommits([
    { sha: "a".repeat(40), message: "fix: reject invalid filters" },
  ]), { tag: new TagName(manifest.releasedVersions["."]), sha: "b".repeat(40), notes: "previous" });
  assert.ok(candidate);
  const merged: PullRequest = {
    number: 1, title: candidate.title.toString(), body: candidate.body.toString(),
    headBranchName: candidate.headRefName, baseBranchName: "main",
    sha: "c".repeat(40), labels: ["autorelease: pending"],
    files: candidate.updates.map(update => update.path),
  };
  const pending = await fixture([merged]);
  const releases = await pending.manifest.buildReleases();
  assert.equal(releases.length, 1);
  assert.equal(releases[0].tag.toString(), `v${candidate.version}`);
  assert.equal(releases[0].sha, merged.sha);
  assert.equal(releases[0].draft, true);
  const tagged = await fixture([{ ...merged, labels: ["autorelease: tagged"] }]);
  assert.deepEqual(await tagged.manifest.buildReleases(), []);
});

test("release automation only opens version PRs until native integration is enabled", async () => {
  const workflow = parse(await readFile(".github/workflows/release-please.yml", "utf8"));
  assert.deepEqual(workflow.on, { push: { branches: ["main"] } });
  assert.deepEqual(Object.keys(workflow.jobs), ["release-pr"]);
  const job = workflow.jobs["release-pr"];
  assert.deepEqual(job.permissions, { contents: "write", issues: "write", "pull-requests": "write" });
  assert.equal(job.steps.length, 1);
  assert.equal(job.steps[0].uses, "googleapis/release-please-action@v4");
  assert.deepEqual(job.steps[0].with, {
    "config-file": "release-please-config.json",
    "manifest-file": ".release-please-manifest.json",
    "target-branch": "main",
    "skip-github-release": true,
  });
});

test("native release promotion depends on staged package consumption", async () => {
  const { jobs } = parse(await readFile(".github/workflows/native-prebuilds.yml", "utf8"));
  assert.deepEqual(jobs["release-stage"].needs, ["linux-current-load", "windows-build-test"]);
  assert.equal(jobs["release-consume"].needs, "release-stage");
  assert.equal(jobs["release-publish"].needs, "release-consume");
  assert.equal(jobs["release-stage"].if, "startsWith(github.ref, 'refs/tags/v')");
  assert.equal(jobs["release-consume"].if, "startsWith(github.ref, 'refs/tags/v')");
  assert.equal(jobs["release-publish"].if, "startsWith(github.ref, 'refs/tags/v')");
});
