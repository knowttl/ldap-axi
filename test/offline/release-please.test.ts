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

type WorkflowStep = {
  name?: string;
  uses?: string;
  with?: Record<string, unknown>;
  env?: Record<string, string>;
  if?: string;
  run?: string;
};
type WorkflowJob = { needs?: string | string[]; if?: string; steps: WorkflowStep[] };

async function fixture(pullRequests: PullRequest[] = []) {
  const events: unknown[] = [];
  // Only the remote repository boundary is replaced; versioning and release planning are real.
  const github = {
    repository: { owner: "example", repo: "ldap-axi", defaultBranch: "main" },
    async getFileJson(path: string) { return JSON.parse(await readFile(path, "utf8")); },
    async getFileContentsOnBranch(path: string) {
      const parsedContent = await readFile(path, "utf8");
      return { parsedContent, content: Buffer.from(parsedContent).toString("base64"), sha: "fixture" };
    },
    async *pullRequestIterator() { yield* pullRequests; },
    async *releaseIterator() {
      const pkg = JSON.parse(await readFile("package.json", "utf8"));
      yield { tagName: `v${pkg.version}`, sha: "b".repeat(40), notes: "previous release" };
    },
    async *mergeCommitIterator() {
      yield { sha: "a".repeat(40), message: "fix: reject invalid filters", files: ["src/cli.ts"] };
      yield { sha: "b".repeat(40), message: "chore: previous release", files: [] };
    },
    async createRelease(...[release, options]: Parameters<Scm["createRelease"]>) {
      events.push({ tag: release.tag.toString(), sha: release.sha, options });
      return { tagName: release.tag.toString(), sha: release.sha, url: "https://example.com/release" };
    },
    async commentOnIssue() {},
    async removeIssueLabels(labels: string[], number: number) { events.push({ remove: labels, number }); },
    async addIssueLabels(labels: string[], number: number) { events.push({ add: labels, number }); },
  } as unknown as Scm;
  const manifest = await Manifest.fromManifest(github, "main");
  const strategy = await buildStrategy({ ...manifest.repositoryConfig["."], github, targetBranch: "main" });
  return { manifest, strategy, events };
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

test("a merged pending version PR plans a draft and blocks subsequent version PRs", async () => {
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
  assert.equal(releases[0].forceTag, true);
  assert.equal((await pending.manifest.buildPullRequests()).length, 1);
  assert.deepEqual(await pending.manifest.createPullRequests(), []);
  await pending.manifest.createReleases();
  assert.deepEqual(pending.events, [
    { tag: `v${candidate.version}`, sha: merged.sha, options: { draft: true, prerelease: undefined, forceTag: true } },
    { remove: ["autorelease: pending"], number: merged.number },
    { add: ["autorelease: tagged"], number: merged.number },
  ]);
});

test("release creation explicitly invokes the native workflow with its exact tag and commit", async () => {
  const workflow = parse(await readFile(".github/workflows/release-please.yml", "utf8"));
  assert.deepEqual(workflow.on, { push: { branches: ["main"] } });
  const job = workflow.jobs["release-pr"];
  assert.deepEqual(job.permissions, { contents: "write", issues: "write", "pull-requests": "write" });
  assert.equal(job.steps.length, 1);
  assert.equal(job.steps[0].uses, "googleapis/release-please-action@v4");
  assert.deepEqual(job.steps[0].with, {
    "config-file": "release-please-config.json",
    "manifest-file": ".release-please-manifest.json",
    "target-branch": "main",
  });
  assert.equal(job.steps[0].id, "release");
  assert.deepEqual(job.outputs, {
    released: "${{ steps.release.outputs.release_created }}",
    tag: "${{ steps.release.outputs.tag_name }}",
    sha: "${{ steps.release.outputs.sha }}",
  });
  const native = workflow.jobs["native-release"];
  assert.equal(native.needs, "release-pr");
  assert.equal(native.if, "needs.release-pr.outputs.released == 'true'");
  assert.equal(native.uses, "./.github/workflows/native-prebuilds.yml");
  assert.deepEqual(native.with, {
    tag: "${{ needs.release-pr.outputs.tag }}",
    sha: "${{ needs.release-pr.outputs.sha }}",
  });
  assert.equal(native.secrets, "inherit");
});

test("native release promotion depends on staged package consumption", async () => {
  const workflow = parse(await readFile(".github/workflows/native-prebuilds.yml", "utf8"));
  assert.deepEqual(Object.keys(workflow.on).sort(), ["push", "workflow_call", "workflow_dispatch"]);
  assert.deepEqual(workflow.on.push, { tags: ["v*"] });
  assert.equal(workflow.on.workflow_call.inputs.tag.required, true);
  assert.equal(workflow.on.workflow_call.inputs.sha.required, true);
  assert.equal(workflow.on.workflow_dispatch.inputs.tag.required, true);
  assert.deepEqual(workflow.concurrency, { group: "native-release-${{ inputs.tag || github.ref_name }}", "cancel-in-progress": false });
  const jobs = workflow.jobs as Record<string, WorkflowJob>;
  assert.deepEqual(jobs["release-stage"].needs, ["release-plan", "linux-current-load", "windows-build-test"]);
  assert.deepEqual(jobs["release-consume"].needs, ["release-plan", "release-stage"]);
  assert.deepEqual(jobs["release-publish"].needs, ["release-plan", "release-consume"]);
  for (const [name, job] of Object.entries(jobs)) {
    if (name === "release-plan") continue;
    const checkout = job.steps.find(step => step.uses === "actions/checkout@v7");
    assert.equal(checkout?.with?.ref, "${{ needs.release-plan.outputs.sha }}", name);
    if (name === "linux-build-test" || name === "windows-build-test") assert.equal(job.if, "needs.release-plan.outputs.active == 'true'");
  }
  const stage = jobs["release-stage"].steps;
  assert.deepEqual(stage.find(step => step.name === "Pin release digests in package manifest")?.env, {
    RELEASE_TAG: "${{ needs.release-plan.outputs.tag }}",
  });
  assert.equal(stage.find(step => step.name === "Pack release commit")?.if, "steps.resume.outputs.reused != 'true'");
  const publisher = jobs["release-publish"].steps;
  assert.equal(publisher.find(step => step.name === "Publish exact tested npm package with provenance")?.run, "node scripts/native-release.mjs publish");
  assert.equal(publisher.at(-1)?.name, "Promote tested release");
});
