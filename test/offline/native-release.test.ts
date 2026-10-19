import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

const helperPath = resolve("scripts/native-release.mjs");
const { releasePlan, releaseNotes, windowsAsset, publishPackage, stagedArchive } = await import(pathToFileURL(helperPath).href);

test("reruns reuse only complete draft assets and refuse ambiguous archives", () => {
  const names = ["kerberos-linux-glibc-x64.node", "kerberos-win32-x64.node"];
  const assets = [...names.flatMap(name => [name, `${name}.sha256`]), "package.tgz"].map(name => ({ name }));
  assert.equal(stagedArchive({ draft: true, assets }), "package.tgz");
  assert.equal(stagedArchive(undefined), undefined);
  assert.equal(stagedArchive({ draft: true, assets: assets.slice(1) }), undefined);
  assert.throws(() => stagedArchive({ draft: false, assets }), /already public/);
  assert.throws(() => stagedArchive({ draft: true, assets: [...assets, { name: "other.tgz" }] }), /ambiguous/);
});

test("release planning rejects mismatched commits and skips public releases", () => {
  const sha = "a".repeat(40);
  for (const release of [undefined, { draft: true }]) {
    assert.deepEqual(releasePlan("v1.2.3", sha, sha, release), { tag: "v1.2.3", sha, active: true });
  }
  assert.equal(releasePlan("v1.2.3", sha, undefined, { draft: false }).active, false);
  assert.throws(() => releasePlan("v1.2.3", sha, "b".repeat(40)), /commit/);
  assert.throws(() => releasePlan("main", sha), /version tag/);
});

test("release notes use the matching version file and generated fallback only when absent", async () => {
  assert.equal(await releaseNotes("v1.2.3", "generated", async (path: string) => {
    assert.equal(path, "docs/releases/1.2.3.md");
    return "curated";
  }), "curated");
  const missing = async () => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); };
  assert.equal(await releaseNotes("v1.2.3", "generated", missing), "generated");
  await assert.rejects(releaseNotes("v1.2.3", "", missing), /missing/);
  await assert.rejects(releaseNotes("v1.2.3", "generated", async () => ""), /empty/);
  await assert.rejects(releaseNotes("v1.2.3", "generated", async () => { throw new Error("permission denied"); }), /permission denied/);
});

test("Windows consumption selects only the exact asset of the matching draft", () => {
  const asset = { name: "kerberos-win32-x64.node", url: "https://api.github.com/repos/example/tool/releases/assets/7" };
  const release = { tag_name: "v1.2.3", draft: true, assets: [asset, { name: "other", url: "wrong" }] };
  assert.equal(windowsAsset(release, "v1.2.3"), asset.url);
  assert.throws(() => windowsAsset(release, "v1.2.4"), /matching draft/);
  assert.throws(() => windowsAsset({ ...release, draft: false }, "v1.2.3"), /matching draft/);
  assert.throws(() => windowsAsset({ ...release, assets: [] }, "v1.2.3"), /exactly one/);
  assert.throws(() => windowsAsset({ ...release, assets: [asset, asset] }, "v1.2.3"), /exactly one/);
});

test("publication resumes only when registry bytes match the tested tarball", async () => {
  const bytes = Buffer.from("tested archive");
  const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
  let published = 0;
  const publish = async () => { published++; };
  assert.equal(await publishPackage(bytes, "example", "1.2.3", async () => undefined, publish), "published");
  assert.equal(published, 1);
  assert.equal(await publishPackage(bytes, "example", "1.2.3", async () => ({ dist: { integrity } }), publish), "already-published");
  assert.equal(published, 1);
  await assert.rejects(publishPackage(bytes, "example", "1.2.3", async () => ({ dist: { integrity: "different" } }), publish), /differs/);
  await assert.rejects(publishPackage(bytes, "example", "1.2.3", async () => { throw new Error("registry offline"); }, publish), /registry offline/);
  assert.equal(published, 1);
});

function digest(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

test("release assembly keeps the bundled prebuild checksum and manifest aligned", async () => {
  const fixture = resolve(`.tmp/native-release-${randomUUID()}`);
  const release = join(fixture, "release");
  const prebuilds = join(fixture, "prebuilds");
  const linuxBytes = Buffer.from("replacement linux native artifact");
  const windowsBytes = Buffer.from("replacement windows native artifact");

  try {
    await mkdir(join(prebuilds, "linux-glibc-x64"), { recursive: true });
    await mkdir(release, { recursive: true });
    await writeFile(join(fixture, "package.json"), `${JSON.stringify({ version: "1.2.3" })}\n`);
    await writeFile(join(prebuilds, "manifest.json"), `${JSON.stringify({ version: 1, release: { repository: "example/ldap-axi" }, artifacts: {} })}\n`);
    await writeFile(join(prebuilds, "linux-glibc-x64", "kerberos.node"), "stale binary");
    await writeFile(join(prebuilds, "linux-glibc-x64", "kerberos.node.sha256"), `${"0".repeat(64)}  kerberos-linux-glibc-x64.node\n`);

    for (const [target, bytes] of [["linux-glibc-x64", linuxBytes], ["win32-x64", windowsBytes]] as const) {
      const asset = `kerberos-${target}.node`;
      await writeFile(join(release, asset), bytes);
      await writeFile(join(release, `${asset}.sha256`), `${digest(bytes)}  ${asset}\n`);
    }

    execFileSync(process.execPath, [resolve("scripts/assemble-native-release.mjs"), release], {
      cwd: fixture,
      env: { ...process.env, GITHUB_REF_NAME: "v1.2.3" },
      stdio: "pipe",
    });

    const bundled = await readFile(join(prebuilds, "linux-glibc-x64", "kerberos.node"));
    const checksum = (await readFile(join(prebuilds, "linux-glibc-x64", "kerberos.node.sha256"), "utf8")).trim().split(/\s+/, 1)[0];
    const manifest = JSON.parse(await readFile(join(prebuilds, "manifest.json"), "utf8")) as {
      artifacts: Record<string, { sha256: string }>;
    };
    const bundledDigest = digest(bundled);

    assert.deepEqual(bundled, linuxBytes);
    assert.equal(checksum, bundledDigest);
    assert.equal(manifest.artifacts["linux-glibc-x64"].sha256, bundledDigest);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

for (const invalid of ["version", "checksum"] as const) {
  test(`release assembly refuses a mismatched ${invalid}`, async () => {
    const fixture = resolve(`.tmp/native-release-${randomUUID()}`);
    const release = join(fixture, "release");
    try {
      await mkdir(join(fixture, "prebuilds"), { recursive: true });
      await mkdir(release, { recursive: true });
      await writeFile(join(fixture, "package.json"), JSON.stringify({ version: "1.2.3" }));
      await writeFile(join(fixture, "prebuilds/manifest.json"), JSON.stringify({ version: 1, artifacts: {} }));
      await writeFile(join(release, "kerberos-linux-glibc-x64.node"), "synthetic binary");
      await writeFile(join(release, "kerberos-linux-glibc-x64.node.sha256"), "0".repeat(64));
      assert.throws(() => execFileSync(process.execPath, [resolve("scripts/assemble-native-release.mjs"), release], {
        cwd: fixture,
        env: { ...process.env, GITHUB_REF_NAME: invalid === "version" ? "v1.2.4" : "v1.2.3" },
        stdio: "pipe",
      }), invalid === "version" ? /does not match package version/ : /does not match its build-job checksum/);
      assert.deepEqual(JSON.parse(await readFile(join(fixture, "prebuilds/manifest.json"), "utf8")).artifacts, {});
    } finally {
      await rm(fixture, { recursive: true, force: true });
    }
  });
}
