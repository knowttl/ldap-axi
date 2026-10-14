import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import test from "node:test";

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
