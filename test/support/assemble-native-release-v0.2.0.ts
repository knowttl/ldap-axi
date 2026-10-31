import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

async function replaceFile(path: string, bytes: string | Uint8Array) {
  const temporaryPath = join(dirname(path), `.${basename(path)}.${randomUUID()}.tmp`);
  try {
    await writeFile(temporaryPath, bytes);
    await rename(temporaryPath, path);
  } finally {
    await rm(temporaryPath, { force: true });
  }
}

const releaseDirectory = resolve(process.argv[2] ?? "release");
const manifestPath = resolve("prebuilds/manifest.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const packageManifest = JSON.parse(await readFile(resolve("package.json"), "utf8"));
if (process.env.GITHUB_REF_NAME && process.env.GITHUB_REF_NAME !== `v${packageManifest.version}`) {
  throw new Error(`tag ${process.env.GITHUB_REF_NAME} does not match package version ${packageManifest.version}`);
}
const targets = ["linux-glibc-x64", "win32-x64"];
const artifacts: Record<string, { napi: number; patchLevel: number; sha256: string; bundled: boolean; asset: string }> = {};

for (const target of targets) {
  const asset = `kerberos-${target}.node`;
  const bytes = await readFile(join(releaseDirectory, asset));
  const digest = createHash("sha256").update(bytes).digest("hex");
  const checksum = (await readFile(join(releaseDirectory, `${asset}.sha256`), "utf8")).trim().split(/\s+/, 1)[0];
  if (checksum !== digest) throw new Error(`${asset} does not match its build-job checksum`);
  artifacts[target] = {
    napi: 9,
    patchLevel: 1,
    sha256: digest,
    bundled: target === "linux-glibc-x64",
    asset,
  };
}

const linuxArtifact = artifacts["linux-glibc-x64"];
const linuxPrebuild = resolve("prebuilds/linux-glibc-x64/kerberos.node");
await mkdir(dirname(linuxPrebuild), { recursive: true });
await replaceFile(linuxPrebuild, await readFile(join(releaseDirectory, linuxArtifact.asset)));
await replaceFile(`${linuxPrebuild}.sha256`, `${linuxArtifact.sha256}  ${linuxArtifact.asset}\n`);
await rm(resolve("prebuilds/win32-x64"), { recursive: true, force: true });
await writeFile(manifestPath, `${JSON.stringify({ version: 1, release: manifest.release, artifacts }, null, 2)}\n`);
console.log(`Pinned ${targets.map(target => `${basename(artifacts[target].asset)}:${artifacts[target].sha256}`).join(" ")}`);
