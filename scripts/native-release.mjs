import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFile, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const nativeAssets = ["kerberos-linux-glibc-x64.node", "kerberos-win32-x64.node"];
const stagedAssets = nativeAssets.flatMap(name => [name, `${name}.sha256`]);
const run = (command, args) => execFileSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] }).trim();

export function validateTag(tag) {
  if (!/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(tag ?? "")) throw new Error("a version tag is required");
  return tag;
}

export async function releaseNotes(tag, generated, read = readFile) {
  try {
    const notes = await read(`docs/releases/${validateTag(tag).slice(1)}.md`, "utf8");
    if (!notes.trim()) throw new Error("release notes must not be empty");
    return notes;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    if (!generated?.trim()) throw new Error("generated release notes are missing");
    return generated;
  }
}

export function releasePlan(tag, sha, expected, eventSha, release, eventName) {
  validateTag(tag);
  if (!/^[a-f0-9]{40}$/.test(sha) || (expected && expected !== sha)) throw new Error("tag does not match the release commit");
  if (eventName !== "workflow_dispatch" && eventSha !== sha) throw new Error("workflow event source commit must match the release tag commit");
  return { tag, sha, active: !release || release.draft };
}

export function windowsAsset(release, tag) {
  if (release?.tag_name !== tag || !release.draft) throw new Error("matching draft release is required");
  const assets = release.assets.filter(asset => asset.name === "kerberos-win32-x64.node");
  if (assets.length !== 1) throw new Error("exactly one staged Windows prebuild is required");
  return assets[0].url;
}

export function stagedArchive(release) {
  if (release && !release.draft) throw new Error("release is already public");
  const archives = release?.assets.filter(asset => asset.name.endsWith(".tgz")) ?? [];
  if (archives.length > 1) throw new Error("ambiguous staged package");
  return archives.length === 1 && stagedAssets.every(name => release.assets.some(asset => asset.name === name))
    ? archives[0].name : undefined;
}

export async function publishPackage(bytes, name, version, registry, publish) {
  const metadata = await registry(name, version);
  const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
  if (metadata) {
    if (metadata.dist?.integrity !== integrity) throw new Error("published package differs from the tested archive");
    return "already-published";
  }
  await publish();
  return "published";
}

async function main() {
  const command = process.argv[2];
  const repository = process.env.GITHUB_REPOSITORY;
  const tag = command === "publish" ? undefined : validateTag(process.env.RELEASE_TAG);
  const api = (path, args = []) => JSON.parse(run("gh", ["api", `repos/${repository}/${path}`, ...args]));
  const output = async values => {
    for (const [key, value] of Object.entries(values)) await appendFile(process.env.GITHUB_OUTPUT, `${key}=${value}\n`);
  };
  const getRelease = () => api("releases", ["--paginate", "--slurp"]).flat().find(release => release.tag_name === tag);

  if (command === "plan") {
    let object = api(`git/ref/tags/${tag}`).object;
    while (object.type === "tag") object = api(`git/tags/${object.sha}`).object;
    if (object.type !== "commit") throw new Error("release tag must resolve to a commit");
    const plan = releasePlan(tag, object.sha, process.env.RELEASE_SHA, process.env.GITHUB_SHA, getRelease(), process.env.GITHUB_EVENT_NAME);
    const pkg = api(`contents/package.json?ref=${plan.sha}`);
    if (JSON.parse(Buffer.from(pkg.content, "base64").toString()).version !== tag.slice(1)) throw new Error("tag does not match package version");
    await output(plan);
  } else if (command === "resume") {
    const release = getRelease();
    const reused = Boolean(stagedArchive(release));
    if (reused) {
      await mkdir("package", { recursive: true });
      run("gh", ["release", "download", tag, "--repo", repository, "--pattern", "*.tgz", "--dir", "package", "--clobber"]);
      for (const name of stagedAssets) run("gh", ["release", "download", tag, "--repo", repository, "--pattern", name, "--dir", "release", "--clobber"]);
    }
    await output({ reused });
  } else if (command === "stage") {
    const release = getRelease();
    if (release && !release.draft) throw new Error("release is already public");
    const generated = release?.body || api("releases/generate-notes", ["-f", `tag_name=${tag}`, "-f", `target_commitish=${process.env.RELEASE_SHA}`]).body;
    await writeFile("release-notes.md", await releaseNotes(tag, generated));
    if (!release) run("gh", ["release", "create", tag, "--repo", repository, "--draft", "--verify-tag", "--title", tag, "--notes-file", "release-notes.md"]);
    else run("gh", ["release", "edit", tag, "--repo", repository, "--notes-file", "release-notes.md"]);
    const archives = (await readdir("package")).filter(name => name.endsWith(".tgz"));
    if (archives.length !== 1) throw new Error("exactly one package archive is required");
    run("gh", ["release", "upload", tag, "--repo", repository, ...stagedAssets.map(name => `release/${name}`), `package/${archives[0]}`, "--clobber"]);
  } else if (command === "windows-asset") {
    console.log(windowsAsset(getRelease(), tag));
  } else if (command === "publish") {
    const archives = (await readdir("package")).filter(name => name.endsWith(".tgz"));
    if (archives.length !== 1) throw new Error("exactly one tested package archive is required");
    const archive = `./package/${archives[0]}`;
    const pkg = JSON.parse(await readFile("package.json", "utf8"));
    await publishPackage(await readFile(archive), pkg.name, pkg.version, async (name, version) => {
      const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}/${version}`);
      if (response.status === 404) return undefined;
      if (!response.ok) throw new Error(`registry lookup failed: ${response.status}`);
      return response.json();
    }, () => run("npm", ["publish", archive, "--access", "public", "--provenance"]));
  } else throw new Error("unknown release operation");
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
