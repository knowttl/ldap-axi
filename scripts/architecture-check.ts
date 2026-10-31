import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

async function files(directory: string): Promise<string[]> { const result: string[] = []; for (const entry of await readdir(directory, { withFileTypes: true })) { const path = join(directory, entry.name); if (entry.isDirectory()) result.push(...await files(path)); else if (path.endsWith(".ts")) result.push(path); } return result; }
const sources = await files("src");
for (const file of sources) {
  const body = await readFile(file, "utf8");
  if (/node:child_process/.test(body)) throw new Error(`subprocess import is forbidden: ${file}`);
  const normalized = file.replace(/\\/g, "/");
  if (normalized !== "src/directory/client.ts" && /from\s+["'](?:ldapts|node:(?:net|tls|dns))["']/.test(body)) throw new Error(`network import outside sealed client: ${file}`);
}
const lock = JSON.parse(await readFile("package-lock.json", "utf8"));
const rootPackage = lock.packages?.[""];
const providerManifest = JSON.parse(await readFile("vendor/kerberos/package.json", "utf8"));
const upstream = await readFile("vendor/kerberos/UPSTREAM.md", "utf8");
const declared = {
  version: /`kerberos@([0-9]+\.[0-9]+\.[0-9]+)`/.exec(upstream)?.[1],
  tag: /tag `v([0-9]+\.[0-9]+\.[0-9]+)`/.exec(upstream)?.[1],
  integrity: /integrity is `(sha512-[A-Za-z0-9+/]+={0,2})`/.exec(upstream)?.[1],
};
if (declared.version !== providerManifest.version || declared.tag !== providerManifest.version || !declared.integrity || !upstream.includes("https://github.com/mongodb-js/kerberos")) throw new Error("vendor/kerberos/UPSTREAM.md no longer records the vendored provider's upstream version, tag, repository, and tarball integrity");
if (rootPackage?.optionalDependencies?.["node-addon-api"] !== "8.9.2" || rootPackage?.optionalDependencies?.["node-gyp"] !== "12.4.0" || rootPackage.optionalDependencies?.kerberos || lock.packages?.["node_modules/kerberos"]) throw new Error("the native provider must be owned and built by the ldap-axi package root");
if (providerManifest.name !== "kerberos" || providerManifest.version !== "7.0.0" || providerManifest.ldapAxiPatch?.level !== 1 || providerManifest.ldapAxiPatch?.entry !== "lib/ldap-axi-patch.js" || providerManifest.scripts || providerManifest.dependencies) throw new Error("vendored kerberos must remain inert source owned by the package root");
const prebuildManifest = JSON.parse(await readFile("prebuilds/manifest.json", "utf8"));
if (prebuildManifest.version !== 1 || prebuildManifest.release?.repository !== "knowttl/ldap-axi" || !prebuildManifest.artifacts || Array.isArray(prebuildManifest.artifacts)) throw new Error("native prebuild manifest is malformed");
for (const [target, artifact] of Object.entries(prebuildManifest.artifacts as Record<string, { napi: number; patchLevel: number; sha256: string; bundled: boolean; asset: string }>)) {
  if (
    !new Set(["linux-glibc-x64", "win32-x64"]).has(target) ||
    artifact?.napi !== 9 ||
    artifact?.patchLevel !== 1 ||
    !/^[a-f0-9]{64}$/.test(artifact.sha256) ||
    typeof artifact.bundled !== "boolean" ||
    artifact.asset !== `kerberos-${target}.node`
  ) throw new Error(`unsupported native prebuild metadata: ${target}`);
  if (artifact.bundled) {
    const bytes = await readFile(join("prebuilds", target, "kerberos.node"));
    if (createHash("sha256").update(bytes).digest("hex") !== artifact.sha256) throw new Error(`native prebuild checksum mismatch: ${target}`);
  }
}
try {
  const workflows = await readdir(".github/workflows");
  const authorized = new Set(["native-prebuilds.yml", "local-directory.yml", "release-please.yml"]);
  if (workflows.some(file => !authorized.has(file))) throw new Error("only the native prebuild, local-directory, and release PR workflows are authorized");
  // node --test exits 0 when --test-name-pattern matches nothing, so a stale name turns a required check into a vacuous pass.
  const titles = new Set();
  for (const file of await files("test")) for (const [, title] of (await readFile(file, "utf8")).matchAll(/^test\("([^"]+)"/gm)) titles.add(title);
  for (const file of workflows) for (const [, pattern] of (await readFile(join(".github/workflows", file), "utf8")).matchAll(/--test-name-pattern="([^"]+)"/g)) {
    if (!titles.has(pattern)) throw new Error(`workflow ${file} selects a test that does not exist: ${pattern}`);
  }
} catch (error) {
  if ((error as NodeJS.ErrnoException)?.code !== "ENOENT") throw error;
}
