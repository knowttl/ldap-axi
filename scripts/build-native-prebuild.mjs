import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const target = process.argv[2];
const supported = new Set(["linux-glibc-x64", "win32-x64"]);
if (!supported.has(target)) throw new Error("target must be linux-glibc-x64 or win32-x64");
const current = process.platform === "linux" && process.arch === "x64" && process.report.getReport().header.glibcVersionRuntime
  ? "linux-glibc-x64"
  : process.platform === "win32" && process.arch === "x64"
    ? "win32-x64"
    : "unsupported";
if (current !== target) throw new Error(`prebuild ${target} must be produced on that target`);

process.env.LDAP_AXI_NATIVE_MODE = "source";
await import("./install-native.mjs");
const status = JSON.parse(await readFile("build/native-status.json", "utf8"));
if (status.result !== "installed" || status.detail !== "source build") throw new Error("source build did not produce an addon");
const bytes = await readFile("build/Release/kerberos.node");
const destination = join("prebuilds", target, "kerberos.node");
await mkdir(dirname(destination), { recursive: true });
await copyFile("build/Release/kerberos.node", destination);
const digest = createHash("sha256").update(bytes).digest("hex");
await writeFile(`${destination}.sha256`, `${digest}  kerberos-${target}.node\n`);
const manifestPath = "prebuilds/manifest.json";
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
manifest.artifacts[target] = {
  napi: 9,
  patchLevel: 1,
  sha256: digest,
  bundled: true,
  asset: `kerberos-${target}.node`,
};
const ordered = Object.fromEntries(Object.entries(manifest.artifacts).sort(([a], [b]) => a.localeCompare(b)));
await writeFile(manifestPath, `${JSON.stringify({ version: 1, release: manifest.release, artifacts: ordered }, null, 2)}\n`);
