import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = fileURLToPath(new URL("..", import.meta.url));
const output = join(root, "build", "Release", "kerberos.node");
const debugOutput = join(root, "build", "Debug", "kerberos.node");
const statusPath = join(root, "build", "native-status.json");
const require = createRequire(import.meta.url);
const nativeResolution = require(join(root, "scripts", "native-resolution.cjs"));
const { mode, target } = nativeResolution.selection();
const packageManifest = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const MAX_PREBUILD_BYTES = 8 * 1024 * 1024;
const PREBUILD_DOWNLOAD_TIMEOUT_MS = 30_000;

async function finish(result, detail) {
  await mkdir(dirname(statusPath), { recursive: true });
  await writeFile(statusPath, `${JSON.stringify({ target: target ?? "unsupported", mode, result, detail }, null, 2)}\n`);
}

async function cleanOutputs() {
  await Promise.all([rm(output, { force: true }), rm(debugOutput, { force: true })]);
}

function verifyAddon() {
  const verification = spawnSync(process.execPath, [
    "-e",
    `const addon = require(process.argv[1]);
if (
  addon.definedNapiVersion?.() !== "9" ||
  typeof addon.KerberosClient?.prototype?.wrapWithResult !== "function" ||
  typeof addon.KerberosClient?.prototype?.unwrapWithResult !== "function" ||
  typeof addon.KerberosClient?.prototype?.wrapSizeLimit !== "function"
) {
  process.exitCode = 1;
}`,
    output,
  ], { stdio: "pipe" });
  if (verification.status !== 0) {
    const outputText = `${verification.stdout.toString()}${verification.stderr.toString()}`;
    if (/ERR_DLOPEN_FAILED|Opening library .* failed: .*cannot open shared object file|The specified module could not be found/i.test(outputText)) return;
    throw new Error("native patch capability is missing");
  }
}

async function installPrebuild() {
  const bundled = nativeResolution.verifyBundledPrebuild(root, target);
  let manifest;
  let entry;
  let bytes;
  if (bundled) {
    ({ manifest, entry, bytes } = bundled);
  } else {
    ({ manifest, entry } = nativeResolution.readEntry(root, target));
    if (!entry) return false;
  }
  if (!bundled) {
    if (typeof manifest.release?.repository !== "string") throw new Error("prebuild release is malformed");
    const base = `https://github.com/${manifest.release.repository}/releases/download/v${packageManifest.version}`;
    const url = process.env.LDAP_AXI_NATIVE_RELEASE_ASSET_URL ?? `${base}/${entry.asset}`;
    const token = process.env.LDAP_AXI_NATIVE_RELEASE_TOKEN;
    const response = await fetch(url, {
      ...(token ? { headers: { Accept: "application/octet-stream", Authorization: `Bearer ${token}` } } : {}),
      signal: AbortSignal.timeout(PREBUILD_DOWNLOAD_TIMEOUT_MS),
    });
    if (!response.ok || !response.body) throw new Error("prebuild download failed");
    const contentLength = Number(response.headers.get("content-length"));
    if (Number.isFinite(contentLength) && contentLength > MAX_PREBUILD_BYTES) throw new Error("prebuild download exceeded size limit");
    const chunks = [];
    let received = 0;
    for await (const chunk of response.body) {
      received += chunk.byteLength;
      if (received > MAX_PREBUILD_BYTES) throw new Error("prebuild download exceeded size limit");
      chunks.push(Buffer.from(chunk));
    }
    bytes = Buffer.concat(chunks, received);
  }

  if (createHash("sha256").update(bytes).digest("hex") !== entry.sha256) throw new Error("prebuild checksum mismatch");
  await mkdir(dirname(output), { recursive: true });
  const temporary = `${output}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, bytes, { flag: "wx" });
    await rename(temporary, output);
    verifyAddon();
    return true;
  } finally {
    await rm(temporary, { force: true });
  }
}

async function buildFromSource() {
  const nodeGyp = require.resolve("node-gyp/bin/node-gyp.js");
  const args = [nodeGyp, "rebuild"];
  if (process.env.LDAP_AXI_KERBEROS_INCLUDE_DIR) args.push(`--kerberos_include_dir=${process.env.LDAP_AXI_KERBEROS_INCLUDE_DIR}`);
  const result = spawnSync(process.execPath, args, { cwd: root, stdio: "inherit" });
  if (result.status !== 0) return false;
  verifyAddon();
  return true;
}

try {
  if (!nativeResolution.validModes.has(mode)) {
    await cleanOutputs();
    await finish("unavailable", "invalid native mode");
  } else {
    await cleanOutputs();
    if (!target) {
      await finish("unavailable", "unsupported platform");
    } else if (mode === "off") {
      await finish("unavailable", "disabled");
    } else {
      let installed = false;
      let prebuildFailure;
      if (mode !== "source") {
        try {
          installed = await installPrebuild();
        } catch (error) {
          await rm(output, { force: true });
          prebuildFailure = error;
        }
      }

      if (installed) {
        await finish("installed", "verified prebuild");
      } else if (mode === "prebuild") {
        const detail = prebuildFailure instanceof Error && [
          "prebuild checksum mismatch",
          "prebuild manifest entry is malformed",
        ].includes(prebuildFailure.message)
          ? prebuildFailure.message
          : "verified prebuild not available";
        await finish("unavailable", detail);
      } else if (await buildFromSource()) {
        await finish("installed", "source build");
      } else {
        await rm(output, { force: true });
        await finish("unavailable", "source build failed");
      }
    }
  }
} catch {
  await cleanOutputs();
  await finish("unavailable", "native installation failed");
}
