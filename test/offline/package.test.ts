import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";

const packageManifest = JSON.parse(await readFile(resolve("package.json"), "utf8")) as { name: string; version: string };
const packedName = `${packageManifest.name.replace(/^@/, "").replace(/\//g, "-")}-${packageManifest.version}.tgz`;
const archive = resolve(process.env.LDAP_AXI_PACKAGE_ARCHIVE ?? `.tmp/package-test/${packedName}`);
const KERBEROS_LIBRARIES = ["libgssapi_krb5.so.2", "libkrb5.so.3", "libk5crypto.so.3", "libcom_err.so.2", "libkrb5support.so.0", "libkeyutils.so.1"];
const LIBRARY_DIRECTORIES = ["/usr/lib/x86_64-linux-gnu", "/usr/lib64", "/lib/x86_64-linux-gnu"];

/**
 * Links only the Kerberos/GSS runtime libraries into a shim directory for the packaged consumer's
 * loader path. Prepending a whole system library directory instead makes a Nix-provided Node load the
 * system libuv and abort with `undefined symbol: uv_tcp_keepalive_ex` before any ldap-axi code runs.
 */
function kerberosLibraryEnvironment(): NodeJS.ProcessEnv {
  if (process.platform !== "linux") return {};
  const shim = resolve(".tmp/package-test/kerberos-libraries");
  mkdirSync(shim, { recursive: true });
  let linked = 0;
  for (const library of KERBEROS_LIBRARIES) {
    const source = LIBRARY_DIRECTORIES.map(directory => join(directory, library)).find(candidate => existsSync(candidate));
    if (!source) continue;
    if (!existsSync(join(shim, library))) symlinkSync(source, join(shim, library));
    linked += 1;
  }
  return linked === 0 ? {} : { LD_LIBRARY_PATH: [process.env.LD_LIBRARY_PATH, shim].filter(Boolean).join(":") };
}

const nativeEnvironment = kerberosLibraryEnvironment();
const sourceBuildAvailable = process.platform === "win32" || existsSync("/usr/include/gssapi/gssapi.h");

function install(name: string, environment: NodeJS.ProcessEnv, assertNoSource = false): string {
  const directory = resolve(`.tmp/package-test/${name}`);
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const options = {
    cwd: directory,
    env: { ...process.env, ...environment },
    shell: process.platform === "win32",
    stdio: "pipe" as const,
  };
  execFileSync(npm, ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", archive], options);
  const output = execFileSync(npm, ["ci", "--foreground-scripts", "--no-audit", "--no-fund"], options).toString();
  if (assertNoSource) assert.doesNotMatch(output, /node-gyp|source build/i);
  return resolve(directory, "node_modules", packageManifest.name);
}

async function status(packageRoot: string): Promise<{ target: string; mode: string; result: string; detail: string }> {
  return JSON.parse(await readFile(resolve(packageRoot, "build/native-status.json"), "utf8")) as {
    target: string;
    mode: string;
    result: string;
    detail: string;
  };
}

function runInstaller(packageRoot: string, environment: NodeJS.ProcessEnv): void {
  execFileSync(process.execPath, [resolve(packageRoot, "scripts/install-native.mjs")], {
    cwd: packageRoot,
    env: { ...process.env, ...nativeEnvironment, ...environment },
    stdio: "pipe",
  });
}

async function oversizedServer(): Promise<{ url: string; close: () => void }> {
  const child = spawn(process.execPath, ["-e", `
    const http = require("node:http");
    const server = http.createServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/octet-stream" });
      const chunk = Buffer.alloc(64 * 1024);
      for (let sent = 0; sent <= 8 * 1024 * 1024; sent += chunk.length) response.write(chunk);
      response.end();
    });
    server.listen(0, "127.0.0.1", () => process.stdout.write(String(server.address().port) + "\\n"));
  `], { stdio: ["ignore", "pipe", "inherit"] });
  const port = await new Promise<number>((resolvePort, reject) => {
    child.once("error", reject);
    child.stdout!.once("data", value => resolvePort(Number(String(value).trim())));
  });
  return { url: `http://127.0.0.1:${port}/kerberos.node`, close: () => child.kill() };
}

function verifyCli(packageRoot: string): void {
  const schema = JSON.parse(readFileSync(resolve(packageRoot, "axi-credential.schema.json"), "utf8"));
  assert.equal(schema.properties.bindPassword["x-secret"], true);
  const executable = resolve(packageRoot, "../..", ".bin", process.platform === "win32" ? "ldap-axi.cmd" : "ldap-axi");
  const output = execFileSync(executable, ["--help"], {
    encoding: "utf8",
    shell: process.platform === "win32",
  });
  assert.match(output, /^Read Active Directory and LDAPv3 directories\./);
  const guard = resolve(packageRoot, "version-guard.mjs");
  writeFileSync(guard, `
    import { registerHooks, syncBuiltinESMExports, createRequire } from "node:module";
    import net from "node:net";
    import tls from "node:tls";
    const forbidden = () => { process.stderr.write("Version attempted network/native authentication work\\n"); throw new Error("forbidden version side effect"); };
    net.Socket.prototype.connect = forbidden;
    tls.connect = forbidden;
    createRequire(import.meta.url)("node:module")._extensions[".node"] = forbidden;
    syncBuiltinESMExports();
    registerHooks({ resolve(specifier, context, next) {
      const resolved = next(specifier, context);
      if (!resolved.url.startsWith("node:") && !/\\/(cli|version)\\.js$/.test(resolved.url)) {
        throw new Error("Version loaded the command graph: " + resolved.url);
      }
      return resolved;
    } });
  `);
  for (const flag of ["--version", "-v", "-V"]) {
    const result = spawnSync(executable, [flag], {
      encoding: "utf8", shell: process.platform === "win32",
      env: { ...process.env, NODE_OPTIONS: `--import=${pathToFileURL(guard).href}`, LDAP_AXI_URL: "invalid-url", LDAP_AXI_AUTH: "invalid-auth", LDAP_AXI_CONFIG_FILE: "deprecated-must-not-be-read" },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, `${packageManifest.version}\n`);
    assert.equal(result.stderr, "");
  }
  const floor: number[] = [];
  const version: number[] = [];
  for (let trial = 0; trial < 3; trial++) {
    let started = performance.now();
    execFileSync(process.execPath, ["-e", "console.log(1)"], { stdio: "pipe" });
    floor.push(performance.now() - started);
    started = performance.now();
    execFileSync(process.execPath, [resolve(packageRoot, "dist/src/cli.js"), "--version"], { stdio: "pipe" });
    version.push(performance.now() - started);
  }
  assert.ok(version.toSorted((a, b) => a - b)[1] < floor.toSorted((a, b) => a - b)[1] * 4, "version startup must stay close to the same-machine Node startup floor");
  for (const argv of [["-x"], ["--offline", "extra"], ["entry", "search", "-x"]]) {
    const result = spawnSync(executable, argv, {
      encoding: "utf8", shell: process.platform === "win32",
      env: { ...process.env, LDAP_AXI_URL: "invalid-url", LDAP_AXI_AUTH: "invalid-auth" },
    });
    assert.equal(result.status, 2, result.stderr);
    assert.match(result.stdout, /VALIDATION_ERROR/);
    assert.match(result.stdout, /valid flags/);
    assert.match(result.stdout, new RegExp(argv.at(-1)!));
  }
  for (const argv of [["user", "list", "--help"], ["auth", "status", "--help"], ["setup", "--help"]]) {
    const output = execFileSync(executable, argv, { encoding: "utf8", shell: process.platform === "win32" });
    assert.match(output, /--/);
    assert.match(output, /Examples:/);
  }
  const agentRoot = resolve(packageRoot, "isolated-agent-home");
  const environment = {
    ...process.env,
    LDAP_AXI_CONFIG: resolve(agentRoot, "missing.json"), LDAP_AXI_CREDENTIALS_FILE: resolve(agentRoot, "missing.env"),
    LDAP_AXI_URL: "ldaps://directory.example.test", LDAP_AXI_AUTH: "auto", LDAP_AXI_BIND_DN: "cn=synthetic", LDAP_AXI_BIND_PASSWORD: "packaged-home-canary",
    CLAUDE_CONFIG_DIR: resolve(agentRoot, "claude"), CODEX_HOME: resolve(agentRoot, "codex"), OPENCODE_CONFIG_DIR: resolve(agentRoot, "opencode"),
  };
  const optionGuard = resolve(packageRoot, "option-value-guard.mjs");
  writeFileSync(optionGuard, `
    import { syncBuiltinESMExports } from "node:module";
    import net from "node:net";
    import tls from "node:tls";
    const forbidden = () => { process.stderr.write("Invalid option attempted network/native authentication work\\n"); throw new Error("forbidden option side effect"); };
    net.Socket.prototype.connect = forbidden;
    tls.connect = forbidden;
    process.dlopen = forbidden;
    syncBuiltinESMExports();
  `);
  for (const option of ["base", "profile"]) {
    const result = spawnSync(executable, ["--auth", "simple", `--${option}`, "-x"], {
      encoding: "utf8", shell: process.platform === "win32",
      env: { ...environment, NODE_OPTIONS: `--import=${pathToFileURL(optionGuard).href}` },
    });
    assert.equal(result.status, 2, result.stderr);
    assert.match(result.stdout, /VALIDATION_ERROR/);
    assert.ok(result.stdout.includes(`--${option} requires a value`), result.stdout);
    assert.equal(result.stderr, "");
  }
  const inlineBase = execFileSync(executable, ["--auth", "simple", "--offline", "--base=-x"], {
    encoding: "utf8", shell: process.platform === "win32", env: environment,
  });
  assert.match(inlineBase, /connection: offline/);
  for (const app of ["claude", "codex", "opencode"]) {
    const args = ["setup", "--app", app, "--skill", "--hook"];
    execFileSync(executable, args, { env: environment, shell: process.platform === "win32", stdio: "pipe" });
    execFileSync(executable, [...args, "--check"], { env: environment, shell: process.platform === "win32", stdio: "pipe" });
    assert.equal(readFileSync(resolve(agentRoot, app, "skills/ldap-axi/SKILL.md"), "utf8").startsWith(readFileSync(resolve(packageRoot, "skills/ldap-axi/SKILL.md"), "utf8")), true);
  }
  for (const flag of ["--offline", "--session-start"]) {
    const output = execFileSync(executable, [flag], { env: environment, shell: process.platform === "win32", encoding: "utf8" });
    assert.match(output, /connection: offline/);
    assert.doesNotMatch(output, /packaged-home-canary/);
  }
}

function verifyNativeProvider(packageRoot: string): void {
  const providerManifestPath = resolve(packageRoot, "vendor/kerberos/package.json");
  const kerberosConfig = resolve(packageRoot, "test-krb5.conf");
  writeFileSync(kerberosConfig, "[libdefaults]\n default_realm = LDAP_AXI.TEST\n dns_lookup_realm = false\n dns_lookup_kdc = false\n");
  const nativeCheck = `
    const assert = require("node:assert/strict");
    const provider = require("node:module").createRequire(process.argv[1])("./lib/index.js");
    (async () => {
      assert.deepEqual(Object.keys(provider).sort(), [
        "GSS_C_CONF_FLAG",
        "GSS_C_INTEG_FLAG",
        "GSS_C_MUTUAL_FLAG",
        "GSS_C_SEQUENCE_FLAG",
        "GSS_MECH_OID_KRB5",
        "GSS_MECH_OID_SPNEGO",
        "LDAP_AXI_PATCH_LEVEL",
        "initializeClient",
      ]);
      assert.equal(provider.LDAP_AXI_PATCH_LEVEL, 1);
      await assert.rejects(provider.initializeClient("ldap@directory.example.test", { channelBindingData: Buffer.alloc(65537) }), RangeError);
      if (process.platform !== "win32") {
        const client = await provider.initializeClient("ldap@directory.example.test", {});
        assert.equal(typeof client.wrapWithResult, "function");
        assert.equal(typeof client.unwrapWithResult, "function");
        assert.equal(typeof client.wrapSizeLimit, "function");
        const selectionError = "GSSAPI security-layer offer is shorter than four bytes";
        for (const input of [Buffer.alloc(0), Buffer.from([0x01]), Buffer.from([0x00, 0xff, 0x01])]) {
          await assert.rejects(client.wrapWithResult(input.toString("base64"), { protect: false }), error => error instanceof Error && !error.message.includes(selectionError));
          await assert.rejects(client.wrap(input.toString("base64")), { message: selectionError });
        }
        await assert.rejects(client.step(""), error => {
          assert.equal(typeof error.gssMajor, "number");
          assert.equal(typeof error.gssMinor, "number");
          assert.ok((error.gssMajor & 0x00ff0000) === (7 << 16) || error.gssMinor === (-1765328189 >>> 0) || error.gssMinor === (-1765328243 >>> 0));
          return true;
        });
      }
    })().catch(error => { console.error(error); process.exitCode = 1; });
  `;
  execFileSync(process.execPath, ["-e", nativeCheck, providerManifestPath], {
    env: { ...process.env, ...nativeEnvironment, KRB5_CONFIG: kerberosConfig, KRB5CCNAME: `FILE:${resolve(packageRoot, "absent-ccache")}`, KRB5_CLIENT_KTNAME: resolve(packageRoot, "absent-client.keytab"), KRB5_KTNAME: resolve(packageRoot, "absent.keytab") },
    stdio: "pipe",
  });
}

function verifySupportedPackageBoundary(packageRoot: string): void {
  const boundaryCheck = `
    const assert = require("node:assert/strict");
    (async () => {
      const api = await import("@knowttl/ldap-axi");
      assert.deepEqual(Object.keys(api), ["openDirectory"]);
      assert.equal(typeof api.openDirectory, "function");
      for (const path of [
        "@knowttl/ldap-axi/dist/src/directory/auth.js",
        "@knowttl/ldap-axi/dist/src/directory/gssapi.js",
        "@knowttl/ldap-axi/dist/src/directory/protected-stream.js",
        "@knowttl/ldap-axi/vendor/kerberos/lib/index.js",
      ]) {
        await assert.rejects(import(path), error => error && error.code === "ERR_PACKAGE_PATH_NOT_EXPORTED");
      }
    })().catch(error => { console.error(error); process.exitCode = 1; });
  `;
  execFileSync(process.execPath, ["-e", boundaryCheck], {
    cwd: resolve(packageRoot, "../../.."),
    env: { ...process.env, ...nativeEnvironment },
    stdio: "pipe",
  });
}

test("compiler-free packed consumers use the verified prebuild", async () => {
  const prebuilt = install("prebuild-consumer", {
    LDAP_AXI_NATIVE_MODE: "auto",
    NODE_GYP_FORCE_PYTHON: "ldap-axi-no-compiler",
  }, true);
  assert.deepEqual(await status(prebuilt), {
    target: process.platform === "win32" ? "win32-x64" : "linux-glibc-x64",
    mode: "auto",
    result: "installed",
    detail: "verified prebuild",
  });
  verifyCli(prebuilt);
  assert.equal(existsSync(resolve(prebuilt, "build/Release/kerberos.node")), true);
  verifyNativeProvider(prebuilt);
  verifySupportedPackageBoundary(prebuilt);
});

test("clean packed consumers build and load the forced-source provider", { skip: !sourceBuildAvailable && "Kerberos development headers are not installed" }, async () => {
  const source = install("source-consumer", { ...nativeEnvironment, LDAP_AXI_NATIVE_MODE: "source" });
  assert.deepEqual(await status(source), {
    target: process.platform === "win32" ? "win32-x64" : "linux-glibc-x64",
    mode: "source",
    result: "installed",
    detail: "source build",
  });
  verifyNativeProvider(source);
});

test("a replaced prebuild is refused before native execution and cleaned up", async () => {
  const packageRoot = install("replacement-consumer", { ...nativeEnvironment, LDAP_AXI_NATIVE_MODE: "prebuild" });
  const target = process.platform === "win32" ? "win32-x64" : "linux-glibc-x64";
  const prebuild = resolve(packageRoot, "prebuilds", target, "kerberos.node");
  const replacement = Buffer.concat([await readFile(prebuild), Buffer.from([0])]);
  await writeFile(prebuild, replacement);
  await writeFile(`${prebuild}.sha256`, `${createHash("sha256").update(replacement).digest("hex")}  kerberos-${target}.node\n`);

  const marker = resolve(packageRoot, "build/native-load-marker");
  const preload = resolve(packageRoot, "native-load-observer.cjs");
  await writeFile(preload, `
    const Module = require("node:module");
    const original = Module._extensions[".node"];
    Module._extensions[".node"] = function(module, filename) {
      require("node:fs").writeFileSync(${JSON.stringify(marker)}, filename);
      return original(module, filename);
    };
  `);
  runInstaller(packageRoot, {
    LDAP_AXI_NATIVE_MODE: "prebuild",
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ""} --require=${preload}`.trim(),
  });
  assert.deepEqual(await status(packageRoot), {
    target,
    mode: "prebuild",
    result: "unavailable",
    detail: "prebuild checksum mismatch",
  });
  assert.equal(existsSync(resolve(packageRoot, "build/Release/kerberos.node")), false);
  assert.equal(existsSync(marker), false);

  if (sourceBuildAvailable) {
    runInstaller(packageRoot, { LDAP_AXI_NATIVE_MODE: "auto" });
    assert.deepEqual(await status(packageRoot), {
      target,
      mode: "auto",
      result: "installed",
      detail: "source build",
    });
    verifyNativeProvider(packageRoot);
  }
});

test("an absent bundled prebuild is refused in prebuild mode", async () => {
  const packageRoot = install("missing-consumer", { ...nativeEnvironment, LDAP_AXI_NATIVE_MODE: "prebuild" });
  const target = process.platform === "win32" ? "win32-x64" : "linux-glibc-x64";
  await rm(resolve(packageRoot, "prebuilds", target, "kerberos.node"));
  runInstaller(packageRoot, { LDAP_AXI_NATIVE_MODE: "prebuild" });
  assert.deepEqual(await status(packageRoot), {
    target,
    mode: "prebuild",
    result: "unavailable",
    detail: "verified prebuild not available",
  });
  assert.equal(existsSync(resolve(packageRoot, "build/Release/kerberos.node")), false);
});

test("a malformed pinned manifest falls back only in auto mode", async () => {
  const packageRoot = install("malformed-consumer", { ...nativeEnvironment, LDAP_AXI_NATIVE_MODE: "prebuild" });
  const target = process.platform === "win32" ? "win32-x64" : "linux-glibc-x64";
  const manifestPath = resolve(packageRoot, "prebuilds/manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as { artifacts: Record<string, { sha256: string }> };
  manifest.artifacts[target].sha256 = "not-a-digest";
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

  runInstaller(packageRoot, { LDAP_AXI_NATIVE_MODE: "prebuild" });
  assert.deepEqual(await status(packageRoot), {
    target,
    mode: "prebuild",
    result: "unavailable",
    detail: "prebuild manifest entry is malformed",
  });
  assert.equal(existsSync(resolve(packageRoot, "build/Release/kerberos.node")), false);

  if (sourceBuildAvailable) {
    runInstaller(packageRoot, { LDAP_AXI_NATIVE_MODE: "auto" });
    assert.deepEqual(await status(packageRoot), {
      target,
      mode: "auto",
      result: "installed",
      detail: "source build",
    });
    verifyNativeProvider(packageRoot);
  }
});

test("auto mode source-builds after isolated capability verification fails", { skip: !sourceBuildAvailable && "Kerberos development headers are not installed" }, async () => {
  const packageRoot = install("capability-fallback-consumer", { ...nativeEnvironment, LDAP_AXI_NATIVE_MODE: "prebuild" });
  const target = process.platform === "win32" ? "win32-x64" : "linux-glibc-x64";
  const marker = resolve(packageRoot, "rejected-native-load");
  const preload = resolve(packageRoot, "reject-first-native-load.cjs");
  await writeFile(preload, `
    const fs = require("node:fs");
    const Module = require("node:module");
    const original = Module._extensions[".node"];
    Module._extensions[".node"] = function(module, filename) {
      if (!fs.existsSync(${JSON.stringify(marker)})) {
        fs.writeFileSync(${JSON.stringify(marker)}, filename);
        module.exports = { definedNapiVersion: () => "9", KerberosClient: class KerberosClient {} };
        return;
      }
      return original(module, filename);
    };
  `);

  runInstaller(packageRoot, {
    LDAP_AXI_NATIVE_MODE: "auto",
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ""} --require=${preload}`.trim(),
  });
  assert.deepEqual(await status(packageRoot), {
    target,
    mode: "auto",
    result: "installed",
    detail: "source build",
  });
  assert.equal(existsSync(marker), true);
  verifyNativeProvider(packageRoot);
});

test("oversized remote prebuilds are refused and cleaned up", async () => {
  const packageRoot = install("oversized-download-consumer", { ...nativeEnvironment, LDAP_AXI_NATIVE_MODE: "prebuild" });
  const target = process.platform === "win32" ? "win32-x64" : "linux-glibc-x64";
  const manifestPath = resolve(packageRoot, "prebuilds/manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as { artifacts: Record<string, { bundled: boolean }> };
  manifest.artifacts[target].bundled = false;
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  const server = await oversizedServer();
  try {
    runInstaller(packageRoot, { LDAP_AXI_NATIVE_MODE: "prebuild", LDAP_AXI_NATIVE_RELEASE_ASSET_URL: server.url });
  } finally {
    server.close();
  }
  assert.deepEqual(await status(packageRoot), {
    target,
    mode: "prebuild",
    result: "unavailable",
    detail: "verified prebuild not available",
  });
  assert.equal(existsSync(resolve(packageRoot, "build/Release/kerberos.node")), false);
});

test("invalid native modes fail closed and stale debug addons are never loaded", async () => {
  const packageRoot = install("invalid-mode-consumer", { ...nativeEnvironment, LDAP_AXI_NATIVE_MODE: "off" });
  const target = process.platform === "win32" ? "win32-x64" : "linux-glibc-x64";
  const debugAddon = resolve(packageRoot, "build/Debug/kerberos.node");
  await mkdir(resolve(packageRoot, "build/Debug"), { recursive: true });
  await writeFile(debugAddon, await readFile(resolve(packageRoot, "prebuilds", target, "kerberos.node")));
  const marker = resolve(packageRoot, "native-load-marker");
  const preload = resolve(packageRoot, "native-load-observer.cjs");
  await writeFile(preload, `
    const Module = require("node:module");
    const original = Module._extensions[".node"];
    Module._extensions[".node"] = function(module, filename) {
      require("node:fs").writeFileSync(${JSON.stringify(marker)}, filename);
      return original(module, filename);
    };
  `);

  runInstaller(packageRoot, {
    LDAP_AXI_NATIVE_MODE: "of",
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ""} --require=${preload}`.trim(),
  });
  assert.deepEqual(await status(packageRoot), {
    target,
    mode: "of",
    result: "unavailable",
    detail: "invalid native mode",
  });
  assert.equal(existsSync(debugAddon), false);
  assert.equal(existsSync(resolve(packageRoot, "build/Release/kerberos.node")), false);
  assert.equal(existsSync(marker), false);

  await mkdir(resolve(packageRoot, "build/Debug"), { recursive: true });
  await writeFile(debugAddon, await readFile(resolve(packageRoot, "prebuilds", target, "kerberos.node")));
  const { createKerberosProvider } = await import(`${pathToFileURL(resolve(packageRoot, "dist/src/directory/gssapi.js")).href}?invalid-mode`) as {
    createKerberosProvider: () => { prepare: (service: string) => Promise<unknown> };
  };
  assert.deepEqual(await createKerberosProvider().prepare("ldap@directory.example.test"), { kind: "provider_unavailable" });
});

test("source-build failure preserves explicit simple authentication", async () => {
  const failedSource = install("source-failure-consumer", {
    LDAP_AXI_NATIVE_MODE: "source",
    NODE_GYP_FORCE_PYTHON: "missing-ldap-axi-python",
  });
  assert.deepEqual(await status(failedSource), {
    target: process.platform === "win32" ? "win32-x64" : "linux-glibc-x64",
    mode: "source",
    result: "unavailable",
    detail: "source build failed",
  });
  const { createKerberosProvider } = await import(pathToFileURL(resolve(failedSource, "dist/src/directory/gssapi.js")).href) as {
    createKerberosProvider: () => { prepare: (service: string) => Promise<unknown> };
  };
  assert.deepEqual(await createKerberosProvider().prepare("ldap@directory.example.test"), { kind: "provider_unavailable" });
  const { selectAuthPlan } = await import(pathToFileURL(resolve(failedSource, "dist/src/directory/auth.js")).href) as {
    selectAuthPlan: (input: Readonly<Record<string, unknown>>) => Promise<unknown>;
  };
  assert.deepEqual(
    await selectAuthPlan({
      requested: "simple",
      url: "ldaps://directory.example.test",
      credentials: { dn: "uid=synthetic", password: "pw" },
    }),
    {
      requested: "simple",
      mode: "simple",
      credentials: { dn: "uid=synthetic", password: "pw" },
      credentialSource: undefined,
      protection: "none",
    },
  );
});
