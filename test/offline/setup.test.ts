import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, cp, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import test from "node:test";
import { createSkillMarkdown } from "../../src/skill.js";

const cli = resolve("dist/src/cli.js");
const guard = `import net from 'node:net'; import tls from 'node:tls'; import { syncBuiltinESMExports } from 'node:module';
  const denied = () => process.exit(99); net.Socket.prototype.connect = denied; tls.connect = denied; syncBuiltinESMExports();`;
type Hook = { type: string; command: string; args: string[]; statusMessage?: string };
type Settings = { hooks: { SessionStart: { hooks: Hook[]; matcher?: string }[]; [key: string]: unknown }; [key: string]: unknown };

async function fixture(body: (root: string, env: NodeJS.ProcessEnv, invoke: (args: string[], executable?: string) => ReturnType<typeof spawnSync>) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "ldap-axi setup ' space-"));
  const env = {
    ...process.env, HOME: root, USERPROFILE: root, APPDATA: root,
    CLAUDE_CONFIG_DIR: join(root, "claude"), CODEX_HOME: join(root, "codex"), OPENCODE_CONFIG_DIR: join(root, "opencode"),
    LDAP_AXI_CONFIG: join(root, "missing.json"), LDAP_AXI_CREDENTIALS_FILE: join(root, "missing.env"),
    LDAP_AXI_URL: "ldaps://synthetic.example.test", LDAP_AXI_BIND_DN: "cn=synthetic", LDAP_AXI_BIND_PASSWORD: "synthetic-secret",
  };
  const invoke = (args: string[], executable = cli): ReturnType<typeof spawnSync> => spawnSync(process.execPath, [
    "--import", `data:text/javascript,${encodeURIComponent(guard)}`, executable, ...args,
  ], { env, cwd: root, encoding: "utf8" });
  try { await body(root, env, invoke); }
  finally { await rm(root, { recursive: true, force: true }); }
}

const install = ["setup", "--app", "claude", "--hook", "--skill"];
async function settings(root: string): Promise<Settings> { return JSON.parse(await readFile(join(root, "claude", "settings.json"), "utf8")); }
function owned(config: Settings): Hook[] { return config.hooks.SessionStart.flatMap(group => group.hooks).filter(hook => hook.statusMessage === "ldap-axi offline home"); }

test("setup check is read-only and install is idempotent in a temporary home", async () => {
  await fixture(async (root, _env, invoke) => {
    const checked = invoke([...install, "--check"]);
    assert.equal(checked.status, 1, String(checked.stdout));
    assert.match(String(checked.stdout), /missing/);
    assert.deepEqual(await readdir(root), []);
    const installed = invoke(install);
    assert.equal(installed.status, 0, String(installed.stdout));
    const file = join(root, "claude", "settings.json");
    const skill = join(root, "claude", "skills", "ldap-axi", "SKILL.md");
    const before = await readFile(file, "utf8");
    const times = [(await stat(file)).mtimeMs, (await stat(skill)).mtimeMs];
    assert.ok((await readFile(skill, "utf8")).startsWith(createSkillMarkdown()));
    assert.equal(invoke([...install, "--check"]).status, 0);
    assert.equal(invoke(install).status, 0);
    assert.equal(await readFile(file, "utf8"), before);
    assert.deepEqual([(await stat(file)).mtimeMs, (await stat(skill)).mtimeMs], times);
    assert.equal(owned(await settings(root)).length, 1);
  });
});

test("setup repairs owned hooks and skills while preserving unrelated config", async () => {
  await fixture(async (root, _env, invoke) => {
    assert.equal(invoke(install).status, 0);
    const config = await settings(root);
    const hook = owned(config)[0];
    hook.command = "missing-old-executable";
    config.permissions = { allow: ["Read"] };
    config.hooks.Stop = [{ hooks: [{ type: "command", command: "unrelated-stop" }] }];
    const unrelated = { type: "command", command: "unrelated-start", args: [] };
    config.hooks.SessionStart = [{ matcher: "startup", hooks: [hook, unrelated as Hook] }, { hooks: [hook] }];
    await writeFile(join(root, "claude", "settings.json"), JSON.stringify(config));
    const skill = join(root, "claude", "skills", "ldap-axi", "SKILL.md");
    await writeFile(skill, "stale\n<!-- Managed by ldap-axi setup. -->\n");
    assert.equal(invoke([...install, "--check"]).status, 1);
    assert.equal(owned(await settings(root)).length, 2);
    assert.equal(invoke(install).status, 0);
    const repaired = await settings(root);
    assert.deepEqual(repaired.permissions, config.permissions);
    assert.deepEqual(repaired.hooks.Stop, config.hooks.Stop);
    assert.deepEqual(repaired.hooks.SessionStart[0], { matcher: "startup", hooks: [unrelated] });
    assert.equal(owned(repaired).length, 1);
    assert.notEqual(owned(repaired)[0].command, hook.command);
    assert.equal(invoke([...install, "--check"]).status, 0);
  });
});

test("installed hook executes the compact offline home with paths containing spaces", async () => {
  await fixture(async (root, env, invoke) => {
    assert.equal(invoke(install).status, 0);
    const hook = owned(await settings(root))[0];
    assert.equal(hook.type, "command");
    const result = spawnSync(hook.command, ["--import", `data:text/javascript,${encodeURIComponent(guard)}`, ...hook.args], { env, cwd: root, encoding: "utf8" });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /Read Active Directory/);
    assert.match(result.stdout, /commands\[/);
    assert.doesNotMatch(result.stdout, /synthetic-secret|count:|Install the ldap-axi skill/);
    assert.deepEqual(await readdir(root), ["claude"]);
  });
});

test("setup repairs the executable after relocation", async () => {
  await fixture(async (root, _env, invoke) => {
    assert.equal(invoke(install).status, 0);
    const moved = join(root, "relocated package", "src");
    await cp("dist/src", moved, { recursive: true });
    await writeFile(join(dirname(moved), "package.json"), '{"type":"module"}');
    await symlink(resolve("node_modules"), join(dirname(moved), "node_modules"), process.platform === "win32" ? "junction" : "dir");
    const executable = join(moved, "cli.js");
    assert.equal(invoke([...install, "--check"], executable).status, 1);
    const result = invoke(install, executable);
    assert.equal(result.status, 0, String(result.stdout));
    const hook = owned(await settings(root))[0];
    assert.equal(hook.args[0], await realpath(executable));
    const output = spawnSync(hook.command, hook.args, { cwd: root, env: _env, encoding: "utf8" });
    assert.equal(output.status, 0, output.stdout + output.stderr);
    assert.match(output.stdout, /Read Active Directory/);
    assert.equal(invoke([...install, "--check"], executable).status, 0);
  });
});

test("setup uses a verified PATH binary and rejects an earlier conflicting binary", { skip: process.platform === "win32" }, async () => {
  await fixture(async (root, env, invoke) => {
    const bin = join(root, "bin");
    await mkdir(bin);
    await chmod(cli, 0o755);
    await symlink(cli, join(bin, "ldap-axi"));
    env.PATH = bin + delimiter + process.env.PATH;
    assert.equal(invoke(install).status, 0);
    assert.equal(owned(await settings(root))[0].command, "ldap-axi");
    const conflicting = join(root, "conflict");
    await mkdir(conflicting);
    await writeFile(join(conflicting, "ldap-axi"), "#!/bin/sh\nexit 99\n", { mode: 0o755 });
    env.PATH = conflicting + delimiter + env.PATH;
    assert.equal(invoke([...install, "--check"]).status, 1);
    assert.equal(invoke(install).status, 0);
    assert.notEqual(owned(await settings(root))[0].command, "ldap-axi");
    assert.equal(owned(await settings(root))[0].args[0], await realpath(cli));
  });
});

for (const app of ["claude", "codex", "opencode"]) test(`setup installs only the explicitly selected ${app} skill`, async () => {
  await fixture(async (root, _env, invoke) => {
    const args = ["setup", "--app", app, "--skill"];
    assert.equal(invoke(args).status, 0);
    assert.deepEqual(await readdir(root), [app]);
    assert.deepEqual(await readdir(join(root, app)), ["skills"]);
    assert.equal(invoke([...args, "--check"]).status, 0);
  });
});

for (const content of ["{invalid", "[]", '{"hooks":{"SessionStart":{}}}', '{"hooks":{"SessionStart":[{"hooks":null}]}}']) test(`setup preserves invalid user config ${content}`, async () => {
  await fixture(async (root, _env, invoke) => {
    await mkdir(join(root, "claude"));
    const path = join(root, "claude", "settings.json");
    await writeFile(path, content);
    const result = invoke(install);
    assert.equal(result.status, 1, String(result.stdout));
    assert.match(String(result.stdout), /CONFIG_INVALID/);
    assert.equal(await readFile(path, "utf8"), content);
    assert.deepEqual(await readdir(join(root, "claude")), ["settings.json"]);
  });
});

test("setup refuses to overwrite a custom skill", async () => {
  await fixture(async (root, _env, invoke) => {
    const path = join(root, "claude", "skills", "ldap-axi", "SKILL.md");
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, "custom skill");
    assert.equal(invoke(install).status, 1);
    assert.equal(await readFile(path, "utf8"), "custom skill");
    assert.deepEqual(await readdir(join(root, "claude")), ["skills"]);
  });
});

for (const args of [[], ["--app", "claude"], ["--app", "unknown", "--skill"], ["--app", "codex", "--hook"], ["--app", "claude", "--skill=false"], ["--app", "claude", "--skill", "extra"], ["--app", "claude", "--skill", "--url", "ldaps://synthetic.example.test"], ["--app", "claude", "--bogus"]]) test(`setup rejects incomplete or unsupported input ${args.join(" ")}`, async () => {
  await fixture(async (root, _env, invoke) => {
    assert.equal(invoke(["setup", ...args]).status, 2);
    assert.deepEqual(await readdir(root), []);
  });
});

test("ordinary offline commands never install integrations or connect", async () => {
  await fixture(async (root, _env, invoke) => {
    for (const args of [[], ["--help"], ["--session-start"], ["setup", "--help"], ["auth", "status", "--offline"], ["config", "path"], ["profile", "list"]]) {
      const result = invoke(args);
      assert.equal(result.status, 0, String(result.stdout));
      assert.deepEqual(await readdir(root), []);
    }
  });
});
