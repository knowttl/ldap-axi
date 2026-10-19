import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { Readable } from "node:stream";
import { getStaticTOMLValue, parseForESLint } from "toml-eslint-parser";
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

for (const app of ["claude", "codex"]) for (const content of ["{invalid", "[]", '{"hooks":{"SessionStart":{}}}', '{"hooks":{"SessionStart":[{"hooks":null}]}}']) test(`setup preserves invalid ${app} config ${content}`, async () => {
  await fixture(async (root, _env, invoke) => {
    await mkdir(join(root, app));
    const file = app === "claude" ? "settings.json" : "hooks.json";
    const path = join(root, app, file);
    await writeFile(path, content);
    const result = invoke(["setup", "--app", app, "--hook", "--skill"]);
    assert.equal(result.status, 1, String(result.stdout));
    assert.match(String(result.stdout), /CONFIG_INVALID/);
    assert.equal(await readFile(path, "utf8"), content);
    assert.deepEqual(await readdir(join(root, app)), [file]);
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

for (const args of [[], ["--app", "claude"], ["--app", "unknown", "--skill"], ["--app", "claude", "--skill=false"], ["--app", "claude", "--skill", "extra"], ["--app", "claude", "--skill", "--url", "ldaps://synthetic.example.test"], ["--app", "claude", "--bogus"]]) test(`setup rejects incomplete or unsupported input ${args.join(" ")}`, async () => {
  await fixture(async (root, _env, invoke) => {
    assert.equal(invoke(["setup", ...args]).status, 2);
    assert.deepEqual(await readdir(root), []);
  });
});

for (const app of ["codex", "opencode"]) test(`${app} hook setup is isolated, read-only in check mode, idempotent and repairs relocation`, async () => {
  await fixture(async (root, _env, invoke) => {
    const args = ["setup", "--app", app, "--hook", "--skill"];
    assert.equal(invoke([...args, "--check"]).status, 1);
    assert.deepEqual(await readdir(root), []);
    assert.equal(invoke(args).status, 0);
    assert.deepEqual(await readdir(root), [app]);
    const path = app === "codex" ? join(root, app, "hooks.json") : join(root, app, "plugins", "ldap-axi.js");
    const before = await readFile(path, "utf8");
    const time = (await stat(path)).mtimeMs;
    assert.equal(invoke(args).status, 0);
    assert.equal(await readFile(path, "utf8"), before);
    assert.equal((await stat(path)).mtimeMs, time);
    assert.equal(invoke([...args, "--check"]).status, 0);
    const moved = join(root, "relocated package", "src");
    await cp("dist/src", moved, { recursive: true });
    await writeFile(join(dirname(moved), "package.json"), '{"type":"module"}');
    await symlink(resolve("node_modules"), join(dirname(moved), "node_modules"), process.platform === "win32" ? "junction" : "dir");
    const executable = join(moved, "cli.js");
    assert.equal(invoke([...args, "--check"], executable).status, 1);
    assert.equal(await readFile(path, "utf8"), before);
    assert.equal(invoke(args, executable).status, 0);
    assert.notEqual(await readFile(path, "utf8"), before);
    assert.equal(invoke([...args, "--check"], executable).status, 0);
  });
});

for (const content of [
  "", '# preserved\nmodel = "example"\n',
  '[features] # retained\nhooks = false # retained\nother = true\n[unrelated]\nhooks = false\n',
  'features.hooks = false\nfeatures.other = true\n',
  'features = { hooks = false, other = true }\n',
  'features = { other = true }\n',
  '[features]\nother = true\n',
  '[features.child]\nother = true\n',
  'other = [{ hooks = false }]\n["features"]\n"hooks" = false\n',
]) test(`Codex enables hooks without changing unrelated TOML: ${JSON.stringify(content)}`, async () => {
  await fixture(async (root, _env, invoke) => {
    await mkdir(join(root, "codex"));
    const path = join(root, "codex", "config.toml");
    await writeFile(path, content);
    const previous = getStaticTOMLValue(parseForESLint(content).ast);
    const args = ["setup", "--app", "codex", "--hook"];
    assert.equal(invoke(args).status, 0);
    const after = await readFile(path, "utf8");
    assert.deepEqual(getStaticTOMLValue(parseForESLint(after).ast), { ...previous, features: { ...previous.features as object, hooks: true } });
    assert.equal(invoke([...args, "--check"]).status, 0);
    assert.equal(invoke(args).status, 0);
    assert.equal(await readFile(path, "utf8"), after);
    if (content.includes("# retained")) assert.ok(after.includes("hooks = true # retained"));
  });
});

for (const content of ['[features', 'features = false', '[features]\nhooks = "false"', '[features]\nhooks = false\nhooks = true']) test(`Codex refuses invalid configuration before any writes: ${content}`, async () => {
  await fixture(async (root, _env, invoke) => {
    await mkdir(join(root, "codex"));
    const path = join(root, "codex", "config.toml");
    await writeFile(path, content);
    const result = invoke(["setup", "--app", "codex", "--hook", "--skill"]);
    assert.equal(result.status, 1, String(result.stdout));
    assert.match(String(result.stdout), /CONFIG_INVALID/);
    assert.equal(await readFile(path, "utf8"), content);
    assert.deepEqual(await readdir(join(root, "codex")), ["config.toml"]);
  });
});

test("Codex preserves unrelated hooks and executes the installed shell command offline", async () => {
  await fixture(async (root, env, invoke) => {
    await mkdir(join(root, "codex"));
    const path = join(root, "codex", "hooks.json");
    const unrelated = { hooks: [{ type: "command", command: "unrelated" }], matcher: "resume" };
    await writeFile(path, JSON.stringify({ description: "keep", hooks: { Stop: [], SessionStart: [unrelated] } }));
    const args = ["setup", "--app", "codex", "--hook"];
    assert.equal(invoke(args).status, 0);
    let config = JSON.parse(await readFile(path, "utf8"));
    assert.equal(config.description, "keep");
    assert.deepEqual(config.hooks.Stop, []);
    assert.deepEqual(config.hooks.SessionStart[0], unrelated);
    const hook = owned(config)[0] as Hook & { commandWindows: string; timeout: number };
    const command = process.platform === "win32" ? hook.commandWindows : hook.command;
    const result = spawnSync(command, { shell: true, cwd: root, env: { ...env, NODE_OPTIONS: `--import=data:text/javascript,${encodeURIComponent(guard)}` }, encoding: "utf8", timeout: 5000 });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /Read Active Directory/);
    assert.ok(result.stdout.length < 8192);
    assert.doesNotMatch(result.stdout, /synthetic-secret|count:/);
    hook.command = "old-path";
    config.hooks.SessionStart.push({ hooks: [hook, { type: "command", command: "other" }] });
    await writeFile(path, JSON.stringify(config));
    assert.equal(invoke(args).status, 0);
    config = JSON.parse(await readFile(path, "utf8"));
    assert.equal(owned(config).length, 1);
    assert.deepEqual(config.hooks.SessionStart[1].hooks, [{ type: "command", command: "other" }]);
  });
});

test("OpenCode refuses an unowned plugin and preserves unrelated files", async () => {
  await fixture(async (root, _env, invoke) => {
    const path = join(root, "opencode", "plugins", "ldap-axi.js");
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, "export const Custom = async () => ({});\n");
    await writeFile(join(dirname(path), "other.js"), "other");
    const result = invoke(["setup", "--app", "opencode", "--hook", "--skill"]);
    assert.equal(result.status, 1, String(result.stdout));
    assert.equal(await readFile(path, "utf8"), "export const Custom = async () => ({});\n");
    assert.equal(await readFile(join(dirname(path), "other.js"), "utf8"), "other");
    assert.deepEqual(await readdir(join(root, "opencode")), ["plugins"]);
  });
});

test("OpenCode injects bounded offline context through its real generated plugin", async () => {
  await fixture(async (root, env, invoke) => {
    assert.equal(invoke(["setup", "--app", "opencode", "--hook"]).status, 0);
    const source = await readFile(join(root, "opencode", "plugins", "ldap-axi.js"), "utf8");
    const plugin = await import(`data:text/javascript,${encodeURIComponent(source)}`);
    const runtime = globalThis as typeof globalThis & { Bun?: unknown };
    const previous = runtime.Bun;
    runtime.Bun = { spawn: (argv: string[], options: { cwd: string; timeout: number }) => {
      const child = spawn(argv[0], argv.slice(1), { ...options, env: { ...env, NODE_OPTIONS: `--import=data:text/javascript,${encodeURIComponent(guard)}` }, stdio: ["ignore", "pipe", "ignore"] });
      return { stdout: Readable.toWeb(child.stdout!), exited: new Promise(resolve => child.on("exit", resolve)), kill: () => child.kill() };
    } };
    try {
      const hooks = await plugin.LdapAxi({ directory: root });
      const output = { system: ["unrelated context"] };
      await hooks["experimental.chat.system.transform"]({}, output);
      assert.equal(output.system.length, 2);
      assert.equal(output.system[0], "unrelated context");
      assert.match(output.system[1], /Read Active Directory/);
      assert.ok(output.system[1].length < 8192);
      assert.doesNotMatch(output.system[1], /synthetic-secret|count:/);
      await hooks["experimental.chat.system.transform"]({}, output);
      assert.equal(output.system.length, 2);
      for (const [text, code] of [["x".repeat(8193), 0], ["failed", 1]] as const) {
        let killed = false;
        runtime.Bun = { spawn: (_argv: unknown, options: { timeout: number }) => {
          assert.equal(options.timeout, 5000);
          return { stdout: new Blob([text]).stream(), exited: Promise.resolve(code), kill: () => { killed = true; } };
        } };
        await hooks["experimental.chat.system.transform"]({}, output);
        assert.equal(output.system.length, 2);
        assert.ok(killed);
      }
      runtime.Bun = { spawn: () => { throw new Error("missing executable"); } };
      await hooks["experimental.chat.system.transform"]({}, output);
      assert.equal(output.system.length, 2);
    } finally { runtime.Bun = previous; }
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
