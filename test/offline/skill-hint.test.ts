import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

const executable = resolve("dist/src/cli.js");
const installCommand = "npx skills add knowttl/ldap-axi --skill ldap-axi";
const noHost = { CODEX_THREAD_ID: "", CODEX_SESSION_ID: "", CLAUDECODE: "", OPENCODE: "", PI_CODING_AGENT: "" };
const cases = [
  { name: "Codex missing", marker: { CODEX_THREAD_ID: "synthetic" }, hint: true },
  { name: "Codex user", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "home/.agents/skills", hint: false },
  { name: "Codex project", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "repo/work/.agents/skills", hint: false },
  { name: "Codex native user", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "home/.codex/skills", hint: false },
  { name: "Codex native project", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "repo/work/.codex/skills", hint: false },
  { name: "Codex native ancestor", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "repo/.codex/skills", hint: false },
  { name: "Codex bundled system", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "home/.codex/skills/.system", hint: false },
  { name: "Codex custom user", marker: { CODEX_SESSION_ID: "synthetic" }, installed: "custom-codex/skills", customCodex: true, hint: false },
  { name: "Codex custom bundled system", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "custom-codex/skills/.system", customCodex: true, hint: false },
  { name: "Codex override replaces native user", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "home/.codex/skills", customCodex: true, hint: true },
  { name: "Claude Code missing", marker: { CLAUDECODE: "1" }, hint: true },
  { name: "Claude Code user", marker: { CLAUDECODE: "1" }, installed: "home/.claude/skills", hint: false },
  { name: "Claude Code project", marker: { CLAUDECODE: "1" }, installed: "repo/work/.claude/skills", hint: false },
  { name: "Claude Code custom user directory", marker: { CLAUDECODE: "1" }, installed: "custom-claude/skills", customClaude: true, hint: false },
  { name: "Claude Code ancestor", marker: { CLAUDECODE: "1" }, installed: "repo/.claude/skills", hint: false },
  { name: "Claude Code synced user", marker: { CLAUDECODE: "1" }, installed: "home/.claude/skills/synced", hint: false },
  { name: "Claude Code custom synced user", marker: { CLAUDECODE: "1" }, installed: "custom-claude/skills/synced", customClaude: true, hint: false },
  { name: "Codex-only install does not suppress Claude hint", marker: { CLAUDECODE: "1" }, installed: "home/.agents/skills", hint: true },
  { name: "Claude takes precedence over inherited Codex marker", marker: { CLAUDECODE: "1", CODEX_THREAD_ID: "synthetic" }, installed: "home/.agents/skills", hint: true },
  { name: "OpenCode missing", marker: { OPENCODE: "1" }, hint: true },
  { name: "OpenCode user", marker: { OPENCODE: "1" }, installed: "home/.agents/skills", hint: false },
  { name: "OpenCode project", marker: { OPENCODE: "1" }, installed: "repo/work/.agents/skills", hint: false },
  { name: "OpenCode native user", marker: { OPENCODE: "1" }, installed: "home/.config/opencode/skills", hint: false },
  { name: "OpenCode singular native user", marker: { OPENCODE: "1" }, installed: "home/.config/opencode/skill", hint: false },
  { name: "OpenCode XDG user", marker: { OPENCODE: "1" }, installed: "custom-config/opencode/skills", customConfig: true, hint: false },
  { name: "OpenCode custom config directory", marker: { OPENCODE: "1" }, installed: "custom-opencode/skills", customOpenCode: true, hint: false },
  { name: "OpenCode singular custom config directory", marker: { OPENCODE: "1" }, installed: "custom-opencode/skill", customOpenCode: true, hint: false },
  { name: "OpenCode custom config keeps native user", marker: { OPENCODE: "1" }, installed: "home/.config/opencode/skills", customOpenCode: true, hint: false },
  { name: "OpenCode takes precedence over inherited Codex marker", marker: { OPENCODE: "1", CODEX_THREAD_ID: "synthetic" }, installed: "home/.codex/skills", hint: true },
  { name: "OpenCode relative XDG ignored", marker: { OPENCODE: "1", XDG_CONFIG_HOME: "relative-config" }, installed: "home/.config/opencode/skills", hint: false },
  { name: "OpenCode native project", marker: { OPENCODE: "1" }, installed: "repo/work/.opencode/skills", hint: false },
  { name: "OpenCode singular native project", marker: { OPENCODE: "1" }, installed: "repo/work/.opencode/skill", hint: false },
  { name: "OpenCode native ancestor", marker: { OPENCODE: "1" }, installed: "repo/.opencode/skills", hint: false },
  { name: "OpenCode Claude user", marker: { OPENCODE: "1" }, installed: "home/.claude/skills", hint: false },
  { name: "OpenCode Claude project", marker: { OPENCODE: "1" }, installed: "repo/work/.claude/skills", hint: false },
  { name: "OpenCode Claude ancestor", marker: { OPENCODE: "1" }, installed: "repo/.claude/skills", hint: false },
  { name: "Pi missing", marker: { PI_CODING_AGENT: "true" }, hint: true },
  { name: "Pi user", marker: { PI_CODING_AGENT: "true" }, installed: "home/.agents/skills", hint: false },
  { name: "Pi project", marker: { PI_CODING_AGENT: "true" }, installed: "repo/work/.agents/skills", hint: false },
  { name: "Pi shared ancestor", marker: { PI_CODING_AGENT: "true" }, installed: "repo/.agents/skills", hint: false },
  { name: "Pi native user", marker: { PI_CODING_AGENT: "true" }, installed: "home/.pi/agent/skills", hint: false },
  { name: "Pi custom user", marker: { PI_CODING_AGENT: "true" }, installed: "custom-pi/skills", customPi: true, hint: false },
  { name: "Pi tilde user", marker: { PI_CODING_AGENT: "true", PI_CODING_AGENT_DIR: "~/custom-pi" }, installed: "home/custom-pi/skills", hint: false },
  { name: "Pi native project", marker: { PI_CODING_AGENT: "true" }, installed: "repo/work/.pi/skills", hint: false },
  { name: "Pi native ancestor ignored", marker: { PI_CODING_AGENT: "true" }, installed: "repo/.pi/skills", hint: true },
  { name: "Pi takes precedence over inherited Codex marker", marker: { PI_CODING_AGENT: "true", CODEX_THREAD_ID: "synthetic" }, installed: "home/.codex/skills", hint: true },
  { name: "no host", marker: {}, hint: false },
  { name: "repository ancestor", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "repo/.agents/skills", hint: false },
  { name: "above repository ignored", marker: { CODEX_THREAD_ID: "synthetic" }, installed: ".agents/skills", hint: true },
  { name: "another host's skill ignored", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "home/.claude/skills", hint: true },
  { name: "skill directory without file", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "home/.agents/skills", directoryOnly: true, hint: true },
];

test("the no-argument home hints only when the current host lacks its skill", async t => {
  for (const row of cases) await t.test(row.name, async () => {
    const root = await mkdtemp(join(tmpdir(), "ldap-axi-skill-hint-"));
    try {
      const cwd = join(root, "repo", "work");
      await mkdir(cwd, { recursive: true });
      // Worktrees have a .git file rather than a directory.
      await writeFile(join(root, "repo", ".git"), "gitdir: synthetic\n");
      if (row.installed) {
        const file = join(root, row.installed, "ldap-axi", "SKILL.md");
        await mkdir(dirname(file), { recursive: true });
        if (!row.directoryOnly) await writeFile(file, "synthetic skill\n");
      }
      const env = {
        ...process.env, HOME: join(root, "home"), USERPROFILE: join(root, "home"),
        ...noHost,
        CLAUDE_CONFIG_DIR: row.customClaude ? join(root, "custom-claude") : "",
        CODEX_HOME: row.customCodex ? join(root, "custom-codex") : "",
        OPENCODE_CONFIG_DIR: row.customOpenCode ? join(root, "custom-opencode") : "",
        XDG_CONFIG_HOME: row.customConfig ? join(root, "custom-config") : "",
        PI_CODING_AGENT_DIR: row.customPi ? join(root, "custom-pi") : "",
        LDAP_AXI_CONFIG: join(root, "absent.json"), LDAP_AXI_CREDENTIALS_FILE: join(root, "absent.env"),
        LDAP_AXI_URL: undefined, LDAP_AXI_BIND_DN: undefined, LDAP_AXI_BIND_PASSWORD: undefined, LDAP_AXI_AUTH: undefined, LDAP_AXI_CONFIG_FILE: undefined,
        ...row.marker,
      };
      const isolateSystemSkills = `
        import fs from "node:fs";
        import { syncBuiltinESMExports } from "node:module";
        import { relative, isAbsolute, sep, basename } from "node:path";
        const exists = fs.existsSync;
        fs.existsSync = path => {
          if (typeof path === "string" && basename(path) === "SKILL.md") {
            const local = relative(${JSON.stringify(root)}, path);
            if (isAbsolute(local) || local === ".." || local.startsWith(".." + sep)) return false;
          }
          return exists(path);
        };
        syncBuiltinESMExports();
      `;
      const nodeArgs = ["--import", "data:text/javascript," + encodeURIComponent(isolateSystemSkills), executable];
      const result = spawnSync(process.execPath, nodeArgs, { cwd, env, encoding: "utf8" });
      const baseline = spawnSync(process.execPath, nodeArgs, { cwd, env: { ...env, ...noHost }, encoding: "utf8" });
      assert.equal(result.status, 0, result.stdout);
      assert.equal(result.stderr, "");
      assert.equal(result.stdout.includes(installCommand), row.hint);
      assert.equal(result.stdout, row.hint ? baseline.stdout.replace("help[2]", "help[3]").trimEnd() + ',"Install the ldap-axi skill: `' + installCommand + '`"\n' : baseline.stdout);
      for (const argv of [["--help"], ["--url", "ldaps://directory.example.test"], ["auth", "status", "--offline"]]) {
        const withHost = spawnSync(process.execPath, [...nodeArgs, ...argv], { cwd, env, encoding: "utf8" });
        const withoutHost = spawnSync(process.execPath, [...nodeArgs, ...argv], { cwd, env: { ...env, ...noHost }, encoding: "utf8" });
        assert.equal(withHost.status, 0, withHost.stdout);
        assert.equal(withHost.stdout, withoutHost.stdout);
        assert.equal(withHost.stderr, withoutHost.stderr);
        assert.equal(withHost.status, withoutHost.status);
      }
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});

const systemCases = [
  { name: "Codex Linux admin", platform: "linux", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "/etc/codex/skills", hint: false },
  { name: "Codex macOS admin", platform: "darwin", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "/etc/codex/skills", hint: false },
  { name: "Codex Windows admin", platform: "win32", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "C:/ProgramData/OpenAI/Codex/skills", hint: false },
  { name: "Codex Windows custom ProgramData", platform: "win32", marker: { CODEX_THREAD_ID: "synthetic", ProgramData: "/synthetic-data" }, installed: "/synthetic-data/OpenAI/Codex/skills", hint: false },
  { name: "Claude Linux managed", platform: "linux", marker: { CLAUDECODE: "1" }, installed: "/etc/claude-code/.claude/skills", hint: false },
  { name: "Claude macOS managed", platform: "darwin", marker: { CLAUDECODE: "1" }, installed: "/Library/Application Support/ClaudeCode/.claude/skills", hint: false },
  { name: "Claude Windows managed", platform: "win32", marker: { CLAUDECODE: "1" }, installed: "C:/Program Files/ClaudeCode/.claude/skills", hint: false },
  { name: "OpenCode Linux managed", platform: "linux", marker: { OPENCODE: "1" }, installed: "/etc/opencode/skills", hint: false },
  { name: "OpenCode singular managed", platform: "linux", marker: { OPENCODE: "1" }, installed: "/etc/opencode/skill", hint: false },
  { name: "OpenCode macOS managed", platform: "darwin", marker: { OPENCODE: "1" }, installed: "/Library/Application Support/opencode/skills", hint: false },
  { name: "OpenCode Windows managed", platform: "win32", marker: { OPENCODE: "1" }, installed: "C:/ProgramData/opencode/skills", hint: false },
  { name: "OpenCode Windows custom ProgramData", platform: "win32", marker: { OPENCODE: "1", ProgramData: "/synthetic-data" }, installed: "/synthetic-data/opencode/skills", hint: false },
  { name: "Codex admin does not suppress Claude hint", platform: "linux", marker: { CLAUDECODE: "1" }, installed: "/etc/codex/skills", hint: true },
  { name: "Claude managed does not suppress Codex hint", platform: "linux", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "/etc/claude-code/.claude/skills", hint: true },
  { name: "OpenCode managed does not suppress Pi hint", platform: "linux", marker: { PI_CODING_AGENT: "true" }, installed: "/etc/opencode/skills", hint: true },
];

test("system skill roots suppress hints only for their host and platform", async t => {
  for (const row of systemCases) await t.test(row.name, () => {
    const result = spawnSync(process.execPath, ["--input-type=module", "-e", `
      import fs from "node:fs";
      import { syncBuiltinESMExports } from "node:module";
      import { join } from "node:path";
      Object.defineProperty(process, "platform", { value: ${JSON.stringify(row.platform)} });
      fs.existsSync = path => path === join(${JSON.stringify(row.installed)}, "ldap-axi", "SKILL.md");
      syncBuiltinESMExports();
      const { skillInstallHint } = await import(${JSON.stringify(pathToFileURL(resolve("dist/src/skill-hint.js")).href)});
      console.log(skillInstallHint() ?? "");
    `], { env: { ...process.env, ...noHost, ProgramData: "", ...row.marker }, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, "");
    assert.equal(result.stdout.trim(), row.hint ? "Install the ldap-axi skill: `" + installCommand + "`" : "");
  });
});
