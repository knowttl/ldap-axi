import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";

const executable = resolve("dist/src/cli.js");
const installCommand = "npx skills add knowttl/ldap-axi --skill ldap-axi";
const cases = [
  { name: "Codex missing", marker: { CODEX_THREAD_ID: "synthetic" }, hint: true },
  { name: "Codex user", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "home/.agents/skills", hint: false },
  { name: "Codex project", marker: { CODEX_THREAD_ID: "synthetic" }, installed: "repo/work/.agents/skills", hint: false },
  { name: "Claude Code missing", marker: { CLAUDECODE: "1" }, hint: true },
  { name: "Claude Code user", marker: { CLAUDECODE: "1" }, installed: "home/.claude/skills", hint: false },
  { name: "Claude Code project", marker: { CLAUDECODE: "1" }, installed: "repo/work/.claude/skills", hint: false },
  { name: "Claude Code custom user directory", marker: { CLAUDECODE: "1" }, installed: "custom-claude/skills", customClaude: true, hint: false },
  { name: "OpenCode missing", marker: { OPENCODE: "1" }, hint: true },
  { name: "OpenCode user", marker: { OPENCODE: "1" }, installed: "home/.agents/skills", hint: false },
  { name: "OpenCode project", marker: { OPENCODE: "1" }, installed: "repo/work/.agents/skills", hint: false },
  { name: "Pi missing", marker: { PI_CODING_AGENT: "true" }, hint: true },
  { name: "Pi user", marker: { PI_CODING_AGENT: "true" }, installed: "home/.agents/skills", hint: false },
  { name: "Pi project", marker: { PI_CODING_AGENT: "true" }, installed: "repo/work/.agents/skills", hint: false },
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
        CODEX_THREAD_ID: "", CODEX_SESSION_ID: "", CLAUDECODE: "", OPENCODE: "", PI_CODING_AGENT: "",
        CLAUDE_CONFIG_DIR: row.customClaude ? join(root, "custom-claude") : "",
        LDAP_AXI_CONFIG: join(root, "absent.json"), LDAP_AXI_CREDENTIALS_FILE: join(root, "absent.env"),
        LDAP_AXI_URL: undefined, LDAP_AXI_BIND_DN: undefined, LDAP_AXI_BIND_PASSWORD: undefined, LDAP_AXI_AUTH: undefined, LDAP_AXI_CONFIG_FILE: undefined,
        ...row.marker,
      };
      const result = spawnSync(process.execPath, [executable], { cwd, env, encoding: "utf8" });
      const baseline = spawnSync(process.execPath, [executable], { cwd, env: { ...env, CODEX_THREAD_ID: "", CLAUDECODE: "", OPENCODE: "", PI_CODING_AGENT: "" }, encoding: "utf8" });
      assert.equal(result.status, 0, result.stdout);
      assert.equal(result.stderr, "");
      assert.equal(result.stdout.includes(installCommand), row.hint);
      assert.equal(result.stdout, row.hint ? baseline.stdout.replace("help[2]", "help[3]").trimEnd() + ',"Install the ldap-axi skill: `' + installCommand + '`"\n' : baseline.stdout);
      for (const argv of [["--help"], ["--url", "ldaps://directory.example.test"], ["auth", "status", "--offline"]]) {
        const withHost = spawnSync(process.execPath, [executable, ...argv], { cwd, env, encoding: "utf8" });
        const withoutHost = spawnSync(process.execPath, [executable, ...argv], { cwd, env: { ...env, CODEX_THREAD_ID: "", CLAUDECODE: "", OPENCODE: "", PI_CODING_AGENT: "" }, encoding: "utf8" });
        assert.equal(withHost.status, 0, withHost.stdout);
        assert.equal(withHost.stdout, withoutHost.stdout);
        assert.equal(withHost.stderr, withoutHost.stderr);
        assert.equal(withHost.status, withoutHost.status);
      }
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});
