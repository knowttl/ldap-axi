import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

type SkillRoot = Readonly<{ scope: "ancestors" | "cwd" | "user-system" | "worktree-fallback"; path: string }>;

function worktreeSkillInstalled(root: string, skills: string): boolean {
  if (existsSync(join(root, skills))) return false;
  try {
    const gitdir = /^gitdir: (.+)$/m.exec(readFileSync(join(root, ".git"), "utf8"))?.[1].trim();
    if (!gitdir) return false;
    const directory = resolve(root, gitdir);
    const common = readFileSync(join(directory, "commondir"), "utf8").trim();
    if (!common) return false;
    const commonDirectory = resolve(directory, common);
    return basename(commonDirectory) === ".git" && existsSync(join(dirname(commonDirectory), skills, "ldap-axi", "SKILL.md"));
  } catch {
    return false;
  }
}

export function skillInstallHint(): string | undefined {
  try {
    const env = process.env;
    const home = homedir();
    const claudeHome = env.CLAUDE_CONFIG_DIR?.trim() || join(home, ".claude");
    const codexHome = env.CODEX_HOME?.trim() || join(home, ".codex");
    const configHome = env.XDG_CONFIG_HOME && isAbsolute(env.XDG_CONFIG_HOME) ? env.XDG_CONFIG_HOME : join(home, ".config");
    const piHome = (env.PI_CODING_AGENT_DIR || join(home, ".pi", "agent")).replace(/^~(?=$|[/\\])/, () => home);
    // Skills CLI destinations: https://github.com/vercel-labs/skills/blob/main/src/agents.ts
    const hosts: readonly Readonly<{ detected: boolean; roots: readonly SkillRoot[] }>[] = [
      {
        // https://code.claude.com/docs/en/skills
        // https://code.claude.com/docs/en/managed-settings
        // https://code.claude.com/docs/en/env-vars
        detected: env.CLAUDECODE === "1",
        roots: [
          { scope: "ancestors", path: join(".claude", "skills") },
          { scope: "worktree-fallback", path: join(".claude", "skills") },
          { scope: "user-system", path: join(claudeHome, "skills") },
          { scope: "user-system", path: join(claudeHome, "skills", "synced") },
          { scope: "user-system", path: join(process.platform === "darwin" ? "/Library/Application Support/ClaudeCode" : process.platform === "win32" ? "C:/Program Files/ClaudeCode" : "/etc/claude-code", ".claude", "skills") },
        ],
      },
      {
        // https://opencode.ai/docs/skills/
        // https://opencode.ai/docs/config/#custom-directory
        // https://github.com/anomalyco/opencode/blob/HEAD/packages/core/src/config/discovery.ts
        // https://github.com/anomalyco/opencode/blob/HEAD/packages/core/src/config/plugin/skill.ts
        detected: env.OPENCODE === "1",
        roots: [
          { scope: "ancestors", path: join(".agents", "skills") },
          { scope: "ancestors", path: join(".claude", "skills") },
          ...["skills", "skill"].map(name => ({ scope: "ancestors" as const, path: join(".opencode", name) })),
          { scope: "user-system", path: join(home, ".agents", "skills") },
          { scope: "user-system", path: join(home, ".claude", "skills") },
          ...[
            join(configHome, "opencode"),
            ...(env.OPENCODE_CONFIG_DIR ? [env.OPENCODE_CONFIG_DIR] : []),
            process.platform === "darwin" ? "/Library/Application Support/opencode" : process.platform === "win32" ? join(env.ProgramData || "C:/ProgramData", "opencode") : "/etc/opencode",
          ].flatMap(directory => ["skills", "skill"].map(name => ({ scope: "user-system" as const, path: join(directory, name) }))),
        ],
      },
      {
        // https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/src/core/skills.ts
        // https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/src/config.ts
        detected: env.PI_CODING_AGENT === "true",
        roots: [
          { scope: "ancestors", path: join(".agents", "skills") },
          { scope: "cwd", path: join(".pi", "skills") },
          { scope: "user-system", path: join(home, ".agents", "skills") },
          { scope: "user-system", path: join(piHome, "skills") },
        ],
      },
      {
        // https://developers.openai.com/codex/skills
        // https://github.com/openai/codex/blob/main/codex-rs/ext/skills/src/host_roots.rs
        // https://github.com/openai/codex/blob/main/codex-rs/skills/src/lib.rs
        // https://github.com/openai/codex/blob/main/codex-rs/config/src/loader/mod.rs
        detected: Boolean(env.CODEX_THREAD_ID || env.CODEX_SESSION_ID),
        roots: [
          { scope: "ancestors", path: join(".agents", "skills") },
          { scope: "ancestors", path: join(".codex", "skills") },
          { scope: "user-system", path: join(home, ".agents", "skills") },
          { scope: "user-system", path: join(codexHome, "skills") },
          { scope: "user-system", path: join(codexHome, "skills", ".system") },
          { scope: "user-system", path: join(process.platform === "win32" ? join(env.ProgramData || "C:/ProgramData", "OpenAI", "Codex") : "/etc/codex", "skills") },
        ],
      },
    ];
    const host = hosts.find(candidate => candidate.detected);
    if (!host) return undefined;
    const cwd = process.cwd();
    if (host.roots.some(root => (root.scope === "user-system" || root.scope === "cwd") && existsSync(join(root.scope === "cwd" ? join(cwd, root.path) : root.path, "ldap-axi", "SKILL.md")))) return undefined;
    for (let directory = cwd; ; directory = dirname(directory)) {
      if (host.roots.some(root => root.scope === "ancestors" && existsSync(join(directory, root.path, "ldap-axi", "SKILL.md")))) return undefined;
      if (existsSync(join(directory, ".git")) || dirname(directory) === directory) {
        if (host.roots.some(root => root.scope === "worktree-fallback" && worktreeSkillInstalled(directory, root.path))) return undefined;
        break;
      }
    }
    return "Install the ldap-axi skill: `npx skills add knowttl/ldap-axi --skill ldap-axi`";
  } catch {
    // An optional hint must never prevent the home view from rendering.
    return undefined;
  }
}
