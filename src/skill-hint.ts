import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";

export function skillInstallHint(): string | undefined {
  try {
    const env = process.env;
    const home = homedir();
    const claudeHome = env.CLAUDE_CONFIG_DIR?.trim() || join(home, ".claude");
    const codexHome = env.CODEX_HOME?.trim() || join(home, ".codex");
    const configHome = env.XDG_CONFIG_HOME && isAbsolute(env.XDG_CONFIG_HOME) ? env.XDG_CONFIG_HOME : join(home, ".config");
    const piHome = (env.PI_CODING_AGENT_DIR || join(home, ".pi", "agent")).replace(/^~(?=$|[/\\])/, () => home);
    // Skills CLI destinations: https://github.com/vercel-labs/skills/blob/main/src/agents.ts
    const hosts = [
      {
        // https://code.claude.com/docs/en/skills
        // https://code.claude.com/docs/en/managed-settings
        // https://code.claude.com/docs/en/env-vars
        detected: env.CLAUDECODE === "1",
        project: [join(".claude", "skills")],
        roots: [
          join(claudeHome, "skills"),
          join(claudeHome, "skills", "synced"),
          join(process.platform === "darwin" ? "/Library/Application Support/ClaudeCode" : process.platform === "win32" ? "C:/Program Files/ClaudeCode" : "/etc/claude-code", ".claude", "skills"),
        ],
      },
      {
        // https://opencode.ai/docs/skills/
        // https://opencode.ai/docs/config/#custom-directory
        // https://github.com/anomalyco/opencode/blob/HEAD/packages/core/src/config/discovery.ts
        // https://github.com/anomalyco/opencode/blob/HEAD/packages/core/src/config/plugin/skill.ts
        detected: env.OPENCODE === "1",
        project: [join(".agents", "skills"), join(".claude", "skills"), ...["skills", "skill"].map(name => join(".opencode", name))],
        roots: [
          join(home, ".agents", "skills"),
          join(home, ".claude", "skills"),
          ...[
            join(configHome, "opencode"),
            ...(env.OPENCODE_CONFIG_DIR ? [env.OPENCODE_CONFIG_DIR] : []),
            process.platform === "darwin" ? "/Library/Application Support/opencode" : process.platform === "win32" ? join(env.ProgramData || "C:/ProgramData", "opencode") : "/etc/opencode",
          ].flatMap(directory => ["skills", "skill"].map(name => join(directory, name))),
        ],
      },
      {
        // https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/src/core/skills.ts
        // https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/src/config.ts
        detected: env.PI_CODING_AGENT === "true",
        project: [join(".agents", "skills")],
        roots: [join(home, ".agents", "skills"), join(piHome, "skills"), join(process.cwd(), ".pi", "skills")],
      },
      {
        // https://developers.openai.com/codex/skills
        // https://github.com/openai/codex/blob/main/codex-rs/ext/skills/src/host_roots.rs
        // https://github.com/openai/codex/blob/main/codex-rs/skills/src/lib.rs
        // https://github.com/openai/codex/blob/main/codex-rs/config/src/loader/mod.rs
        detected: Boolean(env.CODEX_THREAD_ID || env.CODEX_SESSION_ID),
        project: [join(".agents", "skills"), join(".codex", "skills")],
        roots: [
          join(home, ".agents", "skills"),
          join(codexHome, "skills"),
          join(codexHome, "skills", ".system"),
          join(process.platform === "win32" ? join(env.ProgramData || "C:/ProgramData", "OpenAI", "Codex") : "/etc/codex", "skills"),
        ],
      },
    ];
    const host = hosts.find(candidate => candidate.detected);
    if (!host) return undefined;
    if (host.roots.some(directory => existsSync(join(directory, "ldap-axi", "SKILL.md")))) return undefined;
    for (let directory = process.cwd(); ; directory = dirname(directory)) {
      if (host.project.some(skills => existsSync(join(directory, skills, "ldap-axi", "SKILL.md")))) return undefined;
      if (existsSync(join(directory, ".git")) || dirname(directory) === directory) break;
    }
    return "Install the ldap-axi skill: `npx skills add knowttl/ldap-axi --skill ldap-axi`";
  } catch {
    // An optional hint must never prevent the home view from rendering.
    return undefined;
  }
}
