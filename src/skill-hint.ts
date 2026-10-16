import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";

export function skillInstallHint(): string | undefined {
  try {
    const env = process.env;
    const claude = env.CLAUDECODE === "1";
    if (!claude && !env.CODEX_THREAD_ID && !env.CODEX_SESSION_ID && env.OPENCODE !== "1" && env.PI_CODING_AGENT !== "true") return undefined;
    const home = homedir();
    const projectSkills = [join(claude ? ".claude" : ".agents", "skills")];
    const userSkills = [claude ? join(env.CLAUDE_CONFIG_DIR?.trim() || join(home, ".claude"), "skills") : join(home, ".agents", "skills")];
    if (!claude && env.OPENCODE === "1") {
      projectSkills.push(join(".opencode", "skills"), join(".claude", "skills"));
      const configHome = env.XDG_CONFIG_HOME && isAbsolute(env.XDG_CONFIG_HOME) ? env.XDG_CONFIG_HOME : join(home, ".config");
      userSkills.push(join(configHome, "opencode", "skills"), join(home, ".claude", "skills"));
    }
    if (!claude && env.PI_CODING_AGENT === "true") {
      const agentDir = env.PI_CODING_AGENT_DIR || join(home, ".pi", "agent");
      userSkills.push(join(agentDir.replace(/^~(?=$|[/\\])/, home), "skills"), join(process.cwd(), ".pi", "skills"));
    }
    if (userSkills.some(directory => existsSync(join(directory, "ldap-axi", "SKILL.md")))) return undefined;
    for (let directory = process.cwd(); ; directory = dirname(directory)) {
      if (projectSkills.some(skills => existsSync(join(directory, skills, "ldap-axi", "SKILL.md")))) return undefined;
      if (existsSync(join(directory, ".git")) || dirname(directory) === directory) break;
    }
    return "Install the ldap-axi skill: `npx skills add knowttl/ldap-axi --skill ldap-axi`";
  } catch {
    // An optional hint must never prevent the home view from rendering.
    return undefined;
  }
}
