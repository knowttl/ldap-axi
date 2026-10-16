import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

/** Only verified host markers and skills CLI install destinations belong here. */
export function skillInstallHint(): string | undefined {
  try {
    const env = process.env;
    const claude = env.CLAUDECODE === "1";
    if (!claude && !env.CODEX_THREAD_ID && !env.CODEX_SESSION_ID && env.OPENCODE !== "1" && env.PI_CODING_AGENT !== "true") return undefined;
    const projectSkills = claude ? join(".claude", "skills") : join(".agents", "skills");
    const userSkills = claude ? join(env.CLAUDE_CONFIG_DIR?.trim() || join(homedir(), ".claude"), "skills") : join(homedir(), ".agents", "skills");
    if (existsSync(join(userSkills, "ldap-axi", "SKILL.md"))) return undefined;
    for (let directory = process.cwd(); ; directory = dirname(directory)) {
      if (existsSync(join(directory, projectSkills, "ldap-axi", "SKILL.md"))) return undefined;
      if (existsSync(join(directory, ".git")) || dirname(directory) === directory) break;
    }
    return "Install the ldap-axi skill: `npx skills add knowttl/ldap-axi --skill ldap-axi`";
  } catch {
    // An optional hint must never prevent the home view from rendering.
    return undefined;
  }
}
