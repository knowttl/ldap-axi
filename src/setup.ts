import { constants } from "node:fs";
import { access, lstat, mkdir, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { CliError } from "./core.js";
import { createSkillMarkdown } from "./skill.js";

const SKILL_MARKER = "<!-- Managed by ldap-axi setup. -->\n";
const HOOK_MARKER = "ldap-axi offline home";
type ObjectValue = Record<string, unknown>;
type Change = { path: string; before: string | undefined; after: string; kind: "skill" | "hook" };

export const SETUP_HELP = `Install or repair explicitly selected local agent integrations. No directory connection.
Usage: ldap-axi setup --app <claude|codex|opencode> [--skill] [--hook] [--check]
Flags:
  --app  required agent target; no automatic host selection
  --skill  install the shipped static skill (default: false)
  --hook  install Claude SessionStart offline home (default: false; Claude only)
  --check  report missing or stale integrations without writing (default: false)
  --help  show this reference
Select at least one of --skill or --hook. Repeating setup repairs owned files and preserves unrelated settings.
Examples:
  ldap-axi setup --app claude --hook --skill
  ldap-axi setup --app codex --skill --check`;

function object(value: unknown, label: string): ObjectValue {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new CliError("CONFIG_INVALID", `${label} must be a JSON object`);
  return value as ObjectValue;
}

async function read(path: string): Promise<string | undefined> {
  try {
    if (!(await lstat(path)).isFile()) throw new CliError("CONFIG_INVALID", "setup refuses a symlink or non-file destination", ["Use a regular file for the selected agent integration"]);
    return await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

/** Only absolute PATH entries participate, so a session's working directory cannot select the binary. */
async function verifiedName(name: string, current: string): Promise<string> {
  for (const directory of (process.env.PATH ?? "").split(delimiter)) {
    if (!isAbsolute(directory)) return current;
    const candidate = join(directory, name);
    try {
      await access(candidate, constants.X_OK);
      if (!(await lstat(candidate)).isFile() && !(await lstat(candidate)).isSymbolicLink()) continue;
      return await realpath(candidate) === await realpath(current) ? name : current;
    } catch (error) {
      if (!["ENOENT", "EACCES", "ENOTDIR"].includes((error as NodeJS.ErrnoException).code ?? "")) throw error;
    }
  }
  return current;
}

async function hookCommand(executable: string): Promise<ObjectValue> {
  const cli = await realpath(resolve(executable));
  // Windows npm shims require a shell. Invoke the actual Node executable instead.
  const name = process.platform === "win32" ? cli : await verifiedName("ldap-axi", cli);
  if (name === "ldap-axi") return { type: "command", command: name, args: ["--session-start"], statusMessage: HOOK_MARKER, timeout: 5 };
  const node = await verifiedName(process.platform === "win32" ? "node.exe" : "node", process.execPath);
  return { type: "command", command: node, args: [cli, "--session-start"], statusMessage: HOOK_MARKER, timeout: 5 };
}

function repairHooks(settings: ObjectValue, desired: ObjectValue): ObjectValue {
  const hooks = settings.hooks === undefined ? {} : object(settings.hooks, "hooks");
  const starts = hooks.SessionStart ?? [];
  if (!Array.isArray(starts)) throw new CliError("CONFIG_INVALID", "hooks.SessionStart must be an array");
  const groups: ObjectValue[] = [];
  for (const value of starts) {
    const group = object(value, "SessionStart entry");
    if (!Array.isArray(group.hooks)) throw new CliError("CONFIG_INVALID", "SessionStart entry hooks must be an array");
    const remaining = group.hooks.filter(value => {
      const hook = object(value, "SessionStart hook");
      return hook.statusMessage !== HOOK_MARKER;
    });
    if (remaining.length || !group.hooks.length) groups.push({ ...group, hooks: remaining });
  }
  groups.push({ hooks: [desired] });
  return { ...settings, hooks: { ...hooks, SessionStart: groups } };
}

async function apply(change: Change): Promise<void> {
  await mkdir(dirname(change.path), { recursive: true });
  const temporary = join(dirname(change.path), `.ldap-axi-${randomUUID()}.tmp`);
  try {
    await writeFile(temporary, change.after, { flag: "wx", mode: 0o600 });
    if (await read(change.path) !== change.before) throw new CliError("CONFIG_INVALID", "agent configuration changed during setup; rerun setup");
    await rename(temporary, change.path);
  } finally { await rm(temporary, { force: true }); }
}

export async function setup(flags: Readonly<Record<string, string | boolean>>, executable: string): Promise<{ data: Record<string, unknown>; help: string[]; exitCode: number }> {
  const app = flags.app;
  if (app !== "claude" && app !== "codex" && app !== "opencode") throw new CliError("VALIDATION_ERROR", "--app must be claude, codex, or opencode", ["Run `ldap-axi setup --help`"]);
  if (!flags.skill && !flags.hook) throw new CliError("VALIDATION_ERROR", "select --skill, --hook, or both", ["Run `ldap-axi setup --help`"]);
  if (flags.hook && app !== "claude") throw new CliError("VALIDATION_ERROR", "--hook currently supports --app claude only", ["Use --skill for Codex or OpenCode"]);
  const home = homedir();
  const root = app === "claude" ? process.env.CLAUDE_CONFIG_DIR || join(home, ".claude")
    : app === "codex" ? process.env.CODEX_HOME || join(home, ".codex")
    : process.env.OPENCODE_CONFIG_DIR || join(process.env.XDG_CONFIG_HOME && isAbsolute(process.env.XDG_CONFIG_HOME) ? process.env.XDG_CONFIG_HOME : join(home, ".config"), "opencode");
  if (!isAbsolute(root)) throw new CliError("CONFIG_INVALID", "agent configuration directory must be absolute");
  const changes: Change[] = [];
  if (flags.skill) {
    const path = join(root, "skills", "ldap-axi", "SKILL.md");
    const before = await read(path);
    const after = createSkillMarkdown() + SKILL_MARKER;
    if (before !== undefined && !before.endsWith(SKILL_MARKER) && before.replaceAll("\r\n", "\n") !== createSkillMarkdown()) throw new CliError("CONFIG_INVALID", "existing ldap-axi skill is not managed by setup", ["Move the custom skill before installing the shipped skill"]);
    changes.push({ path, before, after, kind: "skill" });
  }
  if (flags.hook) {
    const path = join(root, "settings.json");
    const before = await read(path);
    let settings: ObjectValue;
    try { settings = object(JSON.parse(before ?? "{}"), "Claude settings"); }
    catch (error) { if (error instanceof CliError) throw error; throw new CliError("CONFIG_INVALID", "Claude settings must be valid JSON; setup left them unchanged"); }
    const desired = repairHooks(settings, await hookCommand(executable));
    // Preserve bytes and mtime on a semantic no-op, including user formatting.
    const after = JSON.stringify(settings) === JSON.stringify(desired) ? before! : `${JSON.stringify(desired, null, 2)}\n`;
    changes.push({ path, before, after, kind: "hook" });
  }
  const stale = changes.filter(change => change.before !== change.after);
  if (!flags.check) for (const change of stale) await apply(change);
  return {
    data: { app, integrations: changes.map(change => ({ kind: change.kind, status: change.before === change.after ? "current" : flags.check ? change.before === undefined ? "missing" : "stale" : "installed" })) },
    help: flags.check && stale.length ? [`Run \`ldap-axi setup --app ${app}${flags.skill ? " --skill" : ""}${flags.hook ? " --hook" : ""}\` to install or repair`] : [],
    exitCode: flags.check && stale.length ? 1 : 0,
  };
}
