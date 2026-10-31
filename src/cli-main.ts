import { loadConfig, MAX_PAGE_SIZE, pageSizeForFlavor, paths, resolveSettings, validateTlsMaxVersion, type ResolvedSettings } from "./config.js";
import { SecretRedactor } from "./secrets.js";
import { CliError, type Directory, type Scope } from "./core.js";
import { openDirectory, validateFilter, type ConnectOptions } from "./directory/client.js";
import { parseAuthMode, parseProtectionRequirement, selectAuthPlan, type AuthPlan } from "./directory/auth.js";
import { authStatus } from "./auth.js";
import { serverReport } from "./server.js";
import { homeView, liveHome } from "./home.js";
import { skillInstallHint } from "./skill-hint.js";
import { setup, SETUP_HELP } from "./setup.js";
import { createKerberosProvider } from "./directory/gssapi.js";
import { assertAttributes, DEFAULT_ENTRY_ATTRIBUTES, searchEntries, showEntry } from "./entry.js";
import { render, renderError } from "./render.js";
import { commandHelp, completeSchema, flagHelp, groupListSchema, groupMembersSchema, groupShowSchema, selectFields, userGroupsSchema, userListSchema, userShowSchema, type CommandSchema } from "./schema.js";
import { listUsers, showUser, userGroups } from "./user.js";
import { listGroups, showGroup, groupMembers } from "./group.js";
import { listComputers, showComputer } from "./computer.js";
import { computerListSchema, computerShowSchema } from "./schema.js";

const commandGroups = {
  entry: ["search", "show"], user: ["list", "show", "groups"], group: ["list", "show", "members"],
  computer: ["list", "show"], auth: ["status"], profile: ["list"], config: ["path"],
} as const;
type CommandGroup = keyof typeof commandGroups;
type Command = CommandGroup | "home" | "setup" | "server" | "entry search" | "entry show" | "user list" | "user show" | "user groups" | "group list" | "group show" | "group members" | "computer list" | "computer show" | "auth status" | "profile list" | "config path";
export type RunDependencies = Readonly<{ openDirectory?: (options: ConnectOptions) => Promise<Directory>; executable?: string }>;
type Parsed = Readonly<{ command: Command; flags: Readonly<Record<string, string | boolean>>; positionals: readonly string[] }>;
const globalFlags = new Set(["help", "config", "url", "base", "start-tls", "ca-file", "ca-only", "tls-no-verify", "tls-max-version", "insecure-plaintext", "anonymous", "profile", "auth", "gssapi-service", "gssapi-protection"]);

const USER_LIST = completeSchema(userListSchema("ad"), userListSchema("ldapv3"));
const USER_SHOW = completeSchema(userShowSchema("ad"), userShowSchema("ldapv3"));
const USER_GROUPS = completeSchema(userGroupsSchema("ad"), userGroupsSchema("ldapv3"));
const GROUP_LIST = completeSchema(groupListSchema("ad"), groupListSchema("ldapv3"));
const GROUP_SHOW = completeSchema(groupShowSchema("ad"), groupShowSchema("ldapv3"));
const GROUP_MEMBERS = completeSchema(groupMembersSchema("ad"), groupMembersSchema("ldapv3"));
const COMPUTER_LIST = completeSchema(computerListSchema("ad"), computerListSchema("ldapv3"));
const COMPUTER_SHOW = completeSchema(computerShowSchema("ad"), computerShowSchema("ldapv3"));
const commandFlags: Record<Command, readonly string[]> = {
  entry: [], user: [], group: [], computer: [], auth: [], profile: [], config: [], server: [],
  home: ["session-start", "offline"], setup: ["app", "skill", "hook", "check"], "entry search": ["filter", "scope", "attributes", "page-size", "max-rows", "all"], "entry show": ["attributes", "page-size"],
  "user list": [...USER_LIST.booleanFlags, ...USER_LIST.valueFlags], "user show": [...USER_SHOW.booleanFlags, ...USER_SHOW.valueFlags], "user groups": [...USER_GROUPS.booleanFlags, ...USER_GROUPS.valueFlags],
  "group list": [...GROUP_LIST.booleanFlags, ...GROUP_LIST.valueFlags], "group show": [...GROUP_SHOW.booleanFlags, ...GROUP_SHOW.valueFlags], "group members": [...GROUP_MEMBERS.booleanFlags, ...GROUP_MEMBERS.valueFlags],
  "auth status": ["offline"],
  "computer list": [...COMPUTER_LIST.booleanFlags, ...COMPUTER_LIST.valueFlags], "computer show": [...COMPUTER_SHOW.booleanFlags, ...COMPUTER_SHOW.valueFlags],
  "profile list": [], "config path": [],
};
const FILTER_SHAPED_COMMANDS = new Set<Command>(["entry search", "user list", "group list", "computer list"]);
const IDENTIFIER_COMMANDS = new Set<Command>(["entry show", "user show", "user groups", "group show", "group members", "computer show"]);
const values = new Set(["app", "config", "url", "base", "ca-file", "tls-max-version", "profile", "auth", "gssapi-service", "gssapi-protection", "filter", "scope", "attributes", "page-size", "max-rows", "cursor", "name", "sam", "upn", "uid", "limit", "fields"]);
function flagGuard(name: string): void { if (/password|passwd|secret|token|credential|key/i.test(name)) throw new Error(`secret-shaped flag --${name} is forbidden`); }
for (const name of [...globalFlags, ...Object.values(commandFlags).flat()]) flagGuard(name);
function help(command: Parsed["command"]): string {
  if (command === "setup") return SETUP_HELP;
  if (command === "home") return `Read Active Directory and LDAPv3 directories.\nUsage: ldap-axi [flags]\nFlags:\n${flagHelp([...globalFlags, ...commandFlags.home])}\nVersion: --version, -v, -V (bare flags only; prints the package version without connecting).\nDefaults: configured home previews up to five immediate children using the selected authentication and TLS policy.\n--offline and --session-start show local status without a connection.\nFailed connections report an explicit offline status; no authentication fallback occurs.\nExamples:\n  ldap-axi --profile production\n  ldap-axi --offline`;
  if (command === "server") return `Report rootDSE capabilities and server flavor.\nUsage: ldap-axi server [flags]\nFlags:\n${flagHelp([...globalFlags])}\nDefaults: one selected authentication exchange; no search base is required.\nReports advertised facts only; absent optional attributes are omitted, and absent limit values are reported as not advertised.\nA configured flavor override is explicit alongside the detected flavor.\nExamples:\n  ldap-axi server --profile production\n  ldap-axi server --url ldaps://directory.example.test --anonymous`;
  if (Object.hasOwn(commandGroups, command)) return `Subcommands for ldap-axi ${command}:\n${commandGroups[command as CommandGroup].map(subcommand => `  ldap-axi ${command} ${subcommand} --help`).join("\n")}`;
  if (command === "config path") return "config path [--config <path>]\nShow the config path without reading credentials.\nDefaults: LDAP_AXI_CONFIG, then the platform config directory.\nExamples: ldap-axi config path\n          ldap-axi config path --config /private/config.json";
  if (command === "profile list") return "profile list [--config <path>]\nList configured profile names, URLs and auth modes without resolving secrets.\nDefaults: LDAP_AXI_CONFIG, then the platform config directory.\nExamples: ldap-axi profile list\n          ldap-axi profile list --config /private/config.json";
  if (command === "entry search") return `Search directory entries.\nUsage: ldap-axi entry search [flags]\nFlags:\n${flagHelp([...globalFlags, ...commandFlags[command]], {
    filter: "<RFC4515> LDAP filter (default: (objectClass=*))",
    attributes: "<name,...> requested attributes (default: objectClass,cn); wildcards are forbidden",
    "max-rows": "<n> maximum output rows (default: one page)",
    all: "read all pages; requires --max-rows (default: false)",
  })}\nDefaults: base is selected from config or the server naming contexts.\nAuthentication defaults to auto and attempts one ambient GSSAPI context; failures are terminal and never select a password.\nUse --auth simple to preserve a configured bind identity.\nThe URL scheme selects the GSSAPI transport: verified TLS binds with no SASL security layer, plain ldap:// with a mandatory confidentiality layer.\nFilters use RFC 4515 prefix operators & | !; escape literal * ( ) \\ and NUL in values.\nExamples:\n  ldap-axi entry search --filter "(objectClass=person)" --attributes cn,mail --max-rows 25\n  ldap-axi entry search --base "DC=example,DC=test" --scope one --all --max-rows 2000`;
  if (command === "entry show") return "entry show <dn> [--attributes a,b]\nDefaults to objectClass,cn; attribute wildcards are forbidden.\nAuthentication defaults to auto and attempts one ambient GSSAPI context; failures are terminal and never select a password.\nUse --auth simple to preserve a configured bind identity.\nThe URL scheme selects the GSSAPI transport: verified TLS binds with no SASL security layer, plain ldap:// with a mandatory confidentiality layer.\nUse --tls-max-version 1.2 for verified TLS 1.2-only directory endpoints.\nExample: ldap-axi entry show \"CN=Example,DC=example,DC=test\"";
  const schemas: Partial<Record<Command, readonly [CommandSchema, CommandSchema]>> = {
    "user list": [userListSchema("ad"), userListSchema("ldapv3")], "user show": [userShowSchema("ad"), userShowSchema("ldapv3")],
    "user groups": [userGroupsSchema("ad"), userGroupsSchema("ldapv3")], "group list": [groupListSchema("ad"), groupListSchema("ldapv3")],
    "group show": [groupShowSchema("ad"), groupShowSchema("ldapv3")], "group members": [groupMembersSchema("ad"), groupMembersSchema("ldapv3")],
    "computer list": [computerListSchema("ad"), computerListSchema("ldapv3")], "computer show": [computerShowSchema("ad"), computerShowSchema("ldapv3")],
  };
  const schema = schemas[command];
  if (schema) return commandHelp(command, schema[0], schema[1], [...globalFlags]);
  if (command === "auth status") return `Reports the one selected authentication contract: credential provenance, native provider status, mechanism, SASL security layer, and TLS channel binding.\nUsage: ldap-axi auth status [flags]\nFlags:\n${flagHelp([...globalFlags, ...commandFlags[command]])}\nDefaults: one bind against the configured URL, and the server-resolved identity when the server advertises RFC 4532 Who Am I.\n--offline reports the selection without contacting the directory and performs no bind.\nExamples:\n  ldap-axi auth status --profile production\n  ldap-axi auth status --offline --url ldaps://directory.example.test`;
  return "Read Active Directory and LDAPv3 directories.\nAuthentication defaults to auto and attempts one ambient GSSAPI context; failures are terminal and never select a password.\nUse --auth simple to preserve a configured bind identity.\nSelect configuration with --config <path> and --profile <name>.\nThe URL scheme selects the GSSAPI transport: verified TLS binds with no SASL security layer, plain ldap:// with a mandatory confidentiality layer.\nUse --tls-max-version 1.2 for verified TLS 1.2-only directory endpoints.\nCommands: entry search, entry show, user list, user show, user groups, group list, group show, group members, computer list, computer show, auth status, server, profile list, config path, setup";
}
export function parse(argv: readonly string[]): Parsed {
  let index = 0; let command: Command = "home";
  if (Object.hasOwn(commandGroups, argv[0] ?? "") && argv[1] === "--help") { command = argv[0] as CommandGroup; index = 1; }
  else if (argv[0] === "entry") { if (argv[1] === "search" || argv[1] === "show") { command = `entry ${argv[1]}` as Command; index = 2; } else throw new CliError("VALIDATION_ERROR", "unknown entry subcommand", ["Run `ldap-axi entry --help`"]); }
  else if (argv[0] === "user") { if (argv[1] === "list" || argv[1] === "show" || argv[1] === "groups") { command = `user ${argv[1]}` as Command; index = 2; } else throw new CliError("VALIDATION_ERROR", "unknown user subcommand", ["Run `ldap-axi user --help`"]); }
  else if (argv[0] === "group") { if (argv[1] === "list" || argv[1] === "show" || argv[1] === "members") { command = `group ${argv[1]}` as Command; index = 2; } else throw new CliError("VALIDATION_ERROR", "unknown group subcommand", ["Run `ldap-axi group --help`"]); }
  else if (argv[0] === "computer") { if (argv[1] === "list" || argv[1] === "show") { command = `computer ${argv[1]}` as Command; index = 2; } else throw new CliError("VALIDATION_ERROR", "unknown computer subcommand", ["Run `ldap-axi computer --help`"]); }
  else if (argv[0] === "auth") { if (argv[1] === "status") { command = "auth status"; index = 2; } else throw new CliError("VALIDATION_ERROR", "unknown auth subcommand", ["Run `ldap-axi auth status --help`"]); }
  else if (argv[0] === "profile" || argv[0] === "config") { if (argv[0] === "profile" && argv[1] === "list" || argv[0] === "config" && argv[1] === "path") { command = `${argv[0]} ${argv[1]}` as Command; index = 2; } else throw new CliError("VALIDATION_ERROR", "unknown configuration subcommand", ["Run `ldap-axi profile list --help` or `ldap-axi config path --help`"]); }
  else if (argv[0] === "server") { command = "server"; index = 1; }
  else if (argv[0] === "setup") { command = "setup"; index = 1; }
  else if (argv[0]?.startsWith("-")) command = "home";
  const flags: Record<string, string | boolean> = {}; const positionals: string[] = [];
  const allowedFlags = command === "setup" ? ["help", ...commandFlags.setup] : [...globalFlags, ...commandFlags[command]];
  const validFlags = `valid flags for \`${command}\`: ${allowedFlags.map(value => `--${value}`).join(", ")}`;
  if (command === "home" && argv.length && !argv[0].startsWith("-")) throw new CliError("VALIDATION_ERROR", `unknown command ${argv[0]}`, [validFlags]);
  for (; index < argv.length; index++) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      if (token.startsWith("-")) throw new CliError("VALIDATION_ERROR", `unknown flag ${token} for \`${command}\``, [validFlags]);
      positionals.push(token); continue;
    }
    const [name, inline] = token.slice(2).split("=", 2);
    if (name === "cursor") throw new CliError("VALIDATION_ERROR", "--cursor is out of scope for ldap-axi v1", ["Use --all --max-rows <n> for a bounded in-process paged read"]);
    if (!allowedFlags.includes(name)) throw new CliError("VALIDATION_ERROR", `unknown flag --${name} for \`${command}\``, [validFlags]);
    if (values.has(name)) {
      const value = inline ?? argv[++index];
      if (value === undefined || value.startsWith("--") || value === "" && name !== "base") throw new CliError("VALIDATION_ERROR", `--${name} requires a value`);
      flags[name] = value;
    } else flags[name] = true;
  }
  if (command === "setup") {
    if (argv.some(token => /^--(?:skill|hook|check|help)=/.test(token))) throw new CliError("VALIDATION_ERROR", "setup boolean flags accept no value", ["Pass --skill, --hook, or --check without =true or =false"]);
    if (positionals.length) throw new CliError("VALIDATION_ERROR", "setup accepts no positional arguments");
  }
  if (command === "home" && positionals.length) throw new CliError("VALIDATION_ERROR", `unexpected home argument ${positionals[0]}`, [validFlags]);
  if (flags.help) return { command, flags, positionals };
  if (command === "server" && positionals.length) throw new CliError("VALIDATION_ERROR", "server accepts no positional arguments");
  if (typeof flags.auth === "string") parseAuthMode(flags.auth, "--auth");
  if (typeof flags["gssapi-protection"] === "string") parseProtectionRequirement(flags["gssapi-protection"], "--gssapi-protection");
  if (typeof flags["tls-max-version"] === "string") validateTlsMaxVersion(flags["tls-max-version"]);
  if (flags.anonymous && (flags.auth !== undefined || flags["gssapi-service"] !== undefined || flags["gssapi-protection"] !== undefined)) throw new CliError("VALIDATION_ERROR", "--anonymous cannot be combined with --auth, --gssapi-service, or --gssapi-protection");
  if (flags.base === "" && (command !== "entry search" || (flags.scope ?? "sub") !== "base")) throw new CliError("VALIDATION_ERROR", '--base "" requires --scope base for entry search');
  if (FILTER_SHAPED_COMMANDS.has(command) && flags.all && !flags["max-rows"] && !flags.limit) throw new CliError("VALIDATION_ERROR", "--all requires --max-rows (or --limit) to keep output bounded");
  if ((command === "entry show" || IDENTIFIER_COMMANDS.has(command)) && positionals.length !== 1) throw new CliError("VALIDATION_ERROR", `${command} requires exactly one identifier or distinguished name`);
  if ((FILTER_SHAPED_COMMANDS.has(command) || command === "auth status" || command === "profile list" || command === "config path") && positionals.length) throw new CliError("VALIDATION_ERROR", `${command} accepts no positional arguments`);
  validateRequest(command, flags); return { command, flags, positionals };
}
function validateRequest(command: Parsed["command"], flags: Readonly<Record<string, string | boolean>>): void {
  if (FILTER_SHAPED_COMMANDS.has(command)) { const scope = (flags.scope ?? "sub") as string; if (!["base", "one", "sub"].includes(scope)) throw new CliError("VALIDATION_ERROR", "--scope must be base, one, or sub"); if (typeof flags.filter === "string") validateFilter(flags.filter); }
  if (command === "user list" && flags.disabled && flags.enabled) throw new CliError("VALIDATION_ERROR", "--disabled and --enabled cannot be combined");
  if (command !== "home" && typeof flags.attributes === "string") assertAttributes(flags.attributes.split(","));
  if (typeof flags.fields === "string") {
    const schemas: Partial<Record<Command, CommandSchema>> = { "user list": USER_LIST, "user show": USER_SHOW, "user groups": USER_GROUPS, "group list": GROUP_LIST, "group show": GROUP_SHOW, "group members": GROUP_MEMBERS, "computer list": COMPUTER_LIST, "computer show": COMPUTER_SHOW };
    const schema = schemas[command];
    if (schema) selectFields(schema, flags.fields.split(","));
  }
  if (flags["page-size"]) numberFlag(flags, "page-size", 500, MAX_PAGE_SIZE);
  if (flags["max-rows"]) numberFlag(flags, "max-rows", 1);
  if (flags.limit) numberFlag(flags, "limit", 1);
}
function numberFlag(flags: Readonly<Record<string, string | boolean>>, name: string, fallback: number, maximum?: number): number { const text = flags[name]; if (text === undefined) return fallback; const value = Number(text); if (!Number.isInteger(value) || value <= 0 || (maximum !== undefined && value > maximum)) throw new CliError("VALIDATION_ERROR", maximum === undefined ? `--${name} must be a positive integer` : `--${name} must be an integer from 1 to ${maximum}`); return value; }
function str(value: string | boolean | undefined): string | undefined { return typeof value === "string" ? value : undefined; }
function list(value: string | boolean | undefined): string[] | undefined { return typeof value === "string" ? value.split(",") : undefined; }
function resolvedSettings(parsed: Parsed, redactor: SecretRedactor): Promise<ResolvedSettings> {
  return resolveSettings({
    config: str(parsed.flags.config),
    url: typeof parsed.flags.url === "string" ? parsed.flags.url : undefined,
    base: typeof parsed.flags.base === "string" ? parsed.flags.base : undefined,
    pageSize: parsed.flags["page-size"] ? numberFlag(parsed.flags, "page-size", 500, MAX_PAGE_SIZE) : undefined,
    caFile: typeof parsed.flags["ca-file"] === "string" ? parsed.flags["ca-file"] : undefined,
    startTls: parsed.flags["start-tls"] ? true : undefined,
    tlsMaxVersion: typeof parsed.flags["tls-max-version"] === "string" ? validateTlsMaxVersion(parsed.flags["tls-max-version"]) : undefined,
    profile: typeof parsed.flags.profile === "string" ? parsed.flags.profile : undefined,
    auth: typeof parsed.flags.auth === "string" ? parseAuthMode(parsed.flags.auth, "--auth") : undefined,
    gssapiService: typeof parsed.flags["gssapi-service"] === "string" ? parsed.flags["gssapi-service"] : undefined,
    gssapiProtection: typeof parsed.flags["gssapi-protection"] === "string" ? parseProtectionRequirement(parsed.flags["gssapi-protection"], "--gssapi-protection") : undefined,
  }, redactor);
}
function warningFor(settings: ResolvedSettings, parsed: Parsed): string {
  if (!settings.url) return "";
  const plaintext = /^ldap:/i.test(settings.url) && !settings.startTls;
  const simpleOrAnonymous = settings.auth === "simple" || parsed.flags.anonymous;
  const authorizedPlaintext = plaintext && parsed.flags["insecure-plaintext"] && simpleOrAnonymous;
  return `${authorizedPlaintext ? "warning: bind credentials and queries are sent in cleartext over plaintext LDAP\n" : ""}${!plaintext && parsed.flags["tls-no-verify"] && simpleOrAnonymous ? "warning: TLS certificate verification is disabled\n" : ""}`;
}
function caMode(settings: ResolvedSettings, parsed: Parsed): "default" | "appended" | "replacement" {
  return settings.caFile ? (parsed.flags["ca-only"] ? "replacement" : "appended") : "default";
}
async function authPlanFor(parsed: Parsed, settings: ResolvedSettings): Promise<AuthPlan> {
  if (parsed.flags.anonymous && settings.credentialsConfigured) throw new CliError("VALIDATION_ERROR", "--anonymous cannot be combined with configured simple credentials");
  if (!settings.url) throw new CliError("VALIDATION_ERROR", "directory URL is required", ["Set LDAP_AXI_URL or pass --url ldaps://server:636"]);
  return selectAuthPlan({
    requested: settings.auth,
    url: settings.url,
    credentials: settings.credentials,
    credentialSource: settings.credentialSource,
    serviceOverride: settings.gssapiService,
    protection: settings.gssapiProtection,
    startTls: settings.startTls,
    anonymous: Boolean(parsed.flags.anonymous),
    authExplicit: settings.authSource !== "default",
    provider: settings.auth === "simple" ? undefined : createKerberosProvider(),
  });
}
function connectOptions(parsed: Parsed, settings: ResolvedSettings, authPlan: AuthPlan): ConnectOptions {
  return { url: settings.url!, startTls: settings.startTls, caFile: settings.caFile, caOnly: Boolean(parsed.flags["ca-only"]), tlsNoVerify: Boolean(parsed.flags["tls-no-verify"]), tlsMaxVersion: settings.tlsMaxVersion, insecurePlaintext: Boolean(parsed.flags["insecure-plaintext"]), authPlan, anonymous: Boolean(parsed.flags.anonymous) };
}
async function connection(parsed: Parsed, settings: ResolvedSettings, open: (options: ConnectOptions) => Promise<Directory>): Promise<{ directory: Directory; base: string; pageSize: number; tlsVerified: boolean; plaintext: boolean }> {
  const authPlan = await authPlanFor(parsed, settings);
  const plaintext = /^ldap:/i.test(settings.url!) && !settings.startTls;
  const directory = await open(connectOptions(parsed, settings, authPlan));
  let base = settings.base;
  if (base === undefined) { const root = await directory.rootDSE(); const contexts = root.attributes.namingContexts ?? []; base = root.flavor === "ad" ? root.attributes.defaultNamingContext?.[0] : undefined; base ??= contexts.length === 1 ? contexts[0] : undefined; if (!base) { await directory.close(); throw new CliError("VALIDATION_ERROR", "several naming contexts are available and none is a default for this server", contexts.length ? contexts.map(context => `Pass --base ${context}`) : ["Pass --base <dn>"]); } }
  return { directory, base, pageSize: pageSizeForFlavor(settings.pageSize, directory.flavor), tlsVerified: !plaintext && !parsed.flags["tls-no-verify"], plaintext };
}
export async function run(argv: readonly string[], dependencies: RunDependencies = {}): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const redactor = new SecretRedactor();
  const result = await executeRun(argv, dependencies, redactor);
  const deprecated = process.env.LDAP_AXI_CONFIG_FILE !== undefined && process.env.LDAP_AXI_CONFIG === undefined && !argv.includes("--config") && !argv.some(value => value.startsWith("--config="));
  return { ...result, stderr: redactor.text(`${deprecated ? "warning: LDAP_AXI_CONFIG_FILE is deprecated for one minor release; use LDAP_AXI_CONFIG\n" : ""}${result.stderr}`) };
}
async function executeRun(argv: readonly string[], dependencies: RunDependencies, redactor: SecretRedactor): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const open = dependencies.openDirectory ?? openDirectory;
  let transportWarning = "";
  try {
    const parsed = parse(argv); if (parsed.flags.help) return { stdout: `${help(parsed.command)}\n`, stderr: "", exitCode: 0 };
    if (parsed.command === "setup") {
      try {
        const result = await setup(parsed.flags, dependencies.executable ?? process.argv[1]);
        return { stdout: render(result.data, result.help, redactor), stderr: "", exitCode: result.exitCode };
      } catch (error) {
        if (error instanceof CliError) throw error;
        throw new CliError("CONFIG_INVALID", "cannot read or write the selected agent integration", ["Check the agent configuration directory permissions and that the current CLI installation still exists"]);
      }
    }
    if (parsed.command === "config path") return { stdout: render({ config: paths(str(parsed.flags.config)).config }, [], redactor), stderr: "", exitCode: 0 };
    if (parsed.command === "profile list") {
      const loaded = await loadConfig(str(parsed.flags.config));
      const profiles = Object.entries(loaded.config?.profiles ?? {}).map(([name, profile]) => ({ name, url: profile.url, auth: profile.auth ?? "auto" }));
      return { stdout: render(profiles.length ? { profiles } : { profiles: "0 profiles configured" }, ["Run `ldap-axi auth status --offline --profile <name>` to inspect a profile"], redactor), stderr: "", exitCode: 0 };
    }
    if (parsed.command === "home") {
      const settings = await resolvedSettings(parsed, redactor);
      const home = homeView(dependencies.executable ?? process.argv[1], settings.url, settings.credentialsConfigured);
      home.data.connection = "offline";
      home.data.offline_reason = !settings.url ? "unconfigured" : parsed.flags["session-start"] ? "session-start" : "requested";
      if (settings.url && !parsed.flags.offline && !parsed.flags["session-start"]) {
        try {
          const plan = await authPlanFor(parsed, settings);
          transportWarning = warningFor(settings, parsed);
          const directory = await open({ ...connectOptions(parsed, settings, plan), timeoutMs: 3000 });
          try {
            const context = await liveHome(directory, settings.base);
            Object.assign(home.data, context.data, { connection: "live", tls_verified: !/^ldap:/i.test(settings.url) || settings.startTls ? !parsed.flags["tls-no-verify"] : false });
            delete home.data.offline_reason;
            home.help.unshift(...context.help);
          } finally { await directory.close(); }
        } catch (error) {
          if (!(error instanceof CliError) || error.exitCode === 2) throw error;
          home.data.offline_reason = error.code;
          home.data.directory_error = error.message;
          home.help.unshift(...error.help, "Run `ldap-axi --offline` for local status or `ldap-axi auth status` to diagnose the connection");
        }
      }
      const hint = argv.length === 0 ? skillInstallHint() : undefined;
      if (hint) home.help.push(hint);
      return { stdout: render(home.data, home.help, redactor), stderr: transportWarning, exitCode: 0 };
    }
    if (parsed.command === "auth status") {
      const settings = await resolvedSettings(parsed, redactor);
      const plan = settings.url ? await authPlanFor(parsed, settings) : undefined;
      const input = { url: settings.url, startTls: settings.startTls, tlsNoVerify: Boolean(parsed.flags["tls-no-verify"]), caMode: caMode(settings, parsed), authMode: settings.auth, authSource: settings.authSource, plan, credentialSource: settings.credentialSource, credentialsPermissions: settings.credentialsPermissions, profile: settings.profile, configPath: settings.configPath, bindPasswordSource: settings.bindPasswordSource };
      if (!plan || parsed.flags.offline) { const offline = await authStatus(input); return { stdout: render(offline.data, offline.help, redactor), stderr: "", exitCode: 0 }; }
      transportWarning = warningFor(settings, parsed);
      const directory = await open(connectOptions(parsed, settings, plan));
      try { const result = await authStatus(input, directory); return { stdout: render(result.data, result.help, redactor), stderr: transportWarning, exitCode: 0 }; }
      finally { await directory.close(); }
    }
    const settings = await resolvedSettings(parsed, redactor);
    transportWarning = warningFor(settings, parsed);
    if (parsed.command === "server") {
      const plan = await authPlanFor(parsed, settings);
      const plaintext = /^ldap:/i.test(settings.url!) && !settings.startTls;
      const directory = await open(connectOptions(parsed, settings, plan));
      try { const result = await serverReport(directory, settings.flavor); return { stdout: render({ ...result.data, tls_verified: !plaintext && !parsed.flags["tls-no-verify"] }, result.help, redactor), stderr: transportWarning, exitCode: 0 }; }
      finally { await directory.close(); }
    }
    const opened = await connection(parsed, settings, open); const flavor = opened.directory.flavor;
    try {
      const maxRows = parsed.flags["max-rows"] ? numberFlag(parsed.flags, "max-rows", 1) : undefined;
      const limit = parsed.flags.limit ? numberFlag(parsed.flags, "limit", 1) : undefined;
      const scope = (parsed.flags.scope ?? "sub") as Scope;
      let result: { data: Record<string, unknown>; help: string[] };
      if (parsed.command === "entry search") { if (!["base", "one", "sub"].includes(scope)) throw new CliError("VALIDATION_ERROR", "--scope must be base, one, or sub"); result = await searchEntries(opened.directory, { base: opened.base, filter: typeof parsed.flags.filter === "string" ? parsed.flags.filter : "(objectClass=*)", scope, attributes: typeof parsed.flags.attributes === "string" ? parsed.flags.attributes.split(",") : DEFAULT_ENTRY_ATTRIBUTES, pageSize: opened.pageSize, maxRows, all: Boolean(parsed.flags.all), redactor }); }
      else if (parsed.command === "entry show") result = await showEntry(opened.directory, parsed.positionals[0], opened.pageSize, list(parsed.flags.attributes) ?? DEFAULT_ENTRY_ATTRIBUTES, redactor);
      else if (parsed.command === "user list") result = await listUsers(opened.directory, { base: opened.base, flavor, pageSize: opened.pageSize, maxRows, limit, all: Boolean(parsed.flags.all), scope, name: str(parsed.flags.name), sam: str(parsed.flags.sam), upn: str(parsed.flags.upn), uid: str(parsed.flags.uid), disabled: Boolean(parsed.flags.disabled), enabled: Boolean(parsed.flags.enabled), locked: Boolean(parsed.flags.locked), filter: str(parsed.flags.filter), fields: list(parsed.flags.fields), attributes: list(parsed.flags.attributes), redactor });
      else if (parsed.command === "user show") result = await showUser(opened.directory, { base: opened.base, flavor, identifier: parsed.positionals[0], pageSize: opened.pageSize, fields: list(parsed.flags.fields), attributes: list(parsed.flags.attributes), redactor });
      else if (parsed.command === "user groups") result = await userGroups(opened.directory, { base: opened.base, flavor, identifier: parsed.positionals[0], pageSize: opened.pageSize, maxRows, nested: Boolean(parsed.flags.nested), fields: list(parsed.flags.fields) });
      else if (parsed.command === "group list") result = await listGroups(opened.directory, { base: opened.base, flavor, pageSize: opened.pageSize, maxRows, limit, all: Boolean(parsed.flags.all), scope, name: str(parsed.flags.name), sam: str(parsed.flags.sam), filter: str(parsed.flags.filter), fields: list(parsed.flags.fields), attributes: list(parsed.flags.attributes), redactor });
      else if (parsed.command === "group show") result = await showGroup(opened.directory, { base: opened.base, flavor, identifier: parsed.positionals[0], pageSize: opened.pageSize, fields: list(parsed.flags.fields), attributes: list(parsed.flags.attributes), redactor });
      else if (parsed.command === "computer list") result = await listComputers(opened.directory, { base: opened.base, flavor, pageSize: opened.pageSize, maxRows, limit, all: Boolean(parsed.flags.all), scope, name: str(parsed.flags.name), sam: str(parsed.flags.sam), filter: str(parsed.flags.filter), fields: list(parsed.flags.fields), attributes: list(parsed.flags.attributes), redactor });
      else if (parsed.command === "computer show") result = await showComputer(opened.directory, { base: opened.base, flavor, identifier: parsed.positionals[0], pageSize: opened.pageSize, fields: list(parsed.flags.fields), attributes: list(parsed.flags.attributes), redactor });
      else result = await groupMembers(opened.directory, { base: opened.base, flavor, identifier: parsed.positionals[0], pageSize: opened.pageSize, maxRows, nested: Boolean(parsed.flags.nested), fields: list(parsed.flags.fields) });
      return { stdout: render({ ...result.data, tls_verified: opened.tlsVerified }, result.help, redactor), stderr: transportWarning, exitCode: 0 };
    } finally { await opened.directory.close(); }
  } catch (error) { return { ...renderError(error, redactor), stderr: transportWarning }; }
}
