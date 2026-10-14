#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { loadConfig, MAX_PAGE_SIZE, pageSizeForFlavor, paths, resolveSettings, validateTlsMaxVersion, type ResolvedSettings } from "./config.js";
import { SecretRedactor } from "./secrets.js";
import { CliError, type Directory, type Scope } from "./core.js";
import { openDirectory, validateFilter, type ConnectOptions } from "./directory/client.js";
import { parseAuthMode, parseProtectionRequirement, selectAuthPlan, type AuthPlan } from "./directory/auth.js";
import { authStatus } from "./auth.js";
import { homeView } from "./home.js";
import { createKerberosProvider } from "./directory/gssapi.js";
import { assertAttributes, DEFAULT_ENTRY_ATTRIBUTES, searchEntries, showEntry } from "./entry.js";
import { render, renderError } from "./render.js";
import { commandHelp, completeSchema, groupListSchema, groupMembersSchema, groupShowSchema, selectFields, userGroupsSchema, userListSchema, userShowSchema, type CommandSchema } from "./schema.js";
import { listUsers, showUser, userGroups } from "./user.js";
import { listGroups, showGroup, groupMembers } from "./group.js";

type Command = "home" | "entry search" | "entry show" | "user list" | "user show" | "user groups" | "group list" | "group show" | "group members" | "auth status" | "profile list" | "config path";
export type RunDependencies = Readonly<{ openDirectory?: (options: ConnectOptions) => Promise<Directory>; executable?: string }>;
type Parsed = Readonly<{ command: Command; flags: Readonly<Record<string, string | boolean>>; positionals: readonly string[] }>;
const globalFlags = new Set(["help", "config", "url", "base", "start-tls", "ca-file", "ca-only", "tls-no-verify", "tls-max-version", "insecure-plaintext", "anonymous", "profile", "auth", "gssapi-service", "gssapi-protection"]);

const USER_LIST = completeSchema(userListSchema("ad"), userListSchema("ldapv3"));
const USER_SHOW = completeSchema(userShowSchema("ad"), userShowSchema("ldapv3"));
const USER_GROUPS = completeSchema(userGroupsSchema("ad"), userGroupsSchema("ldapv3"));
const GROUP_LIST = completeSchema(groupListSchema("ad"), groupListSchema("ldapv3"));
const GROUP_SHOW = completeSchema(groupShowSchema("ad"), groupShowSchema("ldapv3"));
const GROUP_MEMBERS = completeSchema(groupMembersSchema("ad"), groupMembersSchema("ldapv3"));
const commandFlags: Record<Command, readonly string[]> = {
  home: [], "entry search": ["filter", "scope", "attributes", "page-size", "max-rows", "all"], "entry show": ["attributes", "page-size"],
  "user list": [...USER_LIST.booleanFlags, ...USER_LIST.valueFlags], "user show": [...USER_SHOW.booleanFlags, ...USER_SHOW.valueFlags], "user groups": [...USER_GROUPS.booleanFlags, ...USER_GROUPS.valueFlags],
  "group list": [...GROUP_LIST.booleanFlags, ...GROUP_LIST.valueFlags], "group show": [...GROUP_SHOW.booleanFlags, ...GROUP_SHOW.valueFlags], "group members": [...GROUP_MEMBERS.booleanFlags, ...GROUP_MEMBERS.valueFlags],
  "auth status": ["offline"],
  "profile list": [], "config path": [],
};
const FILTER_SHAPED_COMMANDS = new Set<Command>(["entry search", "user list", "group list"]);
const IDENTIFIER_COMMANDS = new Set<Command>(["entry show", "user show", "user groups", "group show", "group members"]);
const values = new Set(["config", "url", "base", "ca-file", "tls-max-version", "profile", "auth", "gssapi-service", "gssapi-protection", "filter", "scope", "attributes", "page-size", "max-rows", "cursor", "name", "sam", "upn", "uid", "limit", "fields"]);
function flagGuard(name: string): void { if (/password|passwd|secret|token|credential|key/i.test(name)) throw new Error(`secret-shaped flag --${name} is forbidden`); }
for (const name of [...globalFlags, ...Object.values(commandFlags).flat()]) flagGuard(name);
function help(command: Parsed["command"]): string {
  if (command === "config path") return "config path [--config <path>]\nShow the config path without reading credentials.\nDefaults: LDAP_AXI_CONFIG, then the platform config directory.\nExamples: ldap-axi config path\n          ldap-axi config path --config /private/config.json";
  if (command === "profile list") return "profile list [--config <path>]\nList configured profile names, URLs and auth modes without resolving secrets.\nDefaults: LDAP_AXI_CONFIG, then the platform config directory.\nExamples: ldap-axi profile list\n          ldap-axi profile list --config /private/config.json";
  if (command === "entry search") return "entry search [--base <dn>] [--filter <RFC4515>] [--scope base|one|sub] [--attributes a,b] [--max-rows n] [--all]\nDefaults to objectClass,cn; attribute wildcards are forbidden.\nAuthentication defaults to auto and attempts one ambient GSSAPI context; failures are terminal and never select a password.\nUse --auth simple to preserve a configured bind identity.\nThe URL scheme selects the GSSAPI transport: verified TLS binds with no SASL security layer, plain ldap:// with a mandatory confidentiality layer.\nUse --tls-max-version 1.2 for verified TLS 1.2-only directory endpoints.\nExamples: ldap-axi entry search --filter \"(objectClass=person)\"\nFilter values must escape * ( ) \\ and NUL.";
  if (command === "entry show") return "entry show <dn> [--attributes a,b]\nDefaults to objectClass,cn; attribute wildcards are forbidden.\nAuthentication defaults to auto and attempts one ambient GSSAPI context; failures are terminal and never select a password.\nUse --auth simple to preserve a configured bind identity.\nThe URL scheme selects the GSSAPI transport: verified TLS binds with no SASL security layer, plain ldap:// with a mandatory confidentiality layer.\nUse --tls-max-version 1.2 for verified TLS 1.2-only directory endpoints.\nExample: ldap-axi entry show \"CN=Example,DC=example,DC=test\"";
  const schemas: Partial<Record<Command, readonly [CommandSchema, CommandSchema]>> = {
    "user list": [userListSchema("ad"), userListSchema("ldapv3")], "user show": [userShowSchema("ad"), userShowSchema("ldapv3")],
    "user groups": [userGroupsSchema("ad"), userGroupsSchema("ldapv3")], "group list": [groupListSchema("ad"), groupListSchema("ldapv3")],
    "group show": [groupShowSchema("ad"), groupShowSchema("ldapv3")], "group members": [groupMembersSchema("ad"), groupMembersSchema("ldapv3")],
  };
  const schema = schemas[command];
  if (schema) return commandHelp(command, schema[0], schema[1], [...globalFlags]);
  if (command === "auth status") return "auth status [--offline]\nReports the one selected authentication contract: credential provenance, native provider status, mechanism, SASL security layer, and TLS channel binding.\nDefaults: one bind against the configured URL, and the server-resolved identity when the server advertises RFC 4532 Who Am I.\n--offline reports the selection without contacting the directory and performs no bind.\nExamples: ldap-axi auth status\n          ldap-axi auth status --offline --url ldaps://dc01.example.com";
  return "Read Active Directory and LDAPv3 directories.\nAuthentication defaults to auto and attempts one ambient GSSAPI context; failures are terminal and never select a password.\nUse --auth simple to preserve a configured bind identity.\nSelect configuration with --config <path> and --profile <name>.\nThe URL scheme selects the GSSAPI transport: verified TLS binds with no SASL security layer, plain ldap:// with a mandatory confidentiality layer.\nUse --tls-max-version 1.2 for verified TLS 1.2-only directory endpoints.\nCommands: entry search, entry show, user list, user show, user groups, group list, group show, group members, auth status, profile list, config path";
}
export function parse(argv: readonly string[]): Parsed {
  let index = 0; let command: Command = "home";
  if (argv[0] === "entry") { if (argv[1] === "search" || argv[1] === "show") { command = `entry ${argv[1]}` as Command; index = 2; } else throw new CliError("VALIDATION_ERROR", "unknown entry subcommand", ["Run `ldap-axi entry --help`"]); }
  else if (argv[0] === "user") { if (argv[1] === "list" || argv[1] === "show" || argv[1] === "groups") { command = `user ${argv[1]}` as Command; index = 2; } else throw new CliError("VALIDATION_ERROR", "unknown user subcommand", ["Run `ldap-axi user --help`"]); }
  else if (argv[0] === "group") { if (argv[1] === "list" || argv[1] === "show" || argv[1] === "members") { command = `group ${argv[1]}` as Command; index = 2; } else throw new CliError("VALIDATION_ERROR", "unknown group subcommand", ["Run `ldap-axi group --help`"]); }
  else if (argv[0] === "auth") { if (argv[1] === "status") { command = "auth status"; index = 2; } else throw new CliError("VALIDATION_ERROR", "unknown auth subcommand", ["Run `ldap-axi auth status --help`"]); }
  else if (argv[0] === "profile" || argv[0] === "config") { if (argv[0] === "profile" && argv[1] === "list" || argv[0] === "config" && argv[1] === "path") { command = `${argv[0]} ${argv[1]}` as Command; index = 2; } else throw new CliError("VALIDATION_ERROR", "unknown configuration subcommand", ["Run `ldap-axi profile list --help` or `ldap-axi config path --help`"]); }
  else if (argv[0]?.startsWith("-")) command = "home";
  else if (argv.length) throw new CliError("VALIDATION_ERROR", `unknown command ${argv[0]}`, ["Run `ldap-axi --help`"]);
  const flags: Record<string, string | boolean> = {}; const positionals: string[] = [];
  for (; index < argv.length; index++) { const token = argv[index]; if (!token.startsWith("--")) { positionals.push(token); continue; } const [name, inline] = token.slice(2).split("=", 2); if (name === "cursor") throw new CliError("VALIDATION_ERROR", "--cursor is out of scope for ldap-axi v1", ["Use --all --max-rows <n> for a bounded in-process paged read"]); if (!globalFlags.has(name) && !commandFlags[command].includes(name)) throw new CliError("VALIDATION_ERROR", `unknown flag --${name} for \`${command}\``, [`valid flags for \`${command}\`: ${[...globalFlags, ...commandFlags[command]].map(value => `--${value}`).join(", ")}`]); if (values.has(name)) { const value = inline ?? argv[++index]; if (value === undefined || value.startsWith("--") || value === "" && name !== "base") throw new CliError("VALIDATION_ERROR", `--${name} requires a value`); flags[name] = value; } else flags[name] = true; }
  if (flags.help) return { command, flags, positionals };
  if (typeof flags.auth === "string") parseAuthMode(flags.auth, "--auth");
  if (typeof flags["gssapi-protection"] === "string") parseProtectionRequirement(flags["gssapi-protection"], "--gssapi-protection");
  if (typeof flags["tls-max-version"] === "string") validateTlsMaxVersion(flags["tls-max-version"]);
  if (flags.anonymous && (flags.auth !== undefined || flags["gssapi-service"] !== undefined || flags["gssapi-protection"] !== undefined)) throw new CliError("VALIDATION_ERROR", "--anonymous cannot be combined with --auth, --gssapi-service, or --gssapi-protection");
  if (flags.base === "" && (command !== "entry search" || (flags.scope ?? "sub") !== "base")) throw new CliError("VALIDATION_ERROR", '--base "" requires --scope base for entry search');
  if ((command === "entry search" || command === "user list" || command === "group list") && flags.all && !flags["max-rows"] && !flags.limit) throw new CliError("VALIDATION_ERROR", "--all requires --max-rows (or --limit) to keep output bounded");
  if ((command === "entry show" || IDENTIFIER_COMMANDS.has(command)) && positionals.length !== 1) throw new CliError("VALIDATION_ERROR", `${command} requires exactly one identifier or distinguished name`);
  if ((command === "entry search" || command === "user list" || command === "group list" || command === "auth status" || command === "profile list" || command === "config path") && positionals.length) throw new CliError("VALIDATION_ERROR", `${command} accepts no positional arguments`);
  validateRequest(command, flags); return { command, flags, positionals };
}
function validateRequest(command: Parsed["command"], flags: Readonly<Record<string, string | boolean>>): void {
  if (FILTER_SHAPED_COMMANDS.has(command)) { const scope = (flags.scope ?? "sub") as string; if (!["base", "one", "sub"].includes(scope)) throw new CliError("VALIDATION_ERROR", "--scope must be base, one, or sub"); if (typeof flags.filter === "string") validateFilter(flags.filter); }
  if (command === "user list" && flags.disabled && flags.enabled) throw new CliError("VALIDATION_ERROR", "--disabled and --enabled cannot be combined");
  if (command !== "home" && typeof flags.attributes === "string") assertAttributes(flags.attributes.split(","));
  if (typeof flags.fields === "string") {
    const schemas: Partial<Record<Command, CommandSchema>> = { "user list": USER_LIST, "user show": USER_SHOW, "user groups": USER_GROUPS, "group list": GROUP_LIST, "group show": GROUP_SHOW, "group members": GROUP_MEMBERS };
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
    if (parsed.command === "config path") return { stdout: render({ config: paths(str(parsed.flags.config)).config }, [], redactor), stderr: "", exitCode: 0 };
    if (parsed.command === "profile list") {
      const loaded = await loadConfig(str(parsed.flags.config));
      const profiles = Object.entries(loaded.config?.profiles ?? {}).map(([name, profile]) => ({ name, url: profile.url, auth: profile.auth ?? "auto" }));
      return { stdout: render(profiles.length ? { profiles } : { profiles: "0 profiles configured" }, ["Run `ldap-axi auth status --offline --profile <name>` to inspect a profile"], redactor), stderr: "", exitCode: 0 };
    }
    if (parsed.command === "home") { const settings = await resolvedSettings(parsed, redactor); const home = homeView(dependencies.executable ?? process.argv[1], settings.url, settings.credentialsConfigured); return { stdout: render(home.data, home.help, redactor), stderr: "", exitCode: 0 }; }
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
      else result = await groupMembers(opened.directory, { base: opened.base, flavor, identifier: parsed.positionals[0], pageSize: opened.pageSize, maxRows, nested: Boolean(parsed.flags.nested), fields: list(parsed.flags.fields) });
      return { stdout: render({ ...result.data, tls_verified: opened.tlsVerified }, result.help, redactor), stderr: transportWarning, exitCode: 0 };
    } finally { await opened.directory.close(); }
  } catch (error) { return { ...renderError(error, redactor), stderr: transportWarning }; }
}
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) run(process.argv.slice(2)).then(result => { process.stdout.write(result.stdout); process.stderr.write(result.stderr); process.exitCode = result.exitCode; });
