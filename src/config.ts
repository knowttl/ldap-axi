import { lstat, readFile } from "node:fs/promises";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import { CliError, type ServerFlavor } from "./core.js";
import { parseAuthMode, parseProtectionRequirement, type AuthMode } from "./directory/auth.js";
import type { GssapiProtectionRequirement } from "./directory/gssapi.js";

export type TlsMaxVersion = "1.2";
export type Profile = Readonly<{ url?: string; base?: string; pageSize?: number; caFile?: string; startTls?: boolean; tlsMaxVersion?: TlsMaxVersion; flavor?: ServerFlavor; auth?: AuthMode; gssapiService?: string; gssapiProtection?: GssapiProtectionRequirement }>;
export type SettingsOverrides = Readonly<Profile & { profile?: string }>;
type ConfigFile = Profile & Readonly<{ profiles?: Readonly<Record<string, Profile>> }>;
export type AuthSettingSource = "cli" | "environment" | "profile" | "config" | "default";
export type ResolvedSettings = Readonly<{
  url?: string;
  base?: string;
  pageSize?: number;
  caFile?: string;
  startTls: boolean;
  tlsMaxVersion?: TlsMaxVersion;
  flavor?: ServerFlavor;
  auth: AuthMode;
  authSource: AuthSettingSource;
  gssapiService?: string;
  gssapiProtection?: GssapiProtectionRequirement;
  credentials?: Readonly<{ dn: string; password: string }>;
  credentialSource?: "environment" | "credentials-file";
  credentialsPermissions: "checked" | "unchecked (windows)" | "not-used";
}>;
export const MAX_PAGE_SIZE = 1000;

export function validateDirectoryUrl(value: string): string {
  let url: URL;
  try { url = new URL(value); } catch { throw new CliError("VALIDATION_ERROR", "--url must be a valid LDAP URL"); }
  if (url.protocol !== "ldaps:" && url.protocol !== "ldap:") throw new CliError("VALIDATION_ERROR", "--url must use ldap:// or ldaps://");
  if (url.username || url.password) throw new CliError("VALIDATION_ERROR", "--url must not contain credentials", ["Provide bind credentials through the environment or credentials file"]);
  return value;
}
export function validatePageSize(value: number): number {
  if (!Number.isInteger(value) || value <= 0 || value > MAX_PAGE_SIZE) throw new CliError("VALIDATION_ERROR", `pageSize must be an integer from 1 to ${MAX_PAGE_SIZE}`);
  return value;
}
export function validateTlsMaxVersion(value: unknown, source = "--tls-max-version"): TlsMaxVersion {
  if (value !== "1.2") throw new CliError("VALIDATION_ERROR", `${source} must be 1.2`);
  return "1.2";
}
export function pageSizeForFlavor(configured: number | undefined, flavor: ServerFlavor): number {
  return configured ?? (flavor === "ad" || flavor === "adlds" ? 1000 : 500);
}
const secretName = /password|passwd|secret|token|credential|key/i;
function configDirectory(): string { return platform() === "win32" ? join(process.env.APPDATA ?? homedir(), "ldap-axi") : join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "ldap-axi"); }
export function paths(): Readonly<{ config: string; credentials: string }> { const directory = configDirectory(); return { config: process.env.LDAP_AXI_CONFIG_FILE ?? join(directory, "config.json"), credentials: process.env.LDAP_AXI_CREDENTIALS_FILE ?? join(directory, "credentials.env") }; }

function assertConfigKeys(value: unknown, path: string): void {
  if (!value || typeof value !== "object" || Array.isArray(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (secretName.test(key)) throw new CliError("VALIDATION_ERROR", `config file contains secret-shaped key ${path}${key}`);
    assertConfigKeys(child, `${path}${key}.`);
  }
}

async function config(): Promise<ConfigFile> {
  try {
    const file = paths().config;
    const stat = await lstat(file);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new CliError("VALIDATION_ERROR", "config file must be a regular non-symlink file");
    if (platform() !== "win32" && ((typeof process.getuid === "function" && stat.uid !== process.getuid()) || (stat.mode & 0o077) !== 0)) throw new CliError("VALIDATION_ERROR", "config file must be owned by the current user and not group- or world-readable");
    const parsed: unknown = JSON.parse(await readFile(file, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new CliError("VALIDATION_ERROR", "config file must contain an object");
    assertConfigKeys(parsed, "");
    return parsed as ConfigFile;
  } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return {}; throw error; }
}
function parseEnv(text: string): Readonly<{ dn?: string; password?: string }> {
  const values: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) { const match = /^([A-Z0-9_]+)=(.*)$/.exec(line); if (match) values[match[1]] = match[2]; }
  return { dn: values.LDAP_AXI_BIND_DN, password: values.LDAP_AXI_BIND_PASSWORD };
}
async function fileCredentials(): Promise<Readonly<{ dn: string; password: string; permissions: ResolvedSettings["credentialsPermissions"] }> | undefined> {
  const file = paths().credentials;
  try {
    const stat = await lstat(file);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new CliError("VALIDATION_ERROR", "credentials file must be a regular non-symlink file");
    if (platform() !== "win32" && typeof process.getuid === "function" && stat.uid !== process.getuid()) throw new CliError("VALIDATION_ERROR", "credentials file must be owned by the current user");
    const permissions = platform() === "win32" ? "unchecked (windows)" as const : "checked" as const;
    if (platform() !== "win32" && (stat.mode & 0o077) !== 0) throw new CliError("VALIDATION_ERROR", "credentials file must not be group- or world-readable");
    const parsed = parseEnv(await readFile(file, "utf8"));
    if (!parsed.dn || !parsed.password) throw new CliError("CREDENTIAL_INCOMPLETE", "credentials file must provide both LDAP_AXI_BIND_DN and LDAP_AXI_BIND_PASSWORD");
    return { dn: parsed.dn, password: parsed.password, permissions };
  } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; }
}
function profileFor(saved: ConfigFile, name: string | undefined): Profile {
  if (!name) return {};
  const profile = saved.profiles?.[name];
  if (!profile || typeof profile !== "object" || Array.isArray(profile)) throw new CliError("VALIDATION_ERROR", `unknown profile ${name}`, ["Choose a profile defined in the config file"]);
  return profile;
}
function configuredAuth(value: unknown, source: string): AuthMode | undefined {
  return value === undefined ? undefined : parseAuthMode(value, source);
}
function configuredService(value: unknown, source: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !value) throw new CliError("VALIDATION_ERROR", `${source} must be a non-empty host-based service name`);
  return value;
}

export async function resolveSettings(overrides: SettingsOverrides): Promise<ResolvedSettings> {
  const saved = await config();
  const selected = profileFor(saved, overrides.profile);
  const configuredUrl = overrides.url ?? process.env.LDAP_AXI_URL ?? selected.url ?? saved.url;
  const url = configuredUrl === undefined ? undefined : validateDirectoryUrl(configuredUrl);
  const envDn = process.env.LDAP_AXI_BIND_DN; const envPassword = process.env.LDAP_AXI_BIND_PASSWORD;
  if ((envDn === undefined) !== (envPassword === undefined)) throw new CliError("CREDENTIAL_INCOMPLETE", `environment is missing LDAP_AXI_BIND_${envDn ? "PASSWORD" : "DN"}`);
  const file = envDn === undefined ? await fileCredentials() : undefined;
  const configuredPageSize = overrides.pageSize ?? selected.pageSize ?? saved.pageSize;
  const pageSize = configuredPageSize === undefined ? undefined : validatePageSize(configuredPageSize);
  const flavor = overrides.flavor ?? selected.flavor ?? saved.flavor;
  if (flavor !== undefined && !["ad", "adlds", "ldapv3"].includes(flavor)) throw new CliError("VALIDATION_ERROR", "config flavor must be ad, adlds, or ldapv3");

  const envAuth = process.env.LDAP_AXI_AUTH;
  const authValue = overrides.auth ?? envAuth ?? selected.auth ?? saved.auth;
  const auth = configuredAuth(authValue, overrides.auth !== undefined ? "--auth" : envAuth !== undefined ? "LDAP_AXI_AUTH" : overrides.profile && selected.auth !== undefined ? `profile ${overrides.profile}.auth` : "config auth") ?? "auto";
  const authSource: AuthSettingSource = overrides.auth !== undefined ? "cli" : envAuth !== undefined ? "environment" : selected.auth !== undefined ? "profile" : saved.auth !== undefined ? "config" : "default";
  const envTlsMaxVersion = process.env.LDAP_AXI_TLS_MAX_VERSION;
  const configuredTlsMaxVersion = overrides.tlsMaxVersion ?? envTlsMaxVersion ?? selected.tlsMaxVersion ?? saved.tlsMaxVersion;
  const tlsMaxVersion = configuredTlsMaxVersion === undefined ? undefined : validateTlsMaxVersion(configuredTlsMaxVersion, overrides.tlsMaxVersion !== undefined ? "--tls-max-version" : envTlsMaxVersion !== undefined ? "LDAP_AXI_TLS_MAX_VERSION" : "tlsMaxVersion");
  const envService = process.env.LDAP_AXI_GSSAPI_SERVICE;
  const gssapiService = configuredService(overrides.gssapiService ?? envService ?? selected.gssapiService ?? saved.gssapiService, overrides.gssapiService !== undefined ? "--gssapi-service" : envService !== undefined ? "LDAP_AXI_GSSAPI_SERVICE" : "gssapiService");
  const envProtection = process.env.LDAP_AXI_GSSAPI_PROTECTION;
  const configuredProtection = overrides.gssapiProtection ?? envProtection ?? selected.gssapiProtection ?? saved.gssapiProtection;
  const gssapiProtection = configuredProtection === undefined ? undefined : parseProtectionRequirement(configuredProtection, overrides.gssapiProtection !== undefined ? "--gssapi-protection" : envProtection !== undefined ? "LDAP_AXI_GSSAPI_PROTECTION" : "gssapiProtection");
  return {
    url,
    base: overrides.base ?? selected.base ?? saved.base,
    pageSize,
    caFile: overrides.caFile ?? selected.caFile ?? saved.caFile,
    startTls: overrides.startTls ?? selected.startTls ?? saved.startTls ?? false,
    tlsMaxVersion,
    flavor,
    auth,
    authSource,
    gssapiService,
    gssapiProtection,
    credentials: envDn && envPassword ? { dn: envDn, password: envPassword } : file ? { dn: file.dn, password: file.password } : undefined,
    credentialSource: envDn && envPassword ? "environment" : file ? "credentials-file" : undefined,
    credentialsPermissions: file?.permissions ?? "not-used",
  };
}
