import { lstat } from "node:fs/promises";
import { homedir, platform } from "node:os";
import { isAbsolute, join } from "node:path";
import { CliError, type ServerFlavor } from "./core.js";
import { parseAuthMode, parseProtectionRequirement, type AuthMode } from "./directory/auth.js";
import type { GssapiProtectionRequirement } from "./directory/gssapi.js";
import { readPrivateFile } from "./private-file.js";
import { resolveSecret, SecretRedactor, secretSource, validateSecretRef, type SecretRef } from "./secrets.js";

export type TlsMaxVersion = "1.2";
export type Profile = Readonly<{ url?: string; base?: string; pageSize?: number; caFile?: string; startTls?: boolean; tlsMaxVersion?: TlsMaxVersion; flavor?: ServerFlavor; auth?: AuthMode; gssapiService?: string; gssapiProtection?: GssapiProtectionRequirement; bindDn?: string; bindPassword?: SecretRef }>;
export type SettingsOverrides = Readonly<Omit<Profile, "bindDn" | "bindPassword"> & { profile?: string; config?: string }>;
type ConfigFile = Readonly<{ version: 1; defaultProfile?: string; profiles: Readonly<Record<string, Profile>> }>;
export type AuthSettingSource = "cli" | "environment" | "profile" | "config" | "default";
export type ResolvedSettings = Readonly<{
  url?: string; base?: string; pageSize?: number; caFile?: string; startTls: boolean; tlsMaxVersion?: TlsMaxVersion;
  flavor?: ServerFlavor; auth: AuthMode; authSource: AuthSettingSource; gssapiService?: string; gssapiProtection?: GssapiProtectionRequirement;
  profile?: string; configPath: string; bindPasswordSource?: string; credentialsConfigured: boolean;
  credentials?: Readonly<{ dn: string; password: string }>;
  credentialSource?: "environment" | "credentials-file";
  credentialsPermissions: "checked" | "unchecked (windows)" | "not-used";
}>;
export const MAX_PAGE_SIZE = 1000;
const PROFILE_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const PROFILE_KEYS = ["url", "base", "pageSize", "caFile", "startTls", "tlsMaxVersion", "flavor", "auth", "gssapiService", "gssapiProtection", "bindDn", "bindPassword"];

export function validateDirectoryUrl(value: string): string {
  let url: URL;
  try { url = new URL(value); } catch { throw new CliError("VALIDATION_ERROR", "--url must be a valid LDAP URL"); }
  if (url.protocol !== "ldaps:" && url.protocol !== "ldap:") throw new CliError("VALIDATION_ERROR", "--url must use ldap:// or ldaps://");
  if (url.username || url.password) throw new CliError("VALIDATION_ERROR", "--url must not contain credentials", ["Provide bind credentials through SecretRefs"]);
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
function configDirectory(): string {
  if (platform() === "win32") return join(process.env.APPDATA ?? join(homedir(), "AppData", "Roaming"), "ldap-axi");
  const xdg = process.env.XDG_CONFIG_HOME;
  return join(xdg && isAbsolute(xdg) ? xdg : join(homedir(), ".config"), "ldap-axi");
}
export function paths(explicit?: string): Readonly<{ config: string; credentials: string }> {
  const directory = configDirectory();
  return { config: explicit ?? process.env.LDAP_AXI_CONFIG ?? process.env.LDAP_AXI_CONFIG_FILE ?? join(directory, "config.json"), credentials: process.env.LDAP_AXI_CREDENTIALS_FILE ?? join(directory, "credentials.env") };
}
function object(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function invalid(message: string): never { throw new CliError("CONFIG_INVALID", message); }
function validateProfile(name: string, value: unknown): asserts value is Profile {
  if (!PROFILE_NAME.test(name)) invalid("invalid profile name; use 1-64 letters, digits, dash or underscore, starting with a letter or digit");
  if (!object(value)) invalid(`profile ${name} must be an object`);
  for (const key of Object.keys(value)) if (!PROFILE_KEYS.includes(key)) invalid(`profile ${name} has unknown field ${key}`);
  for (const key of ["url", "base", "caFile", "gssapiService", "bindDn"]) if (value[key] !== undefined && (typeof value[key] !== "string" || key !== "base" && !value[key])) invalid(`profile ${name}.${key} must be a non-empty string`);
  if (!value.url) invalid(`profile ${name}.url is required`);
  if (value.startTls !== undefined && typeof value.startTls !== "boolean") invalid(`profile ${name}.startTls must be a boolean`);
  if (value.flavor !== undefined && !["ad", "adlds", "ldapv3"].includes(value.flavor as string)) invalid(`profile ${name}.flavor must be ad, adlds, or ldapv3`);
  if (value.bindPassword !== undefined) validateSecretRef(value.bindPassword, `profile ${name}.bindPassword`);
  try {
    validateDirectoryUrl(value.url as string);
    if (value.pageSize !== undefined) validatePageSize(value.pageSize as number);
    if (value.tlsMaxVersion !== undefined) validateTlsMaxVersion(value.tlsMaxVersion);
    if (value.auth !== undefined) parseAuthMode(value.auth);
    if (value.gssapiProtection !== undefined) parseProtectionRequirement(value.gssapiProtection);
  } catch { invalid(`profile ${name} has invalid directory settings`); }
}
export async function loadConfig(explicit?: string): Promise<{ path: string; config?: ConfigFile }> {
  const path = paths(explicit).config;
  let text: string;
  try { text = await readPrivateFile(path); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return { path }; throw error; }
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { invalid(`config file at ${path} is not valid JSON`); }
  if (object(parsed) && parsed.version === undefined) throw new CliError("CONFIG_MOVED", `legacy config format at ${path} is no longer read`, ["Convert to {version:1, defaultProfile, profiles:{name:{url, auth, bindDn, bindPassword:{env:NAME}}}}; replace credentials.env with a SecretRef"]);
  if (!object(parsed) || parsed.version !== 1 || !object(parsed.profiles) || Object.keys(parsed).some(key => !["version", "defaultProfile", "profiles"].includes(key))) invalid(`config file at ${path} must contain version 1 and profiles`);
  if (parsed.defaultProfile !== undefined && (typeof parsed.defaultProfile !== "string" || !PROFILE_NAME.test(parsed.defaultProfile))) invalid("invalid defaultProfile name");
  for (const [name, value] of Object.entries(parsed.profiles)) validateProfile(name, value);
  return { path, config: parsed as ConfigFile };
}
function envBoolean(name: string): boolean | undefined {
  const value = process.env[name];
  if (value === undefined) return undefined;
  if (!/^(1|true|0|false)$/i.test(value)) invalid(`${name} must be 1, true, 0 or false`);
  return /^(1|true)$/i.test(value);
}
function envProfile(flagUrl?: string): Profile | undefined {
  const dn = process.env.LDAP_AXI_BIND_DN; const password = process.env.LDAP_AXI_BIND_PASSWORD;
  if (Boolean(dn) !== Boolean(password)) throw new CliError("CREDENTIAL_INCOMPLETE", `environment is missing LDAP_AXI_BIND_${dn ? "PASSWORD" : "DN"}`);
  const url = process.env.LDAP_AXI_URL;
  const auth = process.env.LDAP_AXI_AUTH;
  const hasFields = PROFILE_KEYS.some(key => process.env[`LDAP_AXI_${key.replace(/[A-Z]/g, letter => `_${letter}`).toUpperCase()}`] !== undefined);
  if (!hasFields) return undefined;
  if (!url && !flagUrl) invalid("env profile requires LDAP_AXI_URL or --url; select a file profile explicitly to ignore env fields");
  // Ambient auth needs no password; a non-secret flag may supply the endpoint.
  const pageSize = process.env.LDAP_AXI_PAGE_SIZE;
  return { url, bindDn: dn, bindPassword: password === undefined ? undefined : { env: "LDAP_AXI_BIND_PASSWORD" }, auth: auth === undefined ? undefined : parseAuthMode(auth, "LDAP_AXI_AUTH"),
    base: process.env.LDAP_AXI_BASE, caFile: process.env.LDAP_AXI_CA_FILE, pageSize: pageSize === undefined ? undefined : validatePageSize(Number(pageSize)),
    startTls: envBoolean("LDAP_AXI_START_TLS"), tlsMaxVersion: process.env.LDAP_AXI_TLS_MAX_VERSION === undefined ? undefined : validateTlsMaxVersion(process.env.LDAP_AXI_TLS_MAX_VERSION),
    flavor: process.env.LDAP_AXI_FLAVOR as ServerFlavor | undefined, gssapiService: process.env.LDAP_AXI_GSSAPI_SERVICE,
    gssapiProtection: process.env.LDAP_AXI_GSSAPI_PROTECTION === undefined ? undefined : parseProtectionRequirement(process.env.LDAP_AXI_GSSAPI_PROTECTION) };
}
async function rejectLegacyCredentials(): Promise<void> {
  const file = paths().credentials;
  try { await lstat(file); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return; throw error; }
  throw new CliError("CONFIG_MOVED", `legacy credentials file at ${file} is no longer read`, ["Move the password to a private UTF-8 file and reference it with bindPassword: {file: absolutePath} in a version 1 profile; remove credentials.env"]);
}
export async function resolveSettings(overrides: SettingsOverrides, redactor = new SecretRedactor()): Promise<ResolvedSettings> {
  envBoolean("LDAP_AXI_READ_ONLY"); // v1 remains read-only even when false; no write journal is needed.
  const { path, config } = await loadConfig(overrides.config);
  const profiles = config?.profiles ?? {};
  const names = Object.keys(profiles);
  let name = overrides.profile ?? process.env.LDAP_AXI_PROFILE;
  let selected: Profile | undefined;
  let fromEnv = false;
  if (name === undefined) {
    selected = envProfile(overrides.url);
    fromEnv = selected !== undefined;
    name = selected ? "env" : config?.defaultProfile ?? (names.length === 1 ? names[0] : undefined);
  }
  if (!selected && name !== undefined) {
    if (!PROFILE_NAME.test(name) || !Object.hasOwn(profiles, name)) throw new CliError("PROFILE_NOT_FOUND", "selected profile is not defined", ["Run `ldap-axi profile list` and choose --profile <name>"]);
    selected = profiles[name];
  }
  if (!selected && config) throw new CliError(names.length ? "PROFILE_AMBIGUOUS" : "PROFILE_REQUIRED", "select one directory profile", ["Pass --profile <name> or set LDAP_AXI_PROFILE"]);
  if (!config) await rejectLegacyCredentials();
  selected ??= {};
  const settings = { ...selected, ...Object.fromEntries(Object.entries(overrides).filter(([, value]) => value !== undefined)) };
  const url = settings.url === undefined ? undefined : validateDirectoryUrl(settings.url);
  const auth = parseAuthMode(settings.auth ?? "auto");
  const authSource: AuthSettingSource = overrides.auth !== undefined ? "cli" : selected.auth !== undefined ? fromEnv ? "environment" : "profile" : "default";
  const ref = selected.bindPassword ?? { env: "LDAP_AXI_BIND_PASSWORD" };
  const dn = selected.bindDn;
  const configured = Boolean(dn || selected.bindPassword);
  let password: string | undefined;
  if (auth === "simple") {
    password = await resolveSecret(ref, redactor);
    if (Boolean(dn) !== Boolean(password)) throw new CliError("CREDENTIAL_INCOMPLETE", "simple authentication requires both bindDn and bindPassword", [`Supply the complete credential pair; password source: ${secretSource(ref)}`]);
    if (!dn || !password) throw new CliError("AUTH_REQUIRED", "simple authentication requires bindDn and a bindPassword SecretRef");
  }
  if (settings.flavor !== undefined && !["ad", "adlds", "ldapv3"].includes(settings.flavor)) invalid("flavor must be ad, adlds, or ldapv3");
  if (settings.gssapiService !== undefined && !settings.gssapiService) invalid("gssapiService must be non-empty");
  return { url, base: settings.base, pageSize: settings.pageSize, caFile: settings.caFile, startTls: settings.startTls ?? false,
    tlsMaxVersion: settings.tlsMaxVersion, flavor: settings.flavor, auth, authSource, gssapiService: settings.gssapiService, gssapiProtection: settings.gssapiProtection,
    profile: name, configPath: path, bindPasswordSource: configured || auth === "simple" ? secretSource(ref) : undefined, credentialsConfigured: configured,
    credentials: dn && password ? { dn, password } : undefined,
    credentialSource: configured ? "file" in ref ? "credentials-file" : "environment" : undefined,
    credentialsPermissions: auth === "simple" && "file" in ref ? platform() === "win32" ? "unchecked (windows)" : "checked" : "not-used" };
}
