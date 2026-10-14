import { readFile } from "node:fs/promises";
import type { Directory } from "./core.js";
import type { AuthSettingSource, ResolvedSettings } from "./config.js";
import type { AuthMode, AuthPlan, CredentialSource } from "./directory/auth.js";

const WHOAMI_OID = "1.3.6.1.4.1.4203.1.11.3";
const STATUS_FILE = new URL("../../build/native-status.json", import.meta.url);

export type NativeProviderStatus = Readonly<{ result: string; detail: string; target?: string; mode?: string }>;

export type AuthStatusInput = Readonly<{
  profile?: string;
  configPath?: string;
  bindPasswordSource?: string;
  url?: string;
  startTls: boolean;
  tlsNoVerify: boolean;
  caMode: "default" | "appended" | "replacement";
  authMode: AuthMode;
  authSource: AuthSettingSource;
  plan?: AuthPlan;
  credentialSource?: CredentialSource;
  credentialsPermissions: ResolvedSettings["credentialsPermissions"];
}>;

/**
 * Reports the recorded outcome of native provider installation, which is the loader's source of truth
 * (AGENTS.md, docs/design/v1.md §10.6). A missing file means installation never ran here.
 */
export async function readNativeStatus(file: URL | string = STATUS_FILE): Promise<NativeProviderStatus | undefined> {
  let text: string;
  try { text = await readFile(file, "utf8"); } catch { return undefined; }
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { return { result: "unknown", detail: "native installation status is malformed" }; }
  const status = parsed as Partial<NativeProviderStatus>;
  if (typeof status?.result !== "string" || typeof status.detail !== "string") return { result: "unknown", detail: "native installation status is malformed" };
  return { result: status.result, detail: status.detail, ...(typeof status.target === "string" ? { target: status.target } : {}), ...(typeof status.mode === "string" ? { mode: status.mode } : {}) };
}

function tlsState(input: AuthStatusInput): "verified" | "unverified" | "none" {
  const tls = /^ldaps:/i.test(input.url ?? "") || input.startTls;
  return tls ? (input.tlsNoVerify ? "unverified" : "verified") : "none";
}

function credentialsState(input: AuthStatusInput): string {
  if (input.plan?.mode === "anonymous") return "anonymous";
  if (input.plan?.mode === "gssapi") return "ambient";
  if (input.plan?.mode === "simple" || input.credentialSource) return "resolved";
  return "not configured";
}

/**
 * Reports the single authentication contract this invocation selected, offline when no directory is
 * connected (docs/design/v1.md §10.7, §11). The SASL security layer is the one the exchange enforced:
 * §10.7 derives it from the URL scheme and the bind fails rather than negotiating a weaker layer.
 */
export async function authStatus(input: AuthStatusInput, directory?: Directory): Promise<{ data: Record<string, unknown>; help: string[] }> {
  const plan = input.plan;
  const tls = tlsState(input);
  const gssapi = plan?.mode === "gssapi";
  const native = await readNativeStatus();
  const data: Record<string, unknown> = {
    ...(input.profile ? { profile: input.profile } : {}),
    ...(input.configPath ? { config: input.configPath } : {}),
    ...(input.bindPasswordSource ? { bind_password_source: input.bindPasswordSource } : {}),
    ...(plan?.mode === "simple" ? { configured_bind_dn: plan.credentials!.dn } : {}),
    ...(input.url ? { url: input.url } : {}),
    connection: directory ? "live" : "offline",
    credentials: gssapi && !directory ? "ambient (unchecked)" : credentialsState(input),
    ...(input.credentialSource ? { credential_source: input.credentialSource } : {}),
    credentials_file_permissions: input.credentialsPermissions,
    auth: input.authMode,
    auth_source: input.authSource,
    mechanism: gssapi ? plan!.mechanism! : plan?.mode ?? "not selected",
    ...(gssapi ? { gssapi_service: plan!.service! } : {}),
    sasl_security_layer: gssapi ? plan!.protection : "not applicable",
    channel_binding: gssapi && tls !== "none" ? "tls-server-end-point" : "none",
    tls,
    ca_trust: input.caMode,
    native_provider: directory && gssapi ? "available" : "unchecked",
    native_provider_installation: native?.result ?? "not installed",
    native_provider_detail: native?.detail ?? "native installation has not run in this package",
  };
  const help: string[] = [];
  if (!input.url) { help.push("Set LDAP_AXI_URL or pass --url ldaps://server:636 to report the selected mechanism and transport"); return { data, help }; }
  if (!directory) { help.push("Offline values describe the selected contract and recorded installation; provider loading and ambient credentials are unchecked", "Drop --offline to bind once and report the server-resolved identity"); return { data, help }; }

  const root = await directory.rootDSE();
  const whoamiSupported = (root.attributes.supportedExtension ?? []).includes(WHOAMI_OID);
  const boundAs = whoamiSupported ? await directory.whoami() : plan?.credentials?.dn;
  data.flavor = directory.flavor;
  if (boundAs) data.bound_as = boundAs;
  data.identity_method = whoamiSupported ? "whoami" : plan?.credentials?.dn ? "configured-bind-dn" : "unresolved";
  if (!whoamiSupported) help.push("The server does not advertise RFC 4532 Who Am I, so the bound identity is not server-resolved");
  return { data, help };
}
