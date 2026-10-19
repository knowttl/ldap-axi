import { Duplex } from "node:stream";
import { CliError } from "../core.js";
import { validateDirectoryUrl } from "../config.js";
import { GssapiPreparationError, type GssapiExchange, type GssapiMechanism, type GssapiPreparation, type GssapiPrepareOptions, type GssapiProvider, type GssapiProtectionRequirement } from "./gssapi.js";
import { ProtectedSaslDuplex } from "./protected-stream.js";
import { runSaslExchange, type SaslBindSender, type SaslLimits, type SaslSecurityLayer } from "./sasl.js";
import { trace } from "./trace.js";
import { noAmbientCredential } from "./errors.js";

export type AuthMode = "auto" | "gssapi" | "simple";
export type CredentialSource = "environment" | "credentials-file";
type SimpleCredential = Readonly<{ dn: string; password: string }>;

export type AuthPlan = Readonly<{
  requested: AuthMode;
  mode: "anonymous" | "simple" | "gssapi";
  credentialSource?: CredentialSource;
  credentials?: SimpleCredential;
  service?: string;
  mechanism?: GssapiMechanism;
  protection: GssapiProtectionRequirement;
}>;

export type AuthPlannerInput = Readonly<{
  requested: AuthMode;
  url: string;
  startTls?: boolean;
  credentials?: SimpleCredential;
  credentialSource?: CredentialSource;
  serviceOverride?: string;
  protection?: GssapiProtectionRequirement;
  anonymous?: boolean;
  /** True when --auth or a persisted/environment auth setting selected the mode. */
  authExplicit?: boolean;
  provider?: GssapiProvider;
  platform?: NodeJS.Platform;
}>;

const preparedExchanges = new WeakMap<object, GssapiExchange>();
const providers = new WeakMap<object, GssapiProvider>();
const AUTH_MODES = new Set<AuthMode>(["auto", "gssapi", "simple"]);
const PROTECTION_REQUIREMENTS = new Set<GssapiProtectionRequirement>(["none", "confidentiality"]);

export function parseAuthMode(value: unknown, source = "auth"): AuthMode {
  if (typeof value !== "string" || !AUTH_MODES.has(value as AuthMode)) {
    throw new CliError("VALIDATION_ERROR", `${source} must be auto, gssapi, or simple`);
  }
  return value as AuthMode;
}

export function parseProtectionRequirement(value: unknown, source = "gssapi protection"): GssapiProtectionRequirement {
  if (typeof value !== "string" || !PROTECTION_REQUIREMENTS.has(value as GssapiProtectionRequirement)) {
    throw new CliError("VALIDATION_ERROR", `${source} must be none or confidentiality`);
  }
  return value as GssapiProtectionRequirement;
}

function platformFor(platformName: NodeJS.Platform | undefined): NodeJS.Platform {
  return platformName ?? process.platform;
}

function hostFromUrl(value: string): string {
  try {
    return new URL(validateDirectoryUrl(value)).hostname;
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError("VALIDATION_ERROR", "directory URL must be a valid LDAP URL");
  }
}

function isIpLiteral(hostname: string): boolean {
  const host = hostname.replace(/^\[/, "").replace(/\]$/, "");
  if (!host.includes(":")) {
    const parts = host.split(".");
    return parts.length === 4 && parts.every(part => /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
  }
  const compressed = host.includes("::");
  if (compressed && host.indexOf("::") !== host.lastIndexOf("::")) return false;
  const parts = host.split(":");
  let units = 0;
  for (const [index, part] of parts.entries()) {
    if (!part) continue;
    if (part.includes(".")) {
      if (index !== parts.length - 1 || !isIpLiteral(part)) return false;
      units += 2;
    } else {
      if (!/^[0-9a-f]{1,4}$/i.test(part)) return false;
      units += 1;
    }
  }
  return compressed ? units < 8 : units === 8;
}

function validateService(service: string): string {
  // NUL is deliberately rejected in a host-based service name.
  // eslint-disable-next-line no-control-regex
  if (!service || /[\u0000\r\n\t ]/.test(service)) throw new CliError("VALIDATION_ERROR", "--gssapi-service must be a non-empty host-based service name");
  return service;
}

/** Derives one host-based target and never canonicalizes or tries alternatives. */
export function deriveGssapiService(url: string, platformName?: NodeJS.Platform): string {
  const hostname = hostFromUrl(url);
  const prefix = platformFor(platformName) === "win32" ? "ldap/" : "ldap@";
  return validateService(`${prefix}${hostname.replace(/^\[/, "").replace(/\]$/, "")}`);
}

function immutablePlan(plan: AuthPlan, provider?: GssapiProvider): AuthPlan {
  if (plan.credentials) Object.freeze(plan.credentials);
  const frozen = Object.freeze(plan);
  if (provider) providers.set(frozen, provider);
  return frozen;
}

function providerUnavailable(missingLibrary?: string): CliError {
  const help = ["Install a supported provider/runtime; on Linux ensure libgssapi_krb5.so.2 is discoverable by the system dynamic loader (for Nix/WSL, use the environment's library wrapper or LD_LIBRARY_PATH)", "Use --auth simple in a new invocation"];
  if (missingLibrary) help.unshift(`Install the system library ${missingLibrary} and make it discoverable by the dynamic loader; the native provider load failed on that exact library`);
  return new CliError("GSSAPI_UNAVAILABLE", "the ambient GSSAPI provider is unavailable", help);
}

function preparationFailed(): CliError {
  return new CliError("GSSAPI_PREPARATION_FAILED", "GSSAPI preparation failed", ["Confirm an ambient Kerberos/SSPI credential exists and is current", "Resolve any provider, KDC, service principal, or policy failure; no fallback occurred"]);
}

function negotiationFailure(message: string, phase: string): CliError {
  trace("gssapi-negotiation-failure", () => ({ phase }));
  return new CliError("GSSAPI_NEGOTIATION_FAILED", message, ["The selected SASL mechanism did not complete its bounded RFC 4752 exchange; no fallback occurred"]);
}

function preparationError(error: unknown, platformName: NodeJS.Platform): CliError {
  if (error instanceof GssapiPreparationError) {
    if (error.failure.kind === "provider_unavailable") return providerUnavailable(error.failure.missingLibrary);
    if (error.failure.kind === "no_credentials" || error.failure.kind === "credentials_expired") return noAmbientCredential(platformName);
    return preparationFailed();
  }
  return preparationFailed();
}

function preparedResult(result: GssapiPreparation): { exchange: GssapiExchange; mechanism?: GssapiMechanism } | undefined {
  if (result.kind !== "prepared") return undefined;
  if (!result.exchange || typeof result.exchange.initial !== "function" || typeof result.exchange.step !== "function" || typeof result.exchange.unwrap !== "function" || typeof result.exchange.wrap !== "function") throw preparationFailed();
  return result;
}

/**
 * D1 option C (§10.7): the URL scheme selects the transport, and the transport selects the layer.
 * TLS already carries confidentiality and channel binding, so the SASL layer is none; plain LDAP has no
 * other mechanism, so confidentiality is mandatory. Neither transport falls back to the other.
 */
function protectionFor(input: AuthPlannerInput, url: URL): GssapiProtectionRequirement {
  const tls = url.protocol === "ldaps:" || Boolean(input.startTls);
  const required: GssapiProtectionRequirement = tls ? "none" : "confidentiality";
  if (input.protection !== undefined && input.protection !== required) {
    throw new CliError(
      "VALIDATION_ERROR",
      tls
        ? "GSSAPI over verified TLS negotiates no SASL security layer, so a protection requirement cannot be requested"
        : "GSSAPI over plaintext LDAP requires the confidentiality layer",
      tls
        ? ["Drop --gssapi-protection; verified LDAPS or StartTLS already protects the connection"]
        : ["Drop --gssapi-protection, or pass --gssapi-protection confidentiality"],
    );
  }
  return required;
}

/** Prepares the selected provider only after the transport has supplied any TLS channel binding. */
async function prepareSelectedGssapi(plan: AuthPlan, options: GssapiPrepareOptions = {}): Promise<GssapiExchange> {
  if (plan.mode !== "gssapi" || !plan.service || !plan.mechanism) throw negotiationFailure("the selected authentication plan is not a GSSAPI exchange", "auth-plan");
  const existing = preparedExchanges.get(plan);
  if (existing) return existing;
  const provider = providers.get(plan);
  if (!provider) throw negotiationFailure("the selected GSSAPI provider is unavailable", "provider-lookup");
  trace("gssapi-provider-prepare-start", () => ({ channelBindingPresent: options.channelBindingData !== undefined, channelBindingBytes: options.channelBindingData?.byteLength ?? 0 }));
  let result: GssapiPreparation;
  try {
    result = await provider.prepare(plan.service, { protection: plan.protection, ...options });
  } catch (error) {
    trace("gssapi-provider-prepare-rejection", () => ({ channelBindingPresent: options.channelBindingData !== undefined }));
    throw preparationError(error, process.platform);
  }
  trace("gssapi-provider-prepare-result", () => ({ result: result && typeof result === "object" && typeof result.kind === "string" ? result.kind : "malformed" }));
  if (!result || typeof result !== "object" || typeof result.kind !== "string") throw preparationFailed();
  if (result.kind === "provider_unavailable") throw providerUnavailable(result.missingLibrary);
  if (result.kind === "no_credentials" || result.kind === "credentials_expired") throw noAmbientCredential(process.platform);
  const prepared = preparedResult(result);
  if (!prepared) throw preparationFailed();
  if (prepared.mechanism !== undefined && prepared.mechanism !== plan.mechanism) throw preparationFailed();
  preparedExchanges.set(plan, prepared.exchange);
  return prepared.exchange;
}

/** Runs only the exchange associated with a selected GSSAPI plan; it returns no transport primitive. */
export async function executeSelectedGssapi(plan: AuthPlan, send: SaslBindSender, limits?: SaslLimits, prepareOptions?: GssapiPrepareOptions): Promise<SaslSecurityLayer> {
  const exchange = await prepareSelectedGssapi(plan, prepareOptions);
  return runSaslExchange(exchange, plan.mechanism!, send, limits, { requiredProtection: plan.protection });
}

export async function protectSelectedGssapiTransport(plan: AuthPlan, native: Duplex, negotiated: SaslSecurityLayer, initialData: Uint8Array): Promise<Duplex> {
  if (negotiated.protection === "none") throw negotiationFailure("the selected GSSAPI plan did not negotiate a protected layer", "protected-handoff");
  const exchange = await prepareSelectedGssapi(plan);
  return new ProtectedSaslDuplex(native, exchange, negotiated.protection, negotiated.maxPlaintextBytes, negotiated.maxWrappedBytes, negotiated.maxInboundPlaintextBytes, negotiated.maxInboundWrappedBytes, initialData);
}

/**
 * Selects exactly one authentication and transport protection contract before any LDAP connection.
 * Provider context establishment is deferred until a verified TLS socket can supply channel binding data.
 */
export async function selectAuthPlan(input: AuthPlannerInput): Promise<AuthPlan> {
  const requested = parseAuthMode(input.requested);
  const platformName = platformFor(input.platform);
  const anonymous = Boolean(input.anonymous);
  if (anonymous && (input.credentials || input.authExplicit || requested !== "auto" || input.serviceOverride !== undefined || input.protection !== undefined)) {
    throw new CliError("VALIDATION_ERROR", "--anonymous cannot be combined with authenticated mode, --gssapi-service, --gssapi-protection, or resolved credentials");
  }
  if (anonymous) return immutablePlan({ requested, mode: "anonymous", protection: "none" });

  if (requested === "simple") {
    if (input.protection !== undefined && input.protection !== "none") throw new CliError("VALIDATION_ERROR", "GSSAPI protection applies only to GSSAPI authentication");
    if (!input.credentials) throw new CliError("AUTH_REQUIRED", "simple authentication requires a complete simple-bind credential", ["Set LDAP_AXI_BIND_DN and LDAP_AXI_BIND_PASSWORD, or select a profile with bindDn and a bindPassword SecretRef"]);
    return immutablePlan({ requested, mode: "simple", credentials: input.credentials, credentialSource: input.credentialSource, protection: "none" });
  }

  const parsedUrl = new URL(validateDirectoryUrl(input.url));
  const protection = protectionFor(input, parsedUrl);
  const hostname = parsedUrl.hostname;
  const service = input.serviceOverride !== undefined ? validateService(input.serviceOverride) : deriveGssapiService(input.url, platformName);
  if (isIpLiteral(hostname) && input.serviceOverride === undefined) throw new CliError("VALIDATION_ERROR", "--gssapi-service is required for IP-literal LDAP URLs when GSSAPI may be selected", ["Pass --gssapi-service <service@fqdn> or use --auth simple"]);
  if (!input.provider) throw providerUnavailable();
  const mechanism: GssapiMechanism = platformName === "win32" ? "GSS-SPNEGO" : "GSSAPI";
  return immutablePlan({ requested, mode: "gssapi", service, mechanism, protection }, input.provider);
}
