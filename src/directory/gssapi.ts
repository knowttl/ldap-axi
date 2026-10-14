import { trace } from "./trace.js";

/** The only provider mechanism names admitted by the sealed GSSAPI boundary. */
export type GssapiMechanism = "GSSAPI" | "GSS-SPNEGO";

export type GssapiToken = Buffer;
export const GSSAPI_MAX_CHANNEL_BINDING_BYTES = 64 * 1024;

export type GssapiProtectionRequirement = "none" | "integrity" | "confidentiality";

export type GssapiWrapResult = Readonly<{
  token: GssapiToken;
  confidential: boolean;
  integrity: boolean;
}>;

export type GssapiUnwrapResult = Readonly<{
  token: GssapiToken;
  confidential: boolean;
  integrity: boolean;
}>;

export type GssapiPrepareOptions = Readonly<{
  channelBindingData?: Uint8Array;
  protection?: GssapiProtectionRequirement;
}>;

export type GssapiStep = Readonly<{
  token?: GssapiToken;
  established?: boolean;
}>;

/**
 * Opaque context operations supplied by the platform provider.
 * Implementations and token values remain inside the directory boundary.
 */
export interface GssapiExchange {
  readonly initial: () => Promise<GssapiToken>;
  readonly step: (serverToken: GssapiToken) => Promise<GssapiStep>;
  readonly unwrap: (serverToken: GssapiToken) => Promise<GssapiToken>;
  readonly unwrapWithResult?: (serverToken: GssapiToken) => Promise<GssapiUnwrapResult>;
  readonly wrap: (clientData: GssapiToken) => Promise<GssapiToken>;
  readonly wrapWithResult?: (clientData: GssapiToken, options?: Readonly<{ protect?: boolean }>) => Promise<GssapiWrapResult>;
  readonly wrapSizeLimit?: (maxWrappedBytes: number, options?: Readonly<{ protect?: boolean }>) => Promise<number>;
}

export type GssapiPreparation =
  | Readonly<{ kind: "prepared"; exchange: GssapiExchange; mechanism?: GssapiMechanism }>
  | Readonly<{ kind: "no_credentials" }>
  | Readonly<{ kind: "credentials_expired" }>
  | Readonly<{ kind: "provider_unavailable"; missingLibrary?: string }>
  | Readonly<{ kind: "failed" }>;

export interface GssapiProvider {
  readonly prepare: (service: string, options?: GssapiPrepareOptions) => Promise<GssapiPreparation>;
}

export class GssapiConfidentialityError extends Error {
  constructor() {
    super("GSSAPI confidentiality was not provided");
  }
}

/** Returns a token only when the provider confirms that confidentiality was applied. */
export function requireConfidentiality(result: GssapiWrapResult): GssapiToken {
  if (result.confidential !== true) throw new GssapiConfidentialityError();
  return Buffer.from(result.token);
}

export type GssapiPreparationFailure = Exclude<GssapiPreparation, { kind: "prepared" }>;

export class GssapiPreparationError extends Error {
  constructor(readonly failure: GssapiPreparationFailure, readonly platform: NodeJS.Platform = process.platform) {
    super(failure.kind === "failed" ? "GSSAPI preparation failed" : failure.kind);
  }
}

/** Numeric statuses from the maintained native patch; native prose never selects a remedy. */
function nativePreparationFailure(error: unknown, platform: NodeJS.Platform): GssapiPreparationFailure {
  const status = error as { gssMajor?: unknown; gssMinor?: unknown; sspiCode?: unknown } | null;
  if (platform === "win32") {
    if (typeof status?.sspiCode === "number") {
      const code = status.sspiCode >>> 0;
      if (code === 0x8009030e) return { kind: "no_credentials" }; // SEC_E_NO_CREDENTIALS
      if (code === 0x80090317) return { kind: "credentials_expired" }; // SEC_E_CONTEXT_EXPIRED
    }
  } else {
    const major = typeof status?.gssMajor === "number" ? status.gssMajor & 0x00ff0000 : 0;
    const minor = typeof status?.gssMinor === "number" ? status.gssMinor >>> 0 : 0;
    if (major === 11 << 16 || minor === (-1765328352 >>> 0)) return { kind: "credentials_expired" }; // GSS_S_CREDENTIALS_EXPIRED / KRB5KRB_AP_ERR_TKT_EXPIRED
    if (major === 7 << 16 || minor === (-1765328189 >>> 0) || minor === (-1765328243 >>> 0)) return { kind: "no_credentials" }; // GSS_S_NO_CRED / KRB5_FCC_NOFILE / KRB5_CC_NOTFOUND
  }
  return { kind: "failed" };
}

type ProviderClient = Readonly<{
  step: (challenge: string) => Promise<unknown>;
  unwrap: (challenge: string) => Promise<unknown>;
  wrap: (challenge: string, options?: Readonly<{ protect?: boolean }>) => Promise<unknown>;
  wrapWithResult?: (challenge: string, options?: Readonly<{ protect?: boolean }>) => Promise<unknown>;
  unwrapWithResult?: (challenge: string) => Promise<unknown>;
  wrapSizeLimit?: (maxWrappedBytes: number, options?: Readonly<{ protect?: boolean }>) => Promise<unknown>;
  contextComplete?: unknown;
  contextFlags?: unknown;
  username?: unknown;
}>;

type KerberosModule = Readonly<{
  LDAP_AXI_PATCH_LEVEL?: unknown;
  initializeClient?: (service: string, options?: Readonly<Record<string, unknown>>) => Promise<ProviderClient>;
  GSS_C_MUTUAL_FLAG?: unknown;
  GSS_C_SEQUENCE_FLAG?: unknown;
  GSS_C_INTEG_FLAG?: unknown;
  GSS_C_CONF_FLAG?: unknown;
  GSS_MECH_OID_SPNEGO?: unknown;
  GSS_MECH_OID_KRB5?: unknown;
}>;

export type KerberosModuleLoader = () => Promise<unknown>;

function copyChannelBindingData(value: Uint8Array | undefined): Buffer | undefined {
  if (value === undefined) return undefined;
  if (!(value instanceof Uint8Array)) throw new TypeError("channel binding data is not binary");
  if (value.byteLength > GSSAPI_MAX_CHANNEL_BINDING_BYTES) throw new RangeError("channel binding data exceeds the 65536-byte limit");
  return Buffer.from(value);
}

/**
 * Returns the exact shared-library soname a Linux dynamic-loader failure names, and nothing else.
 * Native prose stays redacted: only a value matching the soname shape is admitted, so the addon path
 * and any other message text in the loader error are never surfaced.
 */
function missingLibraryName(error: unknown, platformName: NodeJS.Platform): string | undefined {
  if (platformName !== "linux") return undefined;
  const message = error instanceof Error ? error.message : "";
  const named = /([^\s/:]+): cannot open shared object file/.exec(message);
  const soname = named?.[1];
  return soname && /^lib[A-Za-z0-9_+-]+\.so(?:\.\d+)*$/.test(soname) ? soname : undefined;
}

function moduleValue(value: unknown): KerberosModule | undefined {
  if (!value || typeof value !== "object") return undefined;
  const candidate = value as { default?: unknown };
  const loaded = candidate.default && typeof candidate.default === "object" ? candidate.default : value;
  return loaded as KerberosModule;
}

function integer(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : fallback;
}

function base64ToBuffer(value: unknown): Buffer {
  if (typeof value !== "string") throw new TypeError("provider token is not base64 text");
  if (!value) return Buffer.alloc(0);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new TypeError("provider token is not valid base64");
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) throw new TypeError("provider token is not canonical base64");
  return bytes;
}

function stepTokenToBuffer(value: unknown): Buffer {
  return value === null ? Buffer.alloc(0) : base64ToBuffer(value);
}

function bufferToBase64(value: Uint8Array): string {
  if (!(value instanceof Uint8Array)) throw new TypeError("GSSAPI input is not binary");
  return Buffer.from(value).toString("base64");
}

function protectionRequirement(value: unknown): GssapiProtectionRequirement {
  if (value === undefined) return "none";
  if (value === "none" || value === "integrity" || value === "confidentiality") return value;
  throw new TypeError("GSSAPI protection requirement is invalid");
}

function requiredProtectionFlags(requirement: GssapiProtectionRequirement, integrity: number, confidentiality: number): number {
  if (requirement === "integrity") return integrity;
  if (requirement === "confidentiality") return integrity | confidentiality;
  return 0;
}

function verifyProtection(client: ProviderClient, requiredFlags: number): void {
  if (requiredFlags === 0) return;
  if (typeof client.contextFlags !== "number" || !Number.isInteger(client.contextFlags) || (client.contextFlags & requiredFlags) !== requiredFlags) {
    throw new Error("GSSAPI required protection was not established");
  }
}

function clientExchange(client: ProviderClient, initial: Buffer, platformName: NodeJS.Platform, requiredFlags: number): GssapiExchange {
  let initialAvailable = true;
  const unwrapWithResult = async (serverToken: Buffer): Promise<GssapiUnwrapResult> => {
    if (typeof client.unwrapWithResult === "function") {
      const result = await client.unwrapWithResult(bufferToBase64(serverToken));
      if (!result || typeof result !== "object") throw new TypeError("provider unwrap result is malformed");
      const value = result as { response?: unknown; confidential?: unknown; integrity?: unknown };
      if (typeof value.confidential !== "boolean" || typeof value.integrity !== "boolean") throw new TypeError("provider protection result is malformed");
      return { token: base64ToBuffer(value.response), confidential: value.confidential, integrity: value.integrity };
    }
    const response = await client.unwrap(bufferToBase64(serverToken));
    return { token: base64ToBuffer(response), confidential: false, integrity: false };
  };
  const wrapWithResult = async (clientData: Buffer, options: Readonly<{ protect?: boolean }> = {}): Promise<GssapiWrapResult> => {
    if (typeof client.wrapWithResult === "function") {
      const result = await client.wrapWithResult(bufferToBase64(clientData), options);
      if (!result || typeof result !== "object") throw new TypeError("provider wrap result is malformed");
      const value = result as { response?: unknown; confidential?: unknown; integrity?: unknown };
      if (typeof value.confidential !== "boolean" || typeof value.integrity !== "boolean") throw new TypeError("provider protection result is malformed");
      return { token: base64ToBuffer(value.response), confidential: value.confidential, integrity: value.integrity };
    }
    const response = await client.wrap(bufferToBase64(clientData), options);
    return { token: base64ToBuffer(response), confidential: false, integrity: false };
  };
  const wrapSizeLimit = async (maxWrappedBytes: number, options: Readonly<{ protect?: boolean }> = {}): Promise<number> => {
    if (typeof client.wrapSizeLimit !== "function") throw new TypeError("provider wrap-size calculation is unavailable");
    const result = await client.wrapSizeLimit(maxWrappedBytes, options);
    if (typeof result !== "number" || !Number.isSafeInteger(result) || result <= 0 || result > maxWrappedBytes) throw new TypeError("provider wrap-size result is malformed");
    return result;
  };
  return {
    initial: async () => {
      if (!initialAvailable) throw new Error("GSSAPI initial token was requested twice");
      initialAvailable = false;
      return Buffer.from(initial);
    },
    step: async serverToken => {
      trace("gssapi-step-request", () => ({ challengeBytes: serverToken.length }));
      try {
        const response = await client.step(bufferToBase64(serverToken));
        const token = stepTokenToBuffer(response);
        const established = platformName === "win32" ? typeof client.username === "string" : client.contextComplete === true;
        if (established) verifyProtection(client, requiredFlags);
        trace("gssapi-step-return", () => ({ challengeBytes: serverToken.length, tokenBytes: token.length, established }));
        return { token, established };
      } catch (error) {
        trace("gssapi-step-rejection", () => ({ challengeBytes: serverToken.length }));
        const failure = nativePreparationFailure(error, platformName);
        if (failure.kind !== "failed") throw new GssapiPreparationError(failure, platformName);
        throw error;
      }
    },
    unwrap: async serverToken => (await unwrapWithResult(serverToken)).token,
    unwrapWithResult,
    wrap: async clientData => (await wrapWithResult(clientData, { protect: false })).token,
    wrapWithResult,
    wrapSizeLimit,
  };
}

async function defaultLoader(): Promise<unknown> {
  return import(new URL("../../../vendor/kerberos/lib/index.js", import.meta.url).href);
}

/**
 * Creates the only production provider. The optional native addon is loaded from the vendored
 * provider only when authentication planning has selected ambient authentication. No native
 * object escapes the exchange held by the authentication plan.
 */
export function createKerberosProvider(loader: KerberosModuleLoader = defaultLoader, platformName: NodeJS.Platform = process.platform): GssapiProvider {
  return {
    prepare: async (service, prepareOptions = {}) => {
      const channelBindingData = copyChannelBindingData(prepareOptions.channelBindingData);
      const protection = protectionRequirement(prepareOptions.protection);
      let module: KerberosModule | undefined;
      trace("gssapi-provider-load-start");
      try {
        module = moduleValue(await loader());
      } catch (error) {
        const missingLibrary = missingLibraryName(error, platformName);
        const loadFields: Record<string, string | number | boolean> = { available: false };
        if (missingLibrary !== undefined) loadFields.missingLibrary = missingLibrary;
        trace("gssapi-provider-load-result", () => loadFields);
        return missingLibrary ? { kind: "provider_unavailable", missingLibrary } : { kind: "provider_unavailable" };
      }
      trace("gssapi-provider-load-result", () => ({ available: module?.LDAP_AXI_PATCH_LEVEL === 1 && typeof module.initializeClient === "function" }));
      if (module?.LDAP_AXI_PATCH_LEVEL !== 1 || !module.initializeClient) return { kind: "provider_unavailable" };

      const mutual = integer(module.GSS_C_MUTUAL_FLAG, 2);
      const sequence = integer(module.GSS_C_SEQUENCE_FLAG, 8);
      const integrity = integer(module.GSS_C_INTEG_FLAG, 32);
      const confidentiality = integer(module.GSS_C_CONF_FLAG, 16);
      const requiredFlags = requiredProtectionFlags(protection, integrity, confidentiality);
      const flags = (platformName === "win32" ? mutual | sequence : mutual | sequence | integrity) | requiredFlags;
      const mechanism: GssapiMechanism = platformName === "win32" ? "GSS-SPNEGO" : "GSSAPI";
      const options: Record<string, unknown> = { flags };
      if (platformName === "win32") options.mechOID = integer(module.GSS_MECH_OID_SPNEGO, 6);
      else options.mechOID = integer(module.GSS_MECH_OID_KRB5, 9);
      if (channelBindingData !== undefined) options.channelBindingData = channelBindingData;

      try {
        let client: ProviderClient;
        trace("gssapi-provider-initialize-start", () => ({ channelBindingPresent: channelBindingData !== undefined, channelBindingBytes: channelBindingData?.length ?? 0 }));
        try {
          client = await module.initializeClient(service, options);
        } catch (error) {
          trace("gssapi-provider-initialize-rejection");
          return nativePreparationFailure(error, platformName);
        }
        trace("gssapi-provider-initialize-result", () => ({ available: Boolean(client) }));
        if (!client || typeof client.step !== "function" || typeof client.unwrap !== "function" || typeof client.wrap !== "function") return { kind: "provider_unavailable" };
        if (protection !== "none" && (typeof client.wrapWithResult !== "function" || typeof client.unwrapWithResult !== "function" || typeof client.wrapSizeLimit !== "function")) return { kind: "provider_unavailable" };
        trace("gssapi-step-request", () => ({ challengeBytes: 0 }));
        let initialResult: unknown;
        try {
          initialResult = await client.step("");
        } catch (error) {
          trace("gssapi-step-rejection", () => ({ challengeBytes: 0 }));
          throw error;
        }
        const initial = stepTokenToBuffer(initialResult);
        const established = platformName === "win32" ? typeof client.username === "string" : client.contextComplete === true;
        trace("gssapi-step-return", () => ({ challengeBytes: 0, tokenBytes: initial.length, established }));
        if (established) verifyProtection(client, requiredFlags);
        return { kind: "prepared", exchange: clientExchange(client, initial, platformName, requiredFlags), mechanism };
      } catch (error) {
        return nativePreparationFailure(error, platformName);
      }
    },
  };
}
