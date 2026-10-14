import { CliError } from "../core.js";
import { GssapiPreparationError, type GssapiExchange, type GssapiProtectionRequirement, type GssapiUnwrapResult, type GssapiWrapResult } from "./gssapi.js";
import { noAmbientCredential, translateLdapError } from "./errors.js";
import { trace } from "./trace.js";

export const SASL_MAX_CONTINUATIONS = 8;
export const SASL_MAX_TOKEN_BYTES = 64 * 1024;
export const SASL_MAX_AGGREGATE_BYTES = 256 * 1024;
export const SASL_CLIENT_MAX_BUFFER_BYTES = 64 * 1024;
export const SASL_MAX_WRAPPED_BYTES = 64 * 1024;
export const SASL_MAX_LDAP_MESSAGE_BYTES = 64 * 1024;

const SASL_LAYER_NONE = 0x01;
const SASL_LAYER_INTEGRITY = 0x02;
const SASL_LAYER_CONFIDENTIALITY = 0x04;
const SASL_LAYER_KNOWN = SASL_LAYER_NONE | SASL_LAYER_INTEGRITY | SASL_LAYER_CONFIDENTIALITY;

export type SaslBindResponse = Readonly<{
  resultCode: number;
  diagnosticMessage?: string;
  serverCredentials?: Uint8Array;
  mechanism?: string;
}>;

export type SaslBindSender = (mechanism: string, credentials: Uint8Array) => Promise<SaslBindResponse>;

export type SaslLimits = Readonly<{
  maxContinuations?: number;
  maxTokenBytes?: number;
  maxAggregateBytes?: number;
}>;

export type SaslSecurityOptions = Readonly<{
  requiredProtection: GssapiProtectionRequirement;
  clientMaxBufferBytes?: number;
  ldapMaxMessageBytes?: number;
}>;

export type SaslSecurityLayer = Readonly<{
  protection: GssapiProtectionRequirement;
  maxPlaintextBytes: number;
  maxWrappedBytes: number;
  maxInboundPlaintextBytes: number;
  maxInboundWrappedBytes: number;
}>;

function failure(message: string, phase = "sasl-exchange"): CliError {
  trace("gssapi-negotiation-failure", () => ({ phase }));
  return new CliError("GSSAPI_NEGOTIATION_FAILED", message, ["The selected SASL mechanism did not complete its bounded RFC 4752 exchange; no fallback occurred"]);
}

function token(value: Uint8Array | undefined, label: string, limits: Required<SaslLimits>, state: { aggregate: number }): Buffer {
  if (!value) throw failure(`${label} token is missing`);
  if (!(value instanceof Uint8Array)) throw failure(`${label} token is not binary`);
  const bytes = Buffer.from(value);
  if (bytes.length > limits.maxTokenBytes) throw failure(`${label} token exceeds the ${limits.maxTokenBytes}-byte limit`);
  state.aggregate += bytes.length;
  if (state.aggregate > limits.maxAggregateBytes) throw failure(`SASL token exchange exceeds the ${limits.maxAggregateBytes}-byte aggregate limit`);
  return bytes;
}

function normalizeLimits(limits: SaslLimits): Required<SaslLimits> {
  const result = {
    maxContinuations: limits.maxContinuations ?? SASL_MAX_CONTINUATIONS,
    maxTokenBytes: limits.maxTokenBytes ?? SASL_MAX_TOKEN_BYTES,
    maxAggregateBytes: limits.maxAggregateBytes ?? SASL_MAX_AGGREGATE_BYTES,
  };
  if (Object.values(result).some(value => !Number.isInteger(value) || value <= 0)) throw failure("SASL exchange limits must be positive integers");
  return result;
}

function response(response: SaslBindResponse, mechanism: string): SaslBindResponse {
  if (!response || !Number.isInteger(response.resultCode)) throw failure("SASL server response has no valid result code");
  if (response.mechanism !== undefined && response.mechanism !== mechanism) throw failure(`SASL mechanism switched from ${mechanism} to ${response.mechanism}`);
  if (response.resultCode !== 0 && response.resultCode !== 14) {
    const error = new Error(response.diagnosticMessage ?? "");
    Object.assign(error, { code: response.resultCode });
    throw translateLdapError(error);
  }
  return response;
}

async function providerCall<T>(label: string, operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof GssapiPreparationError && (error.failure.kind === "no_credentials" || error.failure.kind === "credentials_expired")) throw noAmbientCredential(error.platform);
    if (error instanceof CliError && (error.code === "GSSAPI_NEGOTIATION_FAILED" || error.code === "GSSAPI_CREDENTIAL_UNAVAILABLE")) throw error;
    throw failure(`${label} failed`);
  }
}

function serverToken(responseValue: SaslBindResponse, limits: Required<SaslLimits>, state: { aggregate: number }): Buffer {
  return token(responseValue.serverCredentials, "server", limits, state);
}

function offer(offerValue: Uint8Array): { mask: number; serverMax: number } {
  if (!(offerValue instanceof Uint8Array) || offerValue.length !== 4) throw failure("RFC 4752 server security offer must contain exactly four octets");
  const mask = offerValue[0]!;
  if ((mask & ~SASL_LAYER_KNOWN) !== 0) throw failure("RFC 4752 server security offer contains unknown security-layer bits");
  const serverMax = (offerValue[1]! * 0x10000) + (offerValue[2]! * 0x100) + offerValue[3]!;
  if (!(mask & (SASL_LAYER_INTEGRITY | SASL_LAYER_CONFIDENTIALITY)) && serverMax !== 0) throw failure("RFC 4752 server security offer has a buffer size without a security layer");
  return { mask, serverMax };
}

function protectResult(result: GssapiWrapResult | GssapiUnwrapResult, label: string, limits: Required<SaslLimits>, state: { aggregate: number }): Buffer {
  if (!result || !(result.token instanceof Uint8Array) || typeof result.confidential !== "boolean" || typeof result.integrity !== "boolean") throw failure(`${label} protection result is malformed`);
  return token(result.token, label, limits, state);
}

function layerBit(protection: GssapiProtectionRequirement): number {
  return protection === "confidentiality" ? SASL_LAYER_CONFIDENTIALITY : protection === "integrity" ? SASL_LAYER_INTEGRITY : SASL_LAYER_NONE;
}

function bounded(value: number | undefined, fallback: number, label: string): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result <= 0 || result > 0xffffff) throw failure(`${label} is outside the bounded RFC 4752 range`);
  return result;
}

async function clientLayerLimits(exchange: GssapiExchange, serverMax: number, protection: GssapiProtectionRequirement, options: SaslSecurityOptions): Promise<Omit<SaslSecurityLayer, "protection">> {
  const clientMax = bounded(options.clientMaxBufferBytes, SASL_CLIENT_MAX_BUFFER_BYTES, "client security-layer buffer");
  const ldapMax = bounded(options.ldapMaxMessageBytes, SASL_MAX_LDAP_MESSAGE_BYTES, "LDAP message buffer");
  const maxInboundWrappedBytes = Math.min(clientMax, SASL_MAX_WRAPPED_BYTES);
  if (serverMax === 0) throw failure("server security-layer buffer has no protected-data capacity");
  const maxWrappedBytes = Math.min(bounded(serverMax, SASL_MAX_WRAPPED_BYTES, "server security-layer buffer"), SASL_MAX_WRAPPED_BYTES);
  if (!exchange.wrapSizeLimit) throw failure("GSSAPI provider cannot calculate the protected plaintext capacity");
  const providerLimit = await providerCall("GSSAPI wrap-size calculation", () => exchange.wrapSizeLimit!(maxWrappedBytes, { protect: protection === "confidentiality" }));
  if (!Number.isSafeInteger(providerLimit) || providerLimit <= 0 || providerLimit > maxWrappedBytes) throw failure("GSSAPI provider returned an invalid wrap-size limit");
  return {
    maxPlaintextBytes: Math.min(ldapMax, providerLimit),
    maxWrappedBytes,
    maxInboundPlaintextBytes: ldapMax,
    maxInboundWrappedBytes,
  };
}

async function wrapSelection(exchange: GssapiExchange, selection: Buffer, required: boolean, limits: Required<SaslLimits>, state: { aggregate: number }): Promise<Buffer> {
  trace("gssapi-rfc4752-selection-wrap-start", () => ({ clearBytes: selection.length, integrityRequired: required }));
  if (!required) {
    const result = token(await providerCall("GSSAPI security-layer wrapping", () => exchange.wrap(selection)), "client security selection", limits, state);
    trace("gssapi-rfc4752-selection-wrap-result", () => ({ wrappedBytes: result.length, integrity: false }));
    return result;
  }
  if (!exchange.wrapWithResult) throw failure("GSSAPI provider cannot prove outbound security-layer integrity");
  const result = await providerCall("GSSAPI security-layer wrapping", () => exchange.wrapWithResult!(selection, { protect: false }));
  if (result.integrity !== true) throw failure("GSSAPI provider did not prove outbound security-layer integrity");
  const wrapped = protectResult(result, "client security selection", limits, state);
  trace("gssapi-rfc4752-selection-wrap-result", () => ({ wrappedBytes: wrapped.length, integrity: result.integrity }));
  return wrapped;
}

async function selectSecurityLayer(exchange: GssapiExchange, clearOffer: Uint8Array, options: SaslSecurityOptions, limits: Required<SaslLimits>, state: { aggregate: number }): Promise<{ selection: Buffer; negotiated: SaslSecurityLayer }> {
  const parsed = offer(clearOffer);
  trace("gssapi-rfc4752-offer", () => ({ offerBytes: clearOffer.length, layerMask: parsed.mask, serverMaxBytes: parsed.serverMax }));
  const required = options.requiredProtection;
  const selectedBit = layerBit(required);
  if ((parsed.mask & selectedBit) === 0) throw failure(required === "confidentiality" ? "server did not offer the required confidentiality layer" : required === "integrity" ? "server did not offer the required integrity layer" : "server did not offer the required no-security layer");
  if (required === "none") {
    return { selection: await wrapSelection(exchange, Buffer.from([SASL_LAYER_NONE, 0, 0, 0]), false, limits, state), negotiated: { protection: "none", maxPlaintextBytes: SASL_CLIENT_MAX_BUFFER_BYTES, maxWrappedBytes: SASL_MAX_WRAPPED_BYTES, maxInboundPlaintextBytes: SASL_MAX_LDAP_MESSAGE_BYTES, maxInboundWrappedBytes: SASL_MAX_WRAPPED_BYTES } };
  }
  const negotiated = await clientLayerLimits(exchange, parsed.serverMax, required, options);
  const selection = Buffer.alloc(4);
  selection[0] = selectedBit;
  selection[1] = Math.floor(negotiated.maxInboundWrappedBytes / 0x10000);
  selection[2] = Math.floor(negotiated.maxInboundWrappedBytes / 0x100) & 0xff;
  selection[3] = negotiated.maxInboundWrappedBytes & 0xff;
  return { selection: await wrapSelection(exchange, selection, true, limits, state), negotiated: { protection: required, ...negotiated } };
}

/** Validates and wraps a legacy RFC 4752 no-layer selection. */
export async function negotiateNoSecurityLayer(exchange: GssapiExchange, serverOffer: Uint8Array, limits: SaslLimits = {}): Promise<Buffer> {
  const normalized = normalizeLimits(limits);
  const state = { aggregate: 0 };
  const clearOffer = token(serverOffer, "server security offer", normalized, state);
  const parsed = offer(clearOffer);
  trace("gssapi-rfc4752-offer", () => ({ offerBytes: clearOffer.length, layerMask: parsed.mask, serverMaxBytes: parsed.serverMax }));
  if (!(parsed.mask & SASL_LAYER_NONE)) throw failure("server requires a SASL security layer; no security layer is the only supported policy");
  return wrapSelection(exchange, Buffer.from([SASL_LAYER_NONE, 0, 0, 0]), false, normalized, state);
}

function stepToken(step: { token?: Uint8Array; established?: boolean }, limits: Required<SaslLimits>, state: { aggregate: number }): Buffer {
  if (!step || typeof step !== "object" || step.established !== undefined && typeof step.established !== "boolean") throw failure("GSSAPI provider returned a malformed step");
  if (step.token === undefined) throw failure("GSSAPI provider returned no continuation token");
  return token(step.token, "client", limits, state);
}

/**
 * Drives one bounded same-mechanism SASL exchange and installs exactly one negotiated security contract.
 * The sender is deliberately supplied only inside this directory transport seam and is never returned
 * through Directory or a command module.
 */
export async function runSaslExchange(exchange: GssapiExchange, mechanism: string, send: SaslBindSender, limits: SaslLimits = {}, security: SaslSecurityOptions = { requiredProtection: "none" }): Promise<SaslSecurityLayer> {
  if (!mechanism || mechanism !== "GSSAPI" && mechanism !== "GSS-SPNEGO") throw failure(`unsupported SASL mechanism ${mechanism || "<empty>"}`);
  const normalized = normalizeLimits(limits);
  const state = { aggregate: 0 };
  const initial = token(await providerCall("GSSAPI initial token", () => exchange.initial()), "client", normalized, state);
  let serverResponse = response(await providerCall("SASL bind", () => send(mechanism, initial)), mechanism);
  let continuations = 0;
  let contextEstablished = false;
  let negotiated: SaslSecurityLayer | undefined;

  for (;;) {
    if (negotiated) {
      if (serverResponse.resultCode !== 0) throw failure(`SASL bind failed with LDAP result code ${serverResponse.resultCode} after security-layer selection`);
      if (serverResponse.serverCredentials !== undefined && serverResponse.serverCredentials.length > 0) throw failure("SASL server returned credentials after final negotiation");
      return negotiated;
    }
    if (serverResponse.resultCode === 0) throw failure("SASL bind completed before mandatory security-layer negotiation");
    if (continuations >= normalized.maxContinuations) throw failure(`SASL exchange exceeded the ${normalized.maxContinuations}-continuation limit`);
    continuations += 1;
    const challenge = serverToken(serverResponse, normalized, state);
    if (!contextEstablished) {
      const next = await providerCall("GSSAPI continuation", () => exchange.step(challenge));
      const clientToken = stepToken(next, normalized, state);
      contextEstablished = next.established === true;
      serverResponse = response(await providerCall("SASL continuation bind", () => send(mechanism, clientToken)), mechanism);
      continue;
    }
    let clearOffer: Buffer;
    if (security.requiredProtection === "none") {
      clearOffer = token(await providerCall("GSSAPI security-layer unwrapping", () => exchange.unwrap(challenge)), "unwrapped server security offer", normalized, state);
      trace("gssapi-rfc4752-offer-unwrap", () => ({ wrappedBytes: challenge.length, clearBytes: clearOffer.length, integrity: false }));
    } else {
      if (!exchange.unwrapWithResult) throw failure("GSSAPI provider cannot prove inbound security-layer integrity");
      const unwrapped = await providerCall("GSSAPI security-layer unwrapping", () => exchange.unwrapWithResult!(challenge));
      if (!unwrapped || unwrapped.integrity !== true) throw failure("GSSAPI provider did not prove inbound security-layer integrity");
      clearOffer = protectResult(unwrapped, "unwrapped server security offer", normalized, state);
      trace("gssapi-rfc4752-offer-unwrap", () => ({ wrappedBytes: challenge.length, clearBytes: clearOffer.length, integrity: unwrapped.integrity }));
    }
    const result = await selectSecurityLayer(exchange, clearOffer, security, normalized, state);
    negotiated = result.negotiated;
    serverResponse = response(await providerCall("SASL security-layer bind", () => send(mechanism, result.selection)), mechanism);
  }
}
