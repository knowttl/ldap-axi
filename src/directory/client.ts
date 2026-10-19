import { Client, FilterParser, SearchEntry } from "ldapts";
import { createHash, X509Certificate } from "node:crypto";
import { Duplex } from "node:stream";
import * as net from "node:net";
import * as tls from "node:tls";
import { rootCertificates } from "node:tls";
import { readFile } from "node:fs/promises";
import { isUtf8 } from "node:buffer";
import type { Directory, Entry, RootDse, SearchPage, SearchRequest, ServerFlavor } from "../core.js";
import { attributeBaseName, CliError, ROOT_DSE_ATTRIBUTES } from "../core.js";
import { validateDirectoryUrl, type TlsMaxVersion } from "../config.js";
import { executeSelectedGssapi, protectSelectedGssapiTransport, selectAuthPlan, type AuthMode, type AuthPlan, type CredentialSource } from "./auth.js";
import { createKerberosProvider, type GssapiProvider } from "./gssapi.js";
import { decodeSaslBindResponse, encodeSaslBindRequest, SaslFrameDecoder } from "./sasl-wire.js";
import type { SaslBindResponse, SaslSecurityLayer } from "./sasl.js";
import { requireExtendedOid, requireOperation } from "./policy.js";
import { translateLdapError } from "./errors.js";
import { trace, traceEnabled } from "./trace.js";

export type ConnectOptions = Readonly<{
  url: string;
  startTls: boolean;
  caFile?: string;
  caOnly: boolean;
  tlsNoVerify: boolean;
  tlsMaxVersion?: TlsMaxVersion;
  insecurePlaintext: boolean;
  /** Selected before this function opens the LDAP client. */
  authPlan?: AuthPlan;
  /** Legacy inputs are accepted only to build an AuthPlan before connection. */
  auth?: AuthMode;
  authExplicit?: boolean;
  gssapiService?: string;
  gssapiProtection?: import("./gssapi.js").GssapiProtectionRequirement;
  gssapiProvider?: GssapiProvider;
  credentialSource?: CredentialSource;
  bind?: Readonly<{ dn: string; password: string }>;
  anonymous: boolean;
  timeoutMs?: number;
}>;
const AD_DS = "1.2.840.113556.1.4.800";
const AD_LDS = "1.2.840.113556.1.4.1851";

const BINARY_ATTRIBUTE_NAMES = ["objectSid", "objectGUID", "tokenGroups"] as const;
const BINARY_ATTRIBUTE_BY_NAME = new Map(BINARY_ATTRIBUTE_NAMES.map(name => [name.toLowerCase(), name]));
const searchEntryToObject = SearchEntry.prototype.toObject;
SearchEntry.prototype.toObject = function(requestAttributes, explicitBufferAttributes) {
  const returnedBinaryAttributes = this.attributes
    .map(attribute => attribute.type)
    .filter(type => BINARY_ATTRIBUTE_BY_NAME.has(attributeBaseName(type).toLowerCase()));
  return searchEntryToObject.call(this, requestAttributes, [...new Set([...explicitBufferAttributes, ...returnedBinaryAttributes])]);
};

export function mapAttributes(attributes: Record<string, string | string[] | Buffer | Buffer[]>, requested: readonly string[] = ROOT_DSE_ATTRIBUTES): Record<string, string[]> {
  const canonicalNames = new Map([...ROOT_DSE_ATTRIBUTES, ...requested].map(name => {
    const base = attributeBaseName(name);
    return [base.toLowerCase(), base] as const;
  }));
  const result: Record<string, string[]> = {};
  for (const [key, value] of Object.entries(attributes)) {
    const separator = key.indexOf(";");
    const base = attributeBaseName(key);
    const binaryName = BINARY_ATTRIBUTE_BY_NAME.get(base.toLowerCase());
    const canonicalName = binaryName ?? canonicalNames.get(base.toLowerCase()) ?? base;
    const mappedKey = `${canonicalName}${separator === -1 ? "" : key.slice(separator)}`;
    const items = Array.isArray(value) ? value : [value];
    if (items.length === 0) continue;
    const text: string[] = []; const raw: string[] = [];
    for (const item of items) {
      const binary = binaryName !== undefined || (Buffer.isBuffer(item) && !isUtf8(item));
      if (!binary) text.push(Buffer.isBuffer(item) ? item.toString("utf8") : item);
      else {
        const bytes = Buffer.isBuffer(item) ? item : Buffer.from(item, "utf8");
        text.push(bytes.toString("base64")); raw.push(bytes.toString("base64"));
      }
    }
    result[mappedKey] = text;
    if (raw.length) result[`${mappedKey}_raw`] = raw;
  }
  return result;
}
function flavor(attributes: Record<string, string[]>): ServerFlavor {
  const capabilities = attributes.supportedCapabilities ?? [];
  return capabilities.includes(AD_DS) ? "ad" : capabilities.includes(AD_LDS) ? "adlds" : "ldapv3";
}

class LdapDirectory implements Directory {
  readonly #client: Client;
  readonly #timeLimit: number;
  #root?: RootDse;
  constructor(client: Client, public readonly flavor: ServerFlavor, timeLimit: number, root?: RootDse) {
    this.#client = client;
    this.#timeLimit = timeLimit;
    this.#root = root;
  }
  async rootDSE(): Promise<RootDse> {
    if (this.#root) return this.#root;
    requireOperation("rootDSE");
    try {
      const pages = this.#client.searchPaginated("", { scope: "base", filter: "(objectClass=*)", attributes: [...ROOT_DSE_ATTRIBUTES], timeLimit: this.#timeLimit, paged: { pageSize: 1 } });
      const page = await pages.next();
      // searchPaginated yields plain `{ dn, ...attributes }` entries, exactly as searchPages below
      // destructures them; reading an `attributes` property here fails against every real server.
      const entry = page.value?.searchEntries[0];
      let attributes: Record<string, string[]> = {};
      if (entry) { const { dn, ...values } = entry; attributes = mapAttributes(values); }
      const advertised = attributes.supportedSASLMechanisms ?? [];
      const relevantMechanisms = advertised.filter(value => value === "GSSAPI" || value === "GSS-SPNEGO");
      trace("ldap-rootdse-sasl-capabilities", () => ({ supportedSaslMechanismsCount: advertised.length, supportedSaslMechanisms: relevantMechanisms.join(",") }));
      this.#root = { attributes, flavor: flavor(attributes) };
      return this.#root;
    } catch (error) { throw translateLdapError(error); }
  }
  async *searchPages(request: SearchRequest): AsyncIterable<SearchPage> {
    requireOperation("searchPaged");
    const pages = this.#client.searchPaginated(request.base, { scope: request.scope, filter: FilterParser.parseString(request.filter), attributes: [...request.attributes], explicitBufferAttributes: [...BINARY_ATTRIBUTE_NAMES], timeLimit: this.#timeLimit, paged: { pageSize: request.pageSize } });
    try {
      for await (const page of pages) {
        const entries: Entry[] = page.searchEntries.map(entry => { const { dn, ...attributes } = entry; return { dn: dn.toString(), attributes: mapAttributes(attributes, request.attributes) }; });
        yield { entries, referrals: page.searchReferences };
      }
    } catch (error) {
      const failure = searchFailurePage(error);
      if (failure) { yield failure; return; }
      throw translateLdapError(error);
    }
  }
  async whoami(): Promise<string | undefined> { requireOperation("whoami"); requireExtendedOid("1.3.6.1.4.1.4203.1.11.3"); try { return (await this.#client.exop("1.3.6.1.4.1.4203.1.11.3")).value; } catch (error) { throw translateLdapError(error); } }
  async close(): Promise<void> { requireOperation("unbind"); await this.#client.unbind(); }
}

export function validateFilter(filter: string): void {
  try { FilterParser.parseString(filter); } catch { throw new CliError("VALIDATION_ERROR", "--filter is not a valid LDAP filter", ["Run `ldap-axi entry search --help` for filter syntax"]); }
}

// Composes independently-valid filter fragments under one top-level AND. Each fragment is
// validated to parse standalone first: FilterParser.parseString rejects unbalanced parens and
// rejects two sibling top-level filters (verified locally), so a fragment that parses on its own
// is exactly one self-contained (...) term and textual concatenation cannot let it escape its own
// parentheses or alter the surrounding structure (docs/design/v1.md §8.3).
export function composeFilter(parts: readonly string[]): string {
  for (const part of parts) validateFilter(part);
  return parts.length === 1 ? parts[0] : `(&${parts.join("")})`;
}

function resultCode(error: unknown): number | undefined { const code = (error as { code?: unknown }).code; return typeof code === "number" ? code : undefined; }
export function limitStopReason(error: unknown): SearchPage["stopReason"] | undefined {
  switch (resultCode(error)) {
    case 4: return "server_size_limit";
    case 3: return "server_time_limit";
    case 11: return "server_admin_limit";
    default: return undefined;
  }
}
function referralUris(error: unknown): string[] {
  const candidate = error as { referrals?: unknown; uris?: unknown; message?: unknown };
  const arrays = [candidate.referrals, candidate.uris].filter(Array.isArray).flat() as unknown[];
  const fromFields = arrays.filter((value): value is string => typeof value === "string" && /^ldaps?:\/\//i.test(value));
  const fromMessage = typeof candidate.message === "string" ? candidate.message.match(/ldaps?:\/\/[^\s>"']+/gi) ?? [] : [];
  return [...new Set([...fromFields, ...fromMessage])];
}
export function searchFailurePage(error: unknown): SearchPage | undefined {
  const limit = limitStopReason(error);
  if (limit) return { entries: [], stopReason: limit };
  if (resultCode(error) === 10) {
    const referrals = referralUris(error);
    return { entries: [], referrals, stopReason: "referral" };
  }
  return undefined;
}

type TransportKind = "tls" | "plain";
type TransportSocket = tls.TLSSocket | net.Socket;
type PendingSaslResponse = Readonly<{
  messageId: number;
  resolve: (response: SaslBindResponse) => void;
  reject: (error: unknown) => void;
}>;

const NATIVE_ERROR_CODES = new Set(["EPIPE", "ECONNRESET", "ETIMEDOUT", "ENOTFOUND", "ECONNREFUSED", "ECONNABORTED", "EHOSTUNREACH", "ENETUNREACH"]);

type NativeErrorCategory = "certificate" | "timeout" | "connection" | "unknown";
function nativeErrorCategory(error?: Error | null): NativeErrorCategory {
  const code = (error as { code?: unknown } | null | undefined)?.code;
  if (code === "ETIMEDOUT") return "timeout";
  if (typeof code === "string" && NATIVE_ERROR_CODES.has(code)) return "connection";
  if (/certificate|unable_to_verify|unable_to_get_issuer|self.signed/i.test(error?.message ?? "")) return "certificate";
  return "unknown";
}
function nativeErrorCode(error?: Error | null): string | undefined {
  const code = (error as { code?: unknown } | null | undefined)?.code;
  return typeof code === "string" && NATIVE_ERROR_CODES.has(code) ? code : undefined;
}

function saslFailure(message: string, phase = "transport"): CliError {
  trace("gssapi-negotiation-failure", () => ({ phase }));
  return new CliError("GSSAPI_NEGOTIATION_FAILED", message, ["The selected SASL mechanism did not complete its bounded RFC 4752 exchange; no fallback occurred"]);
}

function tlsUntrusted(): CliError {
  return new CliError("TLS_UNTRUSTED", "certificate verification failed", ["Use --ca-file <pem> to append a corporate CA, or NODE_EXTRA_CA_CERTS; Node does not use the system trust store"]);
}

function tlsChannelBinding(socket: TransportSocket): Buffer {
  trace("gssapi-channel-binding-start", () => ({ tlsSocket: socket instanceof tls.TLSSocket, authorized: socket instanceof tls.TLSSocket && socket.authorized === true }));
  if (!(socket instanceof tls.TLSSocket) || socket.authorized !== true) throw saslFailure("TLS channel binding requires a verified peer certificate");
  const peer = socket.getPeerCertificate();
  const raw = peer && typeof peer === "object" && Buffer.isBuffer(peer.raw) ? peer.raw : undefined;
  if (!raw || raw.length === 0) throw saslFailure("TLS channel binding requires a peer certificate");
  let certificate: X509Certificate;
  try { certificate = new X509Certificate(raw); } catch { throw saslFailure("TLS channel binding certificate is malformed"); }
  const signature = certificate.signatureAlgorithm?.toLowerCase() ?? "";
  const digest = signature.includes("md5") || signature.includes("sha1") ? "sha256" : signature.match(/sha(224|256|384|512)/)?.[0] as "sha224" | "sha256" | "sha384" | "sha512" | undefined;
  if (!digest) throw saslFailure("TLS channel binding certificate uses an unsupported signature digest");
  try {
    const binding = Buffer.concat([Buffer.from("tls-server-end-point:", "ascii"), createHash(digest).update(raw).digest()]);
    trace("gssapi-channel-binding-result", () => ({ certificateBytes: raw.length, bindingBytes: binding.length }));
    return binding;
  } catch { throw saslFailure("TLS channel binding digest is unavailable"); }
}

class GssapiHandshakeSocket extends Duplex {
  readonly #decoder = new SaslFrameDecoder();
  readonly #native: TransportSocket;
  readonly #plan: AuthPlan;
  readonly #transport: TransportKind;
  readonly #readyEvent: "secureConnect" | "connect";
  readonly #timeoutMs: number;
  #outbound?: Duplex;
  #nativeReady = false;
  #pending?: PendingSaslResponse;
  #nextMessageId: number;
  #handshakeTimer?: NodeJS.Timeout;
  #writeSampleTimer?: NodeJS.Timeout;
  #authenticated = false;
  readonly #nativeData = (data: Buffer): void => {
    trace("gssapi-native-data", () => ({ bytes: data.length }));
    this.#receive(data);
  };
  readonly #nativeErrorHandler = (error: Error): void => {
    trace("gssapi-native-error", () => ({ errorPresent: true, errorCategory: nativeErrorCategory(error), ...(nativeErrorCode(error) ? { errorCode: nativeErrorCode(error) } : {}) }));
    this.#nativeError(error);
  };
  readonly #nativeCloseHandler = (): void => {
    trace("gssapi-native-close", () => ({ authenticated: this.#authenticated, nativeReady: this.#nativeReady }));
    this.#nativeClose();
  };
  readonly #nativeEndHandler = (): void => {
    trace("gssapi-native-end", () => ({ authenticated: this.#authenticated, nativeReady: this.#nativeReady }));
    this.#nativeEnd();
  };
  readonly #nativeDrainHandler = (): void => trace("gssapi-native-drain", () => ({ bytesWritten: this.#native.bytesWritten }));

  constructor(native: TransportSocket, plan: AuthPlan, initialMessageId: number, timeoutMs: number, transport: TransportKind) {
    super();
    this.#native = native;
    this.#plan = plan;
    this.#transport = transport;
    this.#readyEvent = transport === "tls" ? "secureConnect" : "connect";
    this.#timeoutMs = timeoutMs;
    this.#nextMessageId = initialMessageId;
    native.on("data", this.#nativeData);
    native.on("error", this.#nativeErrorHandler);
    native.on("close", this.#nativeCloseHandler);
    native.on("end", this.#nativeEndHandler);
    if (traceEnabled) native.on("drain", this.#nativeDrainHandler);
    native.on("timeout", () => this.emit("timeout"));
  }

  get connecting(): boolean { return !this.#authenticated; }
  get readyState(): string { return this.#authenticated ? "open" : "opening"; }

  begin(): void {
    trace("gssapi-deadline-armed", () => ({ timeoutMs: this.#timeoutMs }));
    this.#handshakeTimer = setTimeout(() => {
      trace("gssapi-deadline-fired", () => ({ timeoutMs: this.#timeoutMs }));
      this.destroy(saslFailure("GSSAPI negotiation exceeded the connection deadline", "deadline-timer"));
    }, this.#timeoutMs);
    this.#native.once(this.#readyEvent, () => this.#onNativeReady("event"));
    const alreadyReady = this.#transport === "tls"
      ? this.#native instanceof tls.TLSSocket && this.#native.authorized === true && this.#native.readyState === "open"
      : this.#native.connecting === false && this.#native.readyState === "open";
    if (alreadyReady) queueMicrotask(() => this.#onNativeReady("state"));
  }

  override _read(): void {
    this.#outbound?.resume();
  }

  override _write(chunk: Uint8Array | string, encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    if (!this.#outbound) { callback(saslFailure("LDAP data was written before protected handoff")); return; }
    this.#outbound.write(chunk, encoding, callback);
  }

  override _final(callback: (error?: Error | null) => void): void {
    if (this.#outbound) this.#outbound.end(callback);
    else this.#native.end(callback);
  }

  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    if (this.#handshakeTimer) clearTimeout(this.#handshakeTimer);
    if (this.#writeSampleTimer) clearTimeout(this.#writeSampleTimer);
    this.#handshakeTimer = undefined;
    this.#writeSampleTimer = undefined;
    this.#outbound?.destroy();
    this.#native.destroy();
    callback(error);
  }

  #clearWriteSample(): void {
    if (this.#writeSampleTimer) clearTimeout(this.#writeSampleTimer);
    this.#writeSampleTimer = undefined;
  }

  #scheduleWriteSamples(messageId: number): void {
    if (!traceEnabled || !this.#pending || this.#pending.messageId !== messageId) return;
    const initialBytesWritten = this.#native.bytesWritten;
    let sample = 0;
    const takeSample = (): void => {
      if (!this.#pending || this.#pending.messageId !== messageId) { this.#writeSampleTimer = undefined; return; }
      sample += 1;
      const bytesWritten = this.#native.bytesWritten;
      trace("gssapi-native-write-sample", () => ({ messageId, sample, bytesWritten, bytesWrittenDelta: bytesWritten - initialBytesWritten }));
      if (sample < 3) this.#writeSampleTimer = setTimeout(takeSample, 10);
      else this.#writeSampleTimer = undefined;
    };
    this.#writeSampleTimer = setTimeout(takeSample, 10);
  }

  #resolvePending(response: SaslBindResponse): void {
    const pending = this.#pending;
    if (!pending) return;
    this.#pending = undefined;
    this.#clearWriteSample();
    trace("gssapi-pending-resolve", () => ({ messageId: pending.messageId, resultCode: response.resultCode }));
    pending.resolve(response);
  }

  #rejectPending(error: unknown, reason: "write-callback" | "native-error" | "native-close" | "native-end" | "malformed-response"): void {
    const pending = this.#pending;
    if (!pending) return;
    this.#pending = undefined;
    this.#clearWriteSample();
    trace("gssapi-pending-rejection", () => ({ messageId: pending.messageId, reason }));
    pending.reject(error);
  }

  #receive(data: Buffer): void {
    if (this.#authenticated) return;
    try {
      for (const frame of this.#decoder.push(data)) {
        const response = decodeSaslBindResponse(frame);
        trace("gssapi-bind-response", () => ({ messageId: response.messageId, resultCode: response.resultCode, serverSaslCredsPresent: response.serverCredentials !== undefined, serverSaslCredsBytes: response.serverCredentials?.length ?? 0 }));
        const pending = this.#pending;
        if (!pending || pending.messageId !== response.messageId) throw saslFailure("LDAP SASL response did not match its request");
        this.#resolvePending(response);
      }
    } catch (error) {
      const failure = error instanceof CliError ? error : saslFailure("LDAP SASL response was malformed");
      this.#rejectPending(error, "malformed-response");
      this.destroy(failure);
    }
  }

  #nativeError(error?: Error): void {
    const certificateFailure = this.#native instanceof tls.TLSSocket && (Boolean(this.#native.authorizationError) || /certificate|unable_to_verify|unable_to_get_issuer|self.signed/i.test(error?.message ?? ""));
    const failure = certificateFailure ? tlsUntrusted() : saslFailure("LDAP SASL transport failed");
    if (!this.#nativeReady || this.#authenticated) { this.destroy(failure); return; }
    this.#rejectPending(failure, "native-error");
    this.destroy(failure);
  }

  #nativeClose(): void {
    if (this.destroyed) return;
    if (this.#authenticated) return;
    const failure = this.#nativeReady ? saslFailure("LDAP SASL transport closed") : saslFailure("secure LDAP connection closed");
    this.#rejectPending(failure, "native-close");
    this.destroy(failure);
  }

  #nativeEnd(): void {
    if (this.destroyed || this.#authenticated) return;
    const failure = saslFailure("LDAP SASL transport ended during negotiation");
    this.#rejectPending(failure, "native-end");
    this.destroy(failure);
  }

  async #authenticate(): Promise<void> {
    try {
      const binding = this.#transport === "tls" ? tlsChannelBinding(this.#native) : undefined;
      const negotiated = await executeSelectedGssapi(this.#plan, (mechanism, credentials) => this.#send(mechanism as "GSSAPI" | "GSS-SPNEGO", credentials), undefined, binding ? { channelBindingData: binding } : {});
      await this.#installTransport(negotiated);
      if (this.#handshakeTimer) clearTimeout(this.#handshakeTimer);
      this.#handshakeTimer = undefined;
      this.#authenticated = true;
      trace("gssapi-wrapper-ready", () => ({ transport: this.#transport }));
      this.emit(this.#readyEvent);
    } catch (error) {
      this.destroy(error instanceof CliError ? error : saslFailure("GSSAPI negotiation failed"));
    }
  }

  /** A no-layer plan keeps the native socket; a protected plan never exposes it again. */
  async #installTransport(negotiated: SaslSecurityLayer): Promise<void> {
    this.#native.removeListener("data", this.#nativeData);
    this.#native.removeListener("error", this.#nativeErrorHandler);
    this.#native.removeListener("close", this.#nativeCloseHandler);
    this.#native.removeListener("end", this.#nativeEndHandler);
    if (traceEnabled) this.#native.removeListener("drain", this.#nativeDrainHandler);
    const buffered = this.#decoder.takeBuffered();
    const outbound = negotiated.protection === "none"
      ? this.#native
      : await protectSelectedGssapiTransport(this.#plan, this.#native, negotiated, buffered);
    this.#outbound = outbound;
    outbound.on("data", data => {
      if (!this.push(data)) outbound.pause();
    });
    outbound.on("end", () => this.push(null));
    outbound.on("error", () => this.destroy(saslFailure("GSSAPI protected LDAP transport failed")));
    outbound.on("close", () => { if (!this.destroyed) this.destroy(); });
    if (outbound === this.#native && buffered.length) this.push(buffered);
  }

  #onNativeReady(source: "event" | "state"): void {
    if (this.destroyed || this.#nativeReady) return;
    this.#nativeReady = true;
    trace("gssapi-inner-ready", () => ({ source, transport: this.#transport }));
    void this.#authenticate();
  }

  #send(mechanism: "GSSAPI" | "GSS-SPNEGO", credentials: Uint8Array): Promise<SaslBindResponse> {
    if (this.#pending) return Promise.reject(saslFailure("LDAP SASL exchange sent concurrent requests"));
    const messageId = this.#nextMessageId++;
    const request = encodeSaslBindRequest(messageId, mechanism, credentials);
    trace("gssapi-bind-request", () => ({ messageId, credentialBytes: credentials.length, requestBytes: request.length }));
    return new Promise((resolve, reject) => {
      this.#pending = { messageId, resolve, reject };
      trace("gssapi-native-write-start", () => ({ messageId, writable: this.#native.writable, destroyed: this.#native.destroyed, writableEnded: this.#native.writableEnded, connecting: this.#native.connecting, readyState: this.#native.readyState, bytesWritten: this.#native.bytesWritten }));
      try {
        const accepted = this.#native.write(request, error => {
          trace("gssapi-native-write-callback", () => ({ messageId, errorPresent: error != null, errorCategory: nativeErrorCategory(error), ...(nativeErrorCode(error) ? { errorCode: nativeErrorCode(error) } : {}), bytesWritten: this.#native.bytesWritten }));
          if (error) {
            const failure = saslFailure("LDAP SASL request could not be sent", "first-write");
            this.#rejectPending(failure, "write-callback");
          }
        });
        trace("gssapi-native-write-result", () => ({ messageId, backpressure: accepted === false, bytesWritten: this.#native.bytesWritten }));
        this.#scheduleWriteSamples(messageId);
      } catch {
        trace("gssapi-native-write-callback", () => ({ messageId, errorPresent: true, errorCategory: "unknown", bytesWritten: this.#native.bytesWritten }));
        const failure = saslFailure("LDAP SASL request could not be sent");
        this.#rejectPending(failure, "write-callback");
      }
    });
  }
}

function gssapiSecureConnection(plan: AuthPlan, timeoutMs: number): typeof tls.connect {
  return ((...args: unknown[]) => {
    const options = args.length === 1 && args[0] && typeof args[0] === "object" ? { ...(args[0] as tls.ConnectionOptions) } : undefined;
    trace("gssapi-connect-start", () => ({ transport: "tls" }));
    const native = options ? tls.connect(options) : tls.connect(args[0] as number, args[1] as string, args[2] as tls.ConnectionOptions | undefined);
    const wrapped = new GssapiHandshakeSocket(native, plan, args.length === 1 ? 2 : 1, timeoutMs, "tls");
    wrapped.begin();
    return wrapped as unknown as tls.TLSSocket;
  }) as typeof tls.connect;
}

/** §10.7's sealed plaintext transport: no TLS, no channel binding, and a mandatory confidentiality layer. */
function gssapiPlainConnection(plan: AuthPlan, timeoutMs: number): typeof net.connect {
  return ((...args: unknown[]) => {
    trace("gssapi-connect-start", () => ({ transport: "plain" }));
    const native = net.connect(args[0] as number, args[1] as string);
    const wrapped = new GssapiHandshakeSocket(native, plan, 1, timeoutMs, "plain");
    wrapped.begin();
    return wrapped as unknown as net.Socket;
  }) as typeof net.connect;
}

export async function openDirectory(options: ConnectOptions): Promise<Directory> {
  const url = new URL(validateDirectoryUrl(options.url));
  if (url.protocol === "ldaps:" && options.startTls) throw new CliError("VALIDATION_ERROR", "--start-tls cannot be combined with an ldaps:// URL", ["Use ldaps:// alone, or ldap:// with --start-tls"]);
  const plaintext = url.protocol === "ldap:" && !options.startTls;
  if (options.tlsMaxVersion !== undefined && plaintext) throw new CliError("TLS_REQUIRED", "--tls-max-version requires LDAPS or StartTLS", ["Use ldaps:// or --start-tls"]);
  const gssapiExpected = options.authPlan?.mode === "gssapi" || (!options.authPlan && !options.anonymous && options.auth !== "simple");
  if (gssapiExpected && !plaintext && options.tlsNoVerify) throw new CliError("TLS_REQUIRED", "GSSAPI over TLS requires verified LDAPS or verified StartTLS", ["Use ldaps:// or --start-tls without --tls-no-verify", "Or use ldap:// without --start-tls for the sealed GSSAPI transport"]);
  const plan = options.authPlan ?? await selectAuthPlan({
    requested: options.auth ?? "auto",
    url: options.url,
    credentials: options.bind,
    credentialSource: options.credentialSource,
    serviceOverride: options.gssapiService,
    protection: options.gssapiProtection,
    startTls: options.startTls,
    anonymous: options.anonymous,
    authExplicit: options.authExplicit,
    provider: options.gssapiProvider ?? (options.auth === "simple" ? undefined : createKerberosProvider()),
  });
  if ((options.anonymous && plan.mode !== "anonymous") || (options.bind && plan.mode !== "simple")) throw new CliError("VALIDATION_ERROR", "the selected authentication plan conflicts with legacy connection credentials or anonymous mode");
  // A GSSAPI plan on ldap:// is §10.7's sealed transport: its confidentiality layer encrypts every post-bind
  // PDU, so --insecure-plaintext stays the gate for anonymous and simple binds only.
  if (plaintext && plan.mode !== "gssapi" && !options.insecurePlaintext) throw new CliError("TLS_REQUIRED", "plaintext LDAP requires --insecure-plaintext", ["Use ldaps:// or --start-tls instead"]);
  if (plan.mode === "gssapi" && !plaintext && options.tlsNoVerify) throw new CliError("TLS_REQUIRED", "GSSAPI over TLS requires verified LDAPS or verified StartTLS", ["Use ldaps:// or --start-tls without --tls-no-verify", "Or use ldap:// without --start-tls for the sealed GSSAPI transport"]);
  const extraCa: string[] = [];
  if (options.caFile) {
    try { extraCa.push(await readFile(options.caFile, "utf8")); }
    catch { throw new CliError("VALIDATION_ERROR", "--ca-file could not be read", ["Pass --ca-file <readable-pem> or correct the configured caFile path and permissions"]); }
  }
  const host = url.hostname.replace(/^\[/, "").replace(/\]$/, "");
  // host keeps certificate identity checks correct for socket-based StartTLS without IP SNI.
  const tlsOptions: tls.ConnectionOptions = { host, ...(net.isIP(host) ? {} : { servername: host }), rejectUnauthorized: !options.tlsNoVerify, ...(options.tlsMaxVersion ? { maxVersion: "TLSv1.2" } : {}), ...(extraCa.length ? { ca: options.caOnly ? extraCa : [...rootCertificates, ...extraCa] } : {}) };
  const timeoutMs = options.timeoutMs ?? 30_000;
  const client = new Client({
    url: options.url,
    autoRebind: false,
    timeout: timeoutMs,
    connectTimeout: timeoutMs,
    ...(url.protocol === "ldaps:" ? { tlsOptions } : {}),
    ...(plan.mode !== "gssapi" ? {} : plaintext ? { createConnection: gssapiPlainConnection(plan, timeoutMs) } : { createSecureConnection: gssapiSecureConnection(plan, timeoutMs) }),
  });
  const timeLimit = Math.max(1, Math.ceil(timeoutMs / 1000));
  let tlsUpgraded = false;
  try {
    if (options.startTls) {
      requireOperation("startTLS");
      requireExtendedOid("1.3.6.1.4.1.1466.20037");
      await client.startTLS(tlsOptions);
      tlsUpgraded = true;
    }
    if (plan.mode === "simple") { requireOperation("bind"); await client.bind(plan.credentials!.dn, plan.credentials!.password); }
    const temporary = new LdapDirectory(client, "ldapv3", timeLimit);
    const root = await temporary.rootDSE();
    return new LdapDirectory(client, root.flavor, timeLimit, root);
  } catch (error) {
    const resultCode = (error as { code?: unknown }).code;
    if (!options.startTls || tlsUpgraded || typeof resultCode === "number") await client.unbind().catch(() => undefined);
    throw translateLdapError(error);
  }
}
