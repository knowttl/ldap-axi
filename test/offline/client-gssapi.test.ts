import assert from "node:assert/strict";
import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Duplex, getDefaultHighWaterMark, setDefaultHighWaterMark } from "node:stream";
import net from "node:net";
import tls from "node:tls";
import { Client } from "ldapts";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { CliError } from "../../src/core.js";
import { openDirectory } from "../../src/directory/client.js";
import { SaslDataFrameDecoder } from "../../src/directory/protected-stream.js";
import { SaslFrameDecoder } from "../../src/directory/sasl-wire.js";

// These tests drive the transport/SASL handshake through openDirectory's legacy plan builder,
// which derives the GSSAPI mechanism from process.platform ("GSSAPI" on POSIX, "GSS-SPNEGO" on
// Windows). The mocked provider and assertions here fix the POSIX mechanism, so pin the platform
// to keep them deterministic on any runner; node runs each test file in its own process, so this
// stays scoped to this file. The Windows mechanism and flags are covered in gssapi.test.ts.
Object.defineProperty(process, "platform", { value: "linux", configurable: true });

function der(tag: number, value: Uint8Array): Buffer {
  const bytes = Buffer.from(value);
  if (bytes.length < 0x80) return Buffer.concat([Buffer.from([tag, bytes.length]), bytes]);
  const length: number[] = [];
  for (let value = bytes.length; value; value = Math.floor(value / 0x100)) length.unshift(value & 0xff);
  return Buffer.concat([Buffer.from([tag, 0x80 | length.length, ...length]), bytes]);
}

function objectIdentifier(arcs: readonly number[]): Buffer {
  const bytes: number[] = [arcs[0]! * 40 + arcs[1]!];
  for (const arc of arcs.slice(2)) {
    const encoded = [arc & 0x7f];
    for (let value = Math.floor(arc / 0x80); value; value = Math.floor(value / 0x80)) encoded.unshift(0x80 | (value & 0x7f));
    bytes.push(...encoded);
  }
  return Buffer.from(bytes);
}

function algorithm(): Buffer {
  return der(0x30, Buffer.concat([der(0x06, objectIdentifier([1, 2, 840, 113549, 1, 1, 11])), der(0x05, Buffer.alloc(0))]));
}

function name(): Buffer {
  return der(0x30, der(0x31, der(0x30, Buffer.concat([der(0x06, objectIdentifier([2, 5, 4, 3])), der(0x0c, Buffer.from("ldap-axi test"))]))));
}

function utc(value: Date): Buffer {
  const two = (part: number): string => String(part).padStart(2, "0");
  const text = `${two(value.getUTCFullYear() % 100)}${two(value.getUTCMonth() + 1)}${two(value.getUTCDate())}${two(value.getUTCHours())}${two(value.getUTCMinutes())}${two(value.getUTCSeconds())}Z`;
  return der(0x17, Buffer.from(text));
}

function testCertificate(): { key: string; cert: string } {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const now = Date.now();
  const issuer = name();
  const basicConstraints = der(0x30, Buffer.concat([der(0x06, objectIdentifier([2, 5, 29, 19])), der(0x01, Buffer.from([0xff])), der(0x04, der(0x30, der(0x01, Buffer.from([0xff]))))]));
  const subjectAlternativeName = der(0x30, Buffer.concat([der(0x06, objectIdentifier([2, 5, 29, 17])), der(0x04, der(0x30, der(0x82, Buffer.from("localhost"))))]));
  const extensions = der(0xa3, der(0x30, Buffer.concat([basicConstraints, subjectAlternativeName])));
  const tbs = der(0x30, Buffer.concat([
    der(0xa0, der(0x02, Buffer.from([2]))),
    der(0x02, Buffer.from([1])),
    algorithm(),
    issuer,
    der(0x30, Buffer.concat([utc(new Date(now - 60_000)), utc(new Date(now + 86_400_000))])),
    issuer,
    publicKey.export({ type: "spki", format: "der" }),
    extensions,
  ]));
  const signer = createSign("RSA-SHA256");
  signer.update(tbs);
  signer.end();
  const signature = signer.sign(privateKey);
  const cert = der(0x30, Buffer.concat([tbs, algorithm(), der(0x03, Buffer.concat([Buffer.from([0]), signature]))]));
  return { key: privateKey.export({ type: "pkcs8", format: "pem" }).toString(), cert: cert.toString("base64").match(/.{1,64}/g)!.join("\n") };
}

function tlv(tag: number, value: Uint8Array): Buffer { return der(tag, value); }
function integer(value: number): Buffer {
  const bytes: number[] = [];
  for (let current = value; current; current = Math.floor(current / 0x100)) bytes.unshift(current & 0xff);
  if ((bytes[0] ?? 0) & 0x80) bytes.unshift(0);
  return Buffer.from(bytes.length ? bytes : [0]);
}
function ldapMessage(messageId: number, operation: Buffer, controls?: Buffer): Buffer {
  return tlv(0x30, Buffer.concat([tlv(0x02, integer(messageId)), operation, ...(controls ? [controls] : [])]));
}
function bindResponse(messageId: number, resultCode: number, credentials?: Uint8Array): Buffer {
  return ldapMessage(messageId, tlv(0x61, Buffer.concat([
    tlv(0x0a, integer(resultCode)),
    tlv(0x04, Buffer.alloc(0)),
    tlv(0x04, Buffer.alloc(0)),
    ...(credentials === undefined ? [] : [tlv(0x87, credentials)]),
  ])));
}
function pagedControl(): Buffer {
  const value = tlv(0x30, Buffer.concat([tlv(0x02, Buffer.from([0])), tlv(0x04, Buffer.alloc(0))]));
  return tlv(0xa0, tlv(0x30, Buffer.concat([tlv(0x04, Buffer.from("1.2.840.113556.1.4.319")), tlv(0x04, value)])));
}
function rootSearchEntry(messageId: number, capability: string): Buffer {
  const attribute = tlv(0x30, Buffer.concat([tlv(0x04, Buffer.from("supportedCapabilities")), tlv(0x31, tlv(0x04, Buffer.from(capability)))]));
  return ldapMessage(messageId, tlv(0x64, Buffer.concat([tlv(0x04, Buffer.alloc(0)), tlv(0x30, attribute)])));
}
function rootSearchDone(messageId: number): Buffer {
  return ldapMessage(messageId, tlv(0x65, Buffer.concat([tlv(0x0a, Buffer.from([0])), tlv(0x04, Buffer.alloc(0)), tlv(0x04, Buffer.alloc(0))])), pagedControl());
}
type WriteObservations = { returns: boolean[]; drains: number; fragments: number };
async function writeFragmented(socket: tls.TLSSocket, frame: Buffer, observations: WriteObservations): Promise<void> {
  const fragments = [frame.subarray(0, 2), frame.subarray(2)];
  for (const [index, fragment] of fragments.entries()) {
    if (index > 0) await new Promise<void>(resolve => setImmediate(resolve));
    const accepted = socket.write(fragment);
    observations.returns.push(accepted);
    observations.fragments += 1;
    if (!accepted) {
      await once(socket, "drain");
      observations.drains += 1;
    }
  }
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars -- Existing unused helper retained for separate cleanup.
async function writeProtectedFragmented(socket: tls.TLSSocket, plaintext: Buffer, observations: WriteObservations): Promise<void> {
  const frame = Buffer.alloc(4 + plaintext.length);
  frame.writeUInt32BE(plaintext.length, 0);
  plaintext.copy(frame, 4);
  await writeFragmented(socket, frame, observations);
}

type Tlv = Readonly<{ tag: number; value: Buffer; end: number }>;
function readTlv(buffer: Buffer, offset: number): Tlv {
  const first = buffer[offset + 1];
  assert.notEqual(first, undefined);
  const lengthBytes = first! < 0x80 ? 0 : first! & 0x7f;
  const header = lengthBytes ? 2 + lengthBytes : 2;
  let length = lengthBytes ? 0 : first!;
  for (let index = 0; index < lengthBytes; index += 1) length = length * 0x100 + buffer[offset + 2 + index]!;
  const end = offset + header + length;
  assert.ok(end <= buffer.length);
  return { tag: buffer[offset]!, value: buffer.subarray(offset + header, end), end };
}
function request(frame: Buffer): { id: number; tag: number; mechanism?: string; credentialBytes?: number } {
  const message = readTlv(frame, 0);
  const id = readTlv(message.value, 0);
  const operation = readTlv(message.value, id.end);
  if (operation.tag !== 0x60) return { id: id.value.readUIntBE(0, id.value.length), tag: operation.tag };
  const version = readTlv(operation.value, 0);
  const nameValue = readTlv(operation.value, version.end);
  const authentication = readTlv(operation.value, nameValue.end);
  assert.equal(authentication.tag, 0xa3);
  const mechanism = readTlv(authentication.value, 0);
  const credentials = authentication.value.length > mechanism.end ? readTlv(authentication.value, mechanism.end).value : undefined;
  return { id: id.value.readUIntBE(0, id.value.length), tag: operation.tag, mechanism: mechanism.value.toString("ascii"), ...(credentials === undefined ? {} : { credentialBytes: credentials.length }) };
}

function equalBytes(actual: Uint8Array | undefined, expected: Uint8Array | undefined): void {
  if (expected === undefined) assert.equal(actual, undefined);
  else assert.deepEqual(actual, Buffer.from(expected));
}

type FakeTlsSocket = Duplex & {
  authorized: boolean;
  authorizationError: string | null;
  connecting: boolean;
  readyState: string;
  secureConnecting: boolean;
  getPeerCertificate: () => { raw: Buffer };
  reachReady: (emitEvent: boolean) => void;
};

function fakeTlsSocket(certificate: Buffer, onWrite: (socket: FakeTlsSocket, chunk: Buffer) => void, options: Readonly<{ error?: Error; accepted?: boolean }> = {}): FakeTlsSocket {
  const socket = new Duplex({
    read: () => undefined,
    write: (chunk, _encoding, callback) => { if (!options.error) onWrite(socket, Buffer.from(chunk)); callback(options.error); },
    destroy: (error, callback) => callback(error),
  }) as FakeTlsSocket;
  const baseWrite = Duplex.prototype.write.bind(socket);
  const destroy = Duplex.prototype.destroy.bind(socket);
  Object.setPrototypeOf(socket, tls.TLSSocket.prototype);
  Object.defineProperties(socket, {
    authorized: { value: false, writable: true, configurable: true },
    authorizationError: { value: null, writable: true, configurable: true },
    connecting: { value: true, writable: true, configurable: true },
    readyState: { value: "opening", writable: true, configurable: true },
    secureConnecting: { value: true, writable: true, configurable: true },
    getPeerCertificate: { value: () => ({ raw: certificate }), configurable: true },
    ...(options.error ? { write: { value: (_chunk: Uint8Array | string, encoding: BufferEncoding | ((error?: Error | null) => void), callback?: (error?: Error | null) => void) => { const done = typeof encoding === "function" ? encoding : callback; done?.(options.error); return true; }, configurable: true } } : options.accepted === false ? { write: { value: (chunk: Uint8Array | string, encoding: BufferEncoding | ((error?: Error | null) => void), callback?: (error?: Error | null) => void) => { if (typeof encoding === "function") baseWrite(chunk, encoding); else baseWrite(chunk, encoding, callback); return false; }, configurable: true } } : {}),
    reachReady: { value: (emitEvent: boolean) => { socket.authorized = true; socket.connecting = false; socket.readyState = "open"; socket.secureConnecting = false; if (emitEvent) socket.emit("secureConnect"); }, configurable: true },
    destroy: { value: (error?: Error) => { socket.connecting = false; socket.readyState = "closed"; return destroy(error); }, configurable: true },
  });
  return socket;
}

function listen(server: tls.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      assert.ok(address && typeof address !== "string");
      resolve(address.port);
    });
  });
}

function close(server: tls.Server): Promise<void> {
  return new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}

test("GSSAPI TLS readiness handles delayed, already-open, and duplicate inner events", async () => {
  const certificate = testCertificate();
  const rawCertificate = Buffer.from(certificate.cert.replace(/\n/g, ""), "base64");
  const originalConnect = tls.connect;
  for (const mode of ["delayed", "pending-starttls", "already-open", "already-open-and-event"] as const) {
    let socket: FakeTlsSocket | undefined;
    let observedTlsMaxVersion: string | undefined;
    let bindCount = 0;
    let authenticated = false;
    let plainSearchCount = 0;
    let providerInitialCalls = 0;
    let wrapperSocket: (Duplex & { readyState?: string }) | undefined;
    let wrapperReadyEvents = 0;
    let wrapperStateAtSubscription: string | undefined;
    const wrapperReadyStates: string[] = [];
    let wrapperEnds = 0;
    let wrapperCloses = 0;
    let wrapperErrors = 0;
    let releaseFirstResponse: (() => void) | undefined;
    let resolveFirstBind: (() => void) | undefined;
    const firstBind = new Promise<void>(resolve => { resolveFirstBind = resolve; });
    const provider = {
      prepare: async () => ({
        kind: "prepared" as const,
        mechanism: "GSSAPI" as const,
        exchange: {
          initial: async () => { providerInitialCalls += 1; return Buffer.from([0x01]); },
          step: async () => ({ token: Buffer.alloc(0), established: true }),
          unwrap: async (value: Uint8Array) => Buffer.from(value),
          unwrapWithResult: async (value: Uint8Array) => ({ token: Buffer.from(value), confidential: false, integrity: true }),
          wrap: async (value: Uint8Array) => Buffer.from(value),
          wrapWithResult: async (value: Uint8Array) => ({ token: Buffer.from(value), confidential: false, integrity: true }),
          wrapSizeLimit: async (maxWrappedBytes: number) => maxWrappedBytes - 1,
        },
      }),
    };
    const respond = (current: FakeTlsSocket, value: Buffer): void => { queueMicrotask(() => current.emit("data", value)); };
    const onWrite = (current: FakeTlsSocket, chunk: Buffer): void => {
      const parsed = request(chunk);
      if (!authenticated) {
        assert.equal(parsed.tag, 0x60);
        bindCount += 1;
        if (bindCount === 1) {
          resolveFirstBind?.();
          new Promise<void>(resolve => { releaseFirstResponse = resolve; }).then(() => respond(current, bindResponse(parsed.id, 14, Buffer.from([0x01]))));
        } else if (bindCount === 2) {
          respond(current, bindResponse(parsed.id, 14, Buffer.from([0x07, 0x00, 0x10, 0x00])));
        } else {
          assert.equal(bindCount, 3);
          authenticated = true;
          respond(current, bindResponse(parsed.id, 0));
        }
        return;
      }
      assert.equal(chunk[0], 0x30, "post-bind LDAP under TLS is plain BER, not a wrapped frame");
      if (parsed.tag === 0x42) return;
      plainSearchCount += 1;
      respond(current, rootSearchDone(parsed.id));
    };
    const fakeConnect = (...args: unknown[]): tls.TLSSocket => {
      const optionArgument = args.find(value => value && typeof value === "object");
      const options = optionArgument as { maxVersion?: string } | undefined;
      observedTlsMaxVersion = options?.maxVersion;
      socket = fakeTlsSocket(rawCertificate, onWrite);
      if (mode === "delayed") setImmediate(() => socket?.reachReady(true));
      else if (mode === "pending-starttls") {
        socket.connecting = false;
        socket.readyState = "open";
        setImmediate(() => {
          assert.equal(providerInitialCalls, 0);
          assert.equal(bindCount, 0);
          socket?.reachReady(true);
        });
      } else {
        socket.reachReady(false);
        if (mode === "already-open-and-event") queueMicrotask(() => socket?.emit("secureConnect"));
      }
      return socket as unknown as tls.TLSSocket;
    };
    tls.connect = fakeConnect as typeof tls.connect;
    syncBuiltinESMExports();
    type RuntimeClient = { _connect: () => Promise<void> | void; socket?: Duplex & { readyState?: string } };
    const clientPrototype = Client.prototype as unknown as RuntimeClient;
    const originalClientConnect = clientPrototype._connect;
    clientPrototype._connect = function(this: RuntimeClient): Promise<void> | void {
      const result = originalClientConnect.call(this);
      wrapperSocket = this.socket;
      wrapperStateAtSubscription = wrapperSocket?.readyState;
      wrapperSocket?.on("secureConnect", () => {
        wrapperReadyEvents += 1;
        wrapperReadyStates.push(wrapperSocket?.readyState ?? "missing");
      });
      wrapperSocket?.on("end", () => { wrapperEnds += 1; });
      wrapperSocket?.on("close", () => { wrapperCloses += 1; });
      wrapperSocket?.on("error", () => { wrapperErrors += 1; });
      return result;
    };
    try {
      let openingResolved = false;
      const opening = openDirectory({
        url: "ldaps://localhost:636",
        startTls: false,
        caOnly: false,
        tlsNoVerify: false,
        insecurePlaintext: false,
        auth: "gssapi",
        authExplicit: true,
        gssapiService: "ldap@localhost",
        tlsMaxVersion: mode === "delayed" ? "1.2" : undefined,
        gssapiProvider: provider,
        anonymous: false,
        timeoutMs: 1_000,
      });
      void opening.then(() => { openingResolved = true; }, () => undefined);
      await firstBind;
      assert.equal(openingResolved, false);
      assert.equal(wrapperStateAtSubscription, "opening");
      assert.equal(wrapperReadyEvents, 0);
      assert.equal(providerInitialCalls, 1);
      assert.equal(bindCount, 1);
      if (mode === "delayed") assert.equal(observedTlsMaxVersion, "TLSv1.2");
      releaseFirstResponse?.();
      const directory = await opening;
      assert.equal(directory.flavor, "ldapv3");
      assert.equal(wrapperReadyEvents, 1);
      assert.deepEqual(wrapperReadyStates, ["open"]);
      assert.equal(bindCount, 3);
      assert.equal(plainSearchCount, 1);
      if (mode === "pending-starttls") {
        assert.ok(wrapperSocket);
        const wrapperClosed = new Promise<void>(resolve => wrapperSocket!.once("close", resolve));
        socket?.emit("end");
        socket?.emit("close");
        await wrapperClosed;
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(wrapperEnds, 1);
        assert.equal(wrapperCloses, 1);
        assert.equal(wrapperErrors, 0);
      } else {
        await directory.close();
      }
    } finally {
      clientPrototype._connect = originalClientConnect;
      socket?.destroy();
      tls.connect = originalConnect;
      syncBuiltinESMExports();
    }
  }
});

test("a GSSAPI bind write callback error rejects the pending exchange immediately", async () => {
  const certificate = testCertificate();
  const rawCertificate = Buffer.from(certificate.cert.replace(/\n/g, ""), "base64");
  const originalConnect = tls.connect;
  let socket: FakeTlsSocket | undefined;
  let bindWrites = 0;
  const provider = {
    prepare: async () => ({
      kind: "prepared" as const,
      mechanism: "GSSAPI" as const,
      exchange: {
        initial: async () => Buffer.from([0x01]),
        step: async () => ({ token: Buffer.alloc(0), established: true }),
        unwrap: async (value: Uint8Array) => Buffer.from(value),
        wrap: async (value: Uint8Array) => Buffer.from(value),
      },
    }),
  };
  tls.connect = (() => {
    socket = fakeTlsSocket(rawCertificate, () => { bindWrites += 1; }, { error: new Error("private write failure") });
    queueMicrotask(() => socket?.reachReady(true));
    return socket as unknown as tls.TLSSocket;
  }) as typeof tls.connect;
  syncBuiltinESMExports();
  try {
    const startedAt = Date.now();
    const error = await openDirectory({
      url: "ldaps://localhost:636",
      startTls: false,
      caOnly: true,
      tlsNoVerify: false,
      insecurePlaintext: false,
      auth: "gssapi",
      authExplicit: true,
      gssapiService: "ldap@localhost",
      gssapiProvider: provider,
      anonymous: false,
      timeoutMs: 1_000,
    }).then(() => undefined, failure => failure);
    assert.ok(error instanceof CliError);
    assert.deepEqual({ code: error.code, message: error.message }, { code: "GSSAPI_NEGOTIATION_FAILED", message: "LDAP SASL request could not be sent" });
    assert.ok(Date.now() - startedAt < 500, "write callback error was not propagated promptly");
    assert.equal(bindWrites, 0);
    assert.equal(socket?.destroyed, true);
  } finally {
    socket?.destroy();
    tls.connect = originalConnect;
    syncBuiltinESMExports();
  }
});

test("StartTLS passes DNS SNI but verifies IP identities without sending IP SNI", async () => {
  let tlsOptions: tls.ConnectionOptions | undefined;
  const clientPrototype = Client.prototype as unknown as {
    startTLS: (options?: tls.ConnectionOptions) => Promise<void>;
    searchPaginated: () => { next: () => Promise<{ value: { searchEntries: never[]; searchReferences: never[] } }> };
    unbind: () => Promise<void>;
  };
  const originalStartTLS = clientPrototype.startTLS;
  const originalSearchPaginated = clientPrototype.searchPaginated;
  const originalUnbind = clientPrototype.unbind;
  clientPrototype.startTLS = async function(options): Promise<void> { tlsOptions = options; };
  clientPrototype.searchPaginated = () => ({ next: async () => ({ value: { searchEntries: [], searchReferences: [] } }) });
  clientPrototype.unbind = async function(): Promise<void> {};
  try {
    for (const hostname of ["directory.example.test", "127.0.0.1", "[::1]"]) {
      const directory = await openDirectory({
        url: `ldap://${hostname}`,
        startTls: true,
        caOnly: false,
        tlsNoVerify: false,
        tlsMaxVersion: "1.2",
        insecurePlaintext: false,
        anonymous: true,
        timeoutMs: 1_000,
      });
      assert.deepEqual({ servername: tlsOptions?.servername, host: tlsOptions?.host, maxVersion: tlsOptions?.maxVersion }, { servername: hostname === "directory.example.test" ? hostname : undefined, host: hostname.replace(/[[\]]/g, ""), maxVersion: "TLSv1.2" });
      await directory.close();
    }
  } finally {
    clientPrototype.startTLS = originalStartTLS;
    clientPrototype.searchPaginated = originalSearchPaginated;
    clientPrototype.unbind = originalUnbind;
  }
});

test("a TLS 1.2 maximum completes a TLS 1.2-only handshake", async () => {
  const certificate = testCertificate();
  const server = tls.createServer({
    key: certificate.key,
    cert: `-----BEGIN CERTIFICATE-----\n${certificate.cert}\n-----END CERTIFICATE-----\n`,
    minVersion: "TLSv1.2",
    maxVersion: "TLSv1.2",
  });
  let connected: tls.TLSSocket | undefined;
  server.once("secureConnection", socket => { connected = socket; });
  try {
    const port = await listen(server);
    const socket = tls.connect({
      host: "localhost",
      port,
      servername: "localhost",
      ca: `-----BEGIN CERTIFICATE-----\n${certificate.cert}\n-----END CERTIFICATE-----\n`,
      maxVersion: "TLSv1.2",
    });
    await once(socket, "secureConnect");
    assert.equal(socket.getProtocol(), "TLSv1.2");
    socket.end();
    await once(socket, "close");
    assert.ok(connected);
  } finally {
    connected?.destroy();
    await close(server).catch(() => undefined);
  }
});

test("8122-byte GSSAPI credential BER reaches the parser and hands off a no-layer TLS transport", async t => {
  const certificate = testCertificate();
  const temporaryDirectory = await mkdtemp(join(process.cwd(), ".ldap-axi-tls-"));
  const caFile = join(temporaryDirectory, "ca.pem");
  await writeFile(caFile, `-----BEGIN CERTIFICATE-----\n${certificate.cert}\n-----END CERTIFICATE-----\n`);

  const originalByteHighWaterMark = getDefaultHighWaterMark(false);
  setDefaultHighWaterMark(false, 64);
  const requests: Array<{ id: number; tag: number; mechanism?: string; credentialBytes?: number }> = [];
  const initialToken = Buffer.alloc(8122, 0x5a);
  const clientContinuation = Buffer.alloc(8192, 0x6d);
  const serverTokens = [Buffer.alloc(8192, 0x6b), Buffer.alloc(8192, 0x6c)];
  const wrappedOffer = Buffer.from([0xde, 0xad]);
  const server = tls.createServer({ key: certificate.key, cert: `-----BEGIN CERTIFICATE-----\n${certificate.cert}\n-----END CERTIFICATE-----\n` });
  let bindCount = 0;
  let finalSuccessSent = false;
  let finalSuccessResponses = 0;
  let searchCount = 0;
  let providerInitialCalls = 0;
  let serverStep = 0;
  let competingDataEvents = 0;
  let competingDataEventsAtFinalBind = 0;
  let serverPaused = false;
  let serverResumed = false;
  let serverReadDataEvents = 0;
  const serverReadByteCounts: number[] = [];
  const serverWrites: WriteObservations = { returns: [], drains: 0, fragments: 0 };
  let serverFailure: unknown;
  let connectedSocket: tls.TLSSocket | undefined;
  let finalBind: { socket: tls.TLSSocket; messageId: number } | undefined;
  let resolveFinalBindReceived: (() => void) | undefined;
  const finalBindReceived = new Promise<void>(resolve => { resolveFinalBindReceived = resolve; });
  let restoreClientConnect: (() => void) | undefined;
  let restoreTlsConnect: (() => void) | undefined;
  const clientWriteReturns: boolean[] = [];

  server.on("secureConnection", socket => {
    connectedSocket = socket;
    socket.pause();
    serverPaused = socket.isPaused();
    setImmediate(() => {
      socket.resume();
      serverResumed = !socket.isPaused();
    });
    const decoder = new SaslFrameDecoder();
    socket.on("data", chunk => {
      serverReadDataEvents += 1;
      serverReadByteCounts.push(chunk.length);
      try {
        if (finalSuccessSent) assert.equal(chunk[0], 0x30, "post-bind LDAP under TLS is plain BER, not a wrapped frame");
        for (const frame of decoder.push(chunk)) {
          const parsed = request(frame);
          requests.push(parsed);
          if (parsed.tag === 0x60) {
            assert.equal(parsed.mechanism, "GSSAPI");
            bindCount += 1;
            if (bindCount === 1) assert.equal(parsed.credentialBytes, initialToken.length);
            else if (bindCount === 2) assert.equal(parsed.credentialBytes, clientContinuation.length);
            else if (bindCount === 3) {
              if (parsed.credentialBytes !== undefined) continue;
              void writeFragmented(socket, bindResponse(parsed.id, 14, wrappedOffer), serverWrites).catch(error => {
                serverFailure = error;
                socket.destroy();
              });
              continue;
            } else if (bindCount === 4) {
              assert.equal(parsed.credentialBytes, 3);
              finalBind = { socket, messageId: parsed.id };
              competingDataEventsAtFinalBind = competingDataEvents;
              resolveFinalBindReceived?.();
              continue;
            } else throw new Error("unexpected additional SASL bind");
            void writeFragmented(socket, bindResponse(parsed.id, 14, serverTokens[bindCount - 1]!), serverWrites).catch(error => {
              serverFailure = error;
              socket.destroy();
            });
          } else if (parsed.tag === 0x63) {
            assert.equal(finalSuccessSent, true);
            searchCount += 1;
            void writeFragmented(socket, rootSearchDone(parsed.id), serverWrites).catch(error => {
              serverFailure = error;
              socket.destroy();
            });
          } else if (parsed.tag === 0x42) {
            socket.end();
          } else throw new Error("unexpected LDAP operation");
        }
      } catch (error) {
        serverFailure = error;
        socket.destroy();
      }
    });
  });

  const expectedChannelBinding = Buffer.concat([
    Buffer.from("tls-server-end-point:", "ascii"),
    createHash("sha256").update(Buffer.from(certificate.cert.replace(/\n/g, ""), "base64")).digest(),
  ]);
  const provider = {
    prepare: async (_service: string, options?: { channelBindingData?: Uint8Array }) => {
      equalBytes(options?.channelBindingData, expectedChannelBinding);
      return ({
      kind: "prepared" as const,
      mechanism: "GSSAPI" as const,
      exchange: {
        initial: async () => { providerInitialCalls += 1; return initialToken; },
        step: async (challenge: Uint8Array) => {
          assert.equal(challenge.length, serverTokens[serverStep]!.length);
          serverStep += 1;
          return serverStep === 1 ? { token: clientContinuation, established: false } : { token: Buffer.alloc(0), established: true };
        },
        unwrap: async (challenge: Uint8Array) => { equalBytes(challenge, wrappedOffer); return Buffer.from([0x03, 0xaa, 0xbb, 0xcc]); },
        unwrapWithResult: async (challenge: Uint8Array) => challenge.length === wrappedOffer.length && challenge.every((value, index) => value === wrappedOffer[index])
          ? { token: Buffer.from([0x03, 0xaa, 0xbb, 0xcc]), confidential: false, integrity: true }
          : { token: Buffer.from(challenge), confidential: false, integrity: true },
        wrap: async (value: Uint8Array) => { if (value.length === 4) equalBytes(value, Buffer.from([0x01, 0x00, 0x00, 0x00])); return Buffer.from([0x01, 0x02, 0x03]); },
        wrapWithResult: async (value: Uint8Array) => { if (value.length === 4) equalBytes(value, Buffer.from([0x01, 0x00, 0x00, 0x00])); return { token: Buffer.from([0x01, 0x02, 0x03]), confidential: false, integrity: true }; },
        wrapSizeLimit: async (maxWrappedBytes: number) => maxWrappedBytes - 1,
      },
    });
    },
  };

  try {
    const port = await listen(server);
    const url = `ldaps://localhost:${port}`;
    const untrustedError = await openDirectory({
      url,
      startTls: false,
      caOnly: false,
      tlsNoVerify: false,
      insecurePlaintext: false,
      auth: "gssapi",
      authExplicit: true,
      gssapiService: "ldap@localhost",
      gssapiProvider: provider,
      anonymous: false,
      timeoutMs: 1_000,
    }).then(async directory => { await directory.close(); return undefined; }, failure => failure);
    assert.ok(untrustedError instanceof CliError);
    assert.deepEqual(
      { code: untrustedError.code, message: untrustedError.message, help: untrustedError.help },
      {
        code: "TLS_UNTRUSTED",
        message: "certificate verification failed",
        help: ["Use --ca-file <pem> to append a corporate CA, or NODE_EXTRA_CA_CERTS; Node does not use the system trust store"],
      },
    );
    assert.doesNotMatch(`${untrustedError.message}\n${untrustedError.help.join("\n")}`, /localhost|ldap-axi test/);
    assert.equal(providerInitialCalls, 0);
    assert.equal(connectedSocket, undefined);
    assert.equal(requests.length, 0);

    type RuntimeClient = { _connect: () => Promise<void> | void; socket?: { on: (event: string, listener: () => void) => unknown } };
    const clientPrototype = Client.prototype as unknown as RuntimeClient;
    const originalConnect = clientPrototype._connect;
    restoreClientConnect = () => { clientPrototype._connect = originalConnect; };
    clientPrototype._connect = function(this: RuntimeClient): Promise<void> | void {
      const result = originalConnect.call(this);
      this.socket?.on("data", () => { competingDataEvents += 1; });
      return result;
    };
    const originalTlsConnect = tls.connect;
    tls.connect = ((...args: Parameters<typeof tls.connect>) => {
      const native = originalTlsConnect(...args);
      const write = native.write.bind(native) as (...writeArgs: unknown[]) => boolean;
      (native as unknown as { write: (...writeArgs: unknown[]) => boolean }).write = (...writeArgs: unknown[]) => {
        const accepted = write(...writeArgs);
        const forceBackpressure = writeArgs[0] instanceof Uint8Array && writeArgs[0][0] === 0x30;
        clientWriteReturns.push(forceBackpressure ? false : accepted);
        return forceBackpressure ? false : accepted;
      };
      return native;
    }) as typeof tls.connect;
    syncBuiltinESMExports();
    restoreTlsConnect = () => { tls.connect = originalTlsConnect; syncBuiltinESMExports(); };

    const opening = openDirectory({
      url,
      startTls: false,
      caFile,
      caOnly: true,
      tlsNoVerify: false,
      insecurePlaintext: false,
      auth: "gssapi",
      authExplicit: true,
      gssapiService: "ldap@localhost",
      gssapiProvider: provider,
      anonymous: false,
      timeoutMs: 1_000,
    });
    void opening.catch(() => undefined);
    await Promise.race([
      finalBindReceived,
      delay(500, undefined, { ref: false }).then(() => { throw new Error("final SASL bind was not received"); }),
    ]);
    await delay(25, undefined, { ref: false });
    assert.equal(serverFailure, undefined);
    assert.equal(searchCount, 0);
    assert.equal(finalSuccessResponses, 0);
    assert.ok(finalBind);
    finalSuccessSent = true;
    finalSuccessResponses += 1;
    await writeFragmented(finalBind.socket, bindResponse(finalBind.messageId, 0), serverWrites);

    const directory = await opening;
    assert.equal(serverFailure, undefined);
    const exposed = directory as unknown as Record<string, unknown>;
    assert.equal(exposed.client, undefined);
    assert.equal(exposed.socket, undefined);
    assert.equal(exposed.native, undefined);
    assert.equal(exposed.exchange, undefined);
    assert.equal(exposed.wrap, undefined);
    assert.equal(exposed.unwrap, undefined);
    assert.equal(exposed._send, undefined);
    assert.deepEqual(Object.values(directory), ["ldapv3"]);
    const root = await directory.rootDSE();
    assert.equal(root.flavor, "ldapv3");
    assert.deepEqual(root.attributes, {});
    assert.equal(bindCount, 4);
    assert.equal(serverStep, 2);
    assert.equal(providerInitialCalls, 1);
    assert.equal(finalSuccessResponses, 1);
    assert.equal(searchCount, 1);
    const binds = requests.filter(value => value.tag === 0x60);
    assert.deepEqual(binds.map(value => value.id), [1, 2, 3, 4]);
    assert.deepEqual(binds.map(value => value.mechanism), ["GSSAPI", "GSSAPI", "GSSAPI", "GSSAPI"]);
    assert.deepEqual(requests.slice(4).map(value => value.tag), [0x63]);
    await directory.close();
    assert.equal(serverFailure, undefined);
    assert.ok(clientWriteReturns.includes(false), "expected the client native write to report backpressure");
    assert.equal(competingDataEventsAtFinalBind, 0);
    assert.ok(competingDataEvents > 0);
    assert.equal(serverPaused, true);
    assert.equal(serverResumed, true);
    assert.equal(serverReadDataEvents, serverReadByteCounts.length);
    assert.equal(serverReadByteCounts.reduce((total, bytes) => total + bytes, 0) > initialToken.length, true);
    assert.equal(serverWrites.fragments, (bindCount + searchCount) * 2, "expected every server response to use two application writes");
    assert.equal(serverWrites.fragments, serverWrites.returns.length);
    assert.ok(serverWrites.returns.includes(false), "expected a TLS server write to apply backpressure");
    assert.ok(serverWrites.drains > 0, "expected a TLS server write to await drain");
    assert.equal(bindCount, 4);
    assert.equal(finalSuccessResponses, 1);
    assert.equal(searchCount, 1);
    await new Promise<void>(resolve => setImmediate(resolve));
    assert.equal(bindCount, 4);
    assert.equal(searchCount, 1);
    t.diagnostic(JSON.stringify({
      transport: "verified LDAPS",
      negotiatedSecurityLayer: "none",
      rejectedUntrustedConnectionBeforeProvider: true,
      clientTokenBytes: [initialToken.length, clientContinuation.length, 0, 3],
      serverResultCodes: [14, 14, 14, 0],
      serverReadByteCounts,
      serverWriteFragments: serverWrites.fragments,
      clientWriteBackpressure: clientWriteReturns.filter(accepted => !accepted).length,
      serverWriteBackpressure: serverWrites.returns.filter(accepted => !accepted).length,
      serverWriteDrains: serverWrites.drains,
      pausedAndResumedServerStream: serverPaused && serverResumed,
      competingWrapperDataHandler: true,
      competingDataEventsAtFinalBind,
      competingDataEventsAfterHandoff: competingDataEvents,
      requestOrder: requests.map(value => value.tag === 0x60 ? "bind" : "rootDSE"),
      rootDSEAfterFinalBindSuccess: true,
      tokenContentsRecorded: false,
    }));
  } finally {
    restoreTlsConnect?.();
    restoreClientConnect?.();
    connectedSocket?.destroy();
    await close(server).catch(() => undefined);
    setDefaultHighWaterMark(false, originalByteHighWaterMark);
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
});

test("sealed GSSAPI LDAPS handshake uses the connection deadline and closes a stalled transport", { timeout: 3_000 }, async () => {
  const certificate = testCertificate();
  const temporaryDirectory = await mkdtemp(join(process.cwd(), ".ldap-axi-tls-"));
  const caFile = join(temporaryDirectory, "ca.pem");
  await writeFile(caFile, `-----BEGIN CERTIFICATE-----\n${certificate.cert}\n-----END CERTIFICATE-----\n`);

  const requests: Array<{ id: number; tag: number; mechanism?: string; credentialBytes?: number }> = [];
  const server = tls.createServer({ key: certificate.key, cert: `-----BEGIN CERTIFICATE-----\n${certificate.cert}\n-----END CERTIFICATE-----\n` });
  let transportClosed = false;
  let connectedSocket: tls.TLSSocket | undefined;
  let providerInitialCalls = 0;
  let providerStepCalls = 0;
  let serverFailure: unknown;
  let resolveTransportClosed: (() => void) | undefined;
  const transportClose = new Promise<void>(resolve => { resolveTransportClosed = resolve; });

  server.on("secureConnection", socket => {
    connectedSocket = socket;
    socket.once("close", () => {
      transportClosed = true;
      resolveTransportClosed?.();
    });
    const decoder = new SaslFrameDecoder();
    socket.on("data", chunk => {
      try {
        for (const frame of decoder.push(chunk)) requests.push(request(frame));
      } catch (error) {
        serverFailure = error;
        socket.destroy();
      }
    });
  });

  const provider = {
    prepare: async () => ({
      kind: "prepared" as const,
      mechanism: "GSSAPI" as const,
      exchange: {
        initial: async () => { providerInitialCalls += 1; return Buffer.from("private-provider-token"); },
        step: async () => { providerStepCalls += 1; throw new Error("private-provider-detail"); },
        unwrap: async () => { throw new Error("private-provider-detail"); },
        wrap: async () => { throw new Error("private-provider-detail"); },
      },
    }),
  };

  try {
    const port = await listen(server);
    const startedAt = Date.now();
    const error = await openDirectory({
      url: `ldaps://localhost:${port}`,
      startTls: false,
      caFile,
      caOnly: true,
      tlsNoVerify: false,
      insecurePlaintext: false,
      auth: "gssapi",
      authExplicit: true,
      gssapiService: "ldap@localhost",
      gssapiProvider: provider,
      anonymous: false,
      timeoutMs: 75,
    }).then(() => undefined, failure => failure);
    const elapsedMs = Date.now() - startedAt;

    assert.ok(error instanceof CliError);
    assert.deepEqual(
      { code: error.code, message: error.message, help: error.help },
      {
        code: "GSSAPI_NEGOTIATION_FAILED",
        message: "GSSAPI negotiation exceeded the connection deadline",
        help: ["The selected SASL mechanism did not complete its bounded RFC 4752 exchange; no fallback occurred"],
      },
    );
    assert.doesNotMatch(`${error.message}\n${error.help.join("\n")}`, /private-provider|localhost|provider-token/);
    assert.ok(elapsedMs >= 35, `deadline fired too early after ${elapsedMs}ms`);
    assert.ok(elapsedMs < 1_000, `configured deadline was not shared with the handshake: ${elapsedMs}ms`);
    await Promise.race([
      transportClose,
      delay(500, undefined, { ref: false }).then(() => { throw new Error("stalled TLS transport was not closed"); }),
    ]);
    assert.equal(transportClosed, true);
    assert.equal(serverFailure, undefined);
    assert.equal(providerInitialCalls, 1);
    assert.equal(providerStepCalls, 0);
    assert.deepEqual(requests.map(value => value.id), [1]);
    assert.deepEqual(requests.map(value => value.tag), [0x60]);
    assert.deepEqual(requests.map(value => value.mechanism), ["GSSAPI"]);
    assert.equal(requests[0]?.credentialBytes, Buffer.byteLength("private-provider-token"));
  } finally {
    connectedSocket?.destroy();
    await close(server).catch(() => undefined);
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
});

test("the sealed plaintext transport negotiates confidentiality and frames every post-bind PDU", { timeout: 5_000 }, async () => {
  const seal = (value: Uint8Array): Buffer => Buffer.concat([Buffer.from([0xfe]), Buffer.from(value)]);
  const unseal = (value: Uint8Array): Buffer => {
    assert.equal(value[0], 0xfe, "protected frame was not produced by the negotiated context");
    return Buffer.from(value.subarray(1));
  };
  const requests: Array<{ id: number; tag: number; mechanism?: string; credentialBytes?: number }> = [];
  let bindCount = 0;
  let searchCount = 0;
  let handoff = false;
  let selection: Buffer | undefined;
  let serverFailure: unknown;
  let connected: net.Socket | undefined;
  let resolveUnbound: (() => void) | undefined;
  const unbound = new Promise<void>(resolve => { resolveUnbound = resolve; });
  const server = net.createServer(socket => {
    connected = socket;
    const decoder = new SaslFrameDecoder();
    const protectedDecoder = new SaslDataFrameDecoder();
    socket.on("data", chunk => {
      try {
        if (handoff) {
          assert.notEqual(chunk[0], 0x30, "raw LDAP BER crossed the sealed plaintext boundary");
          for (const frame of protectedDecoder.push(chunk)) {
            const message = unseal(frame);
            const parsed = request(message);
            requests.push(parsed);
            if (parsed.tag === 0x42) { resolveUnbound?.(); socket.end(); continue; }
            assert.equal(parsed.tag, 0x63);
            searchCount += 1;
            for (const message of [rootSearchEntry(parsed.id, "1.2.840.113556.1.4.800"), rootSearchDone(parsed.id)]) {
              const response = seal(message);
              const wrapped = Buffer.alloc(4 + response.length);
              wrapped.writeUInt32BE(response.length, 0);
              response.copy(wrapped, 4);
              socket.write(wrapped);
            }
          }
          return;
        }
        for (const frame of decoder.push(chunk)) {
          const parsed = request(frame);
          requests.push(parsed);
          assert.equal(parsed.tag, 0x60);
          assert.equal(parsed.mechanism, "GSSAPI");
          bindCount += 1;
          if (bindCount === 1) socket.write(bindResponse(parsed.id, 14, Buffer.from([0x11])));
          else if (bindCount === 2) socket.write(bindResponse(parsed.id, 14, seal(Buffer.from([0x07, 0x00, 0x10, 0x00]))));
          else {
            handoff = true;
            socket.write(bindResponse(parsed.id, 0));
          }
        }
      } catch (error) {
        serverFailure = error;
        socket.destroy();
      }
    });
  });

  const provider = {
    prepare: async (_service: string, options?: { channelBindingData?: Uint8Array; protection?: string }) => {
      assert.equal(options?.channelBindingData, undefined, "the plaintext transport has no channel binding to supply");
      assert.equal(options?.protection, "confidentiality");
      return {
        kind: "prepared" as const,
        mechanism: "GSSAPI" as const,
        exchange: {
          initial: async () => Buffer.from([0x01]),
          step: async () => ({ token: Buffer.alloc(0), established: true }),
          unwrap: async (value: Uint8Array) => unseal(value),
          unwrapWithResult: async (value: Uint8Array) => ({ token: unseal(value), confidential: true, integrity: true }),
          wrap: async (value: Uint8Array) => seal(value),
          wrapWithResult: async (value: Uint8Array) => {
            if (value.length === 4 && selection === undefined) selection = Buffer.from(value);
            return { token: seal(value), confidential: true, integrity: true };
          },
          wrapSizeLimit: async (maxWrappedBytes: number) => maxWrappedBytes - 8,
        },
      };
    },
  };

  try {
    const port = await new Promise<number>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        const address = server.address();
        assert.ok(address && typeof address !== "string");
        resolve(address.port);
      });
    });
    const directory = await openDirectory({
      url: `ldap://127.0.0.1:${port}`,
      startTls: false,
      caOnly: false,
      tlsNoVerify: false,
      insecurePlaintext: false,
      auth: "gssapi",
      authExplicit: true,
      gssapiService: "ldap@directory.example.test",
      gssapiProvider: provider,
      anonymous: false,
      timeoutMs: 2_000,
    });
    assert.equal(directory.flavor, "ad", "the rootDSE entry's attributes must reach flavor detection");
    await directory.close();
    await Promise.race([unbound, delay(1_000, undefined, { ref: false }).then(() => { throw new Error("the sealed transport did not deliver the unbind"); })]);
    assert.equal(serverFailure, undefined);
    assert.deepEqual(selection, Buffer.from([0x04, 0x01, 0x00, 0x00]));
    assert.equal(bindCount, 3);
    assert.equal(searchCount, 1);
    assert.deepEqual(requests.map(value => value.tag), [0x60, 0x60, 0x60, 0x63, 0x42]);
  } finally {
    connected?.destroy();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});
