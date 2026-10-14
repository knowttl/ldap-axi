import assert from "node:assert/strict";
import test from "node:test";
import { CliError } from "../../src/core.js";
import { decodeSaslBindResponse, encodeSaslBindRequest, SaslFrameDecoder, SASL_MAX_DIAGNOSTIC_BYTES } from "../../src/directory/sasl-wire.js";

function tlv(tag: number, value: Uint8Array): Buffer {
  const bytes = Buffer.from(value);
  if (bytes.length < 0x80) return Buffer.concat([Buffer.from([tag, bytes.length]), bytes]);
  if (bytes.length < 0x100) return Buffer.concat([Buffer.from([tag, 0x81, bytes.length]), bytes]);
  return Buffer.concat([Buffer.from([tag, 0x82, bytes.length >> 8, bytes.length & 0xff]), bytes]);
}

function bindResponse(resultCode: number, credentials?: Uint8Array, diagnostic = ""): Buffer {
  const body = Buffer.concat([
    tlv(0x0a, Buffer.from([resultCode])),
    tlv(0x04, Buffer.alloc(0)),
    tlv(0x04, Buffer.from(diagnostic, "utf8")),
    ...(credentials === undefined ? [] : [tlv(0x87, credentials)]),
  ]);
  return tlv(0x30, Buffer.concat([tlv(0x02, Buffer.from([1])), tlv(0x61, body)]));
}

function rejects(action: () => unknown): void {
  assert.throws(action, error => error instanceof CliError && error.code === "GSSAPI_NEGOTIATION_FAILED");
}

type IndependentTlv = Readonly<{ tag: number; lengthHex: string; length: number; start: number; contentStart: number; end: number; value: Buffer }>;
function independentTlv(buffer: Buffer, start: number, limit = buffer.length): IndependentTlv {
  assert.ok(start + 1 < limit);
  const first = buffer[start + 1]!;
  const count = first < 0x80 ? 0 : first & 0x7f;
  if (first >= 0x80) assert.ok(count > 0 && count <= 4);
  else assert.ok(first < 0x80);
  const contentStart = start + 2 + count;
  assert.ok(contentStart <= limit);
  let length = count === 0 ? first : 0;
  for (let index = 0; index < count; index += 1) length = length * 0x100 + buffer[start + 2 + index]!;
  const end = contentStart + length;
  assert.ok(end <= limit);
  return { tag: buffer[start]!, lengthHex: buffer.subarray(start + 1, contentStart).toString("hex"), length, start, contentStart, end, value: buffer.subarray(contentStart, end) };
}
function independentlyParseBindRequest(buffer: Buffer): Readonly<Record<string, IndependentTlv>> {
  const outer = independentTlv(buffer, 0);
  assert.equal(outer.end, buffer.length);
  const messageId = independentTlv(buffer, outer.contentStart, outer.end);
  const bindRequest = independentTlv(buffer, messageId.end, outer.end);
  const version = independentTlv(buffer, bindRequest.contentStart, bindRequest.end);
  const dn = independentTlv(buffer, version.end, bindRequest.end);
  const sasl = independentTlv(buffer, dn.end, bindRequest.end);
  const mechanism = independentTlv(buffer, sasl.contentStart, sasl.end);
  const credentials = independentTlv(buffer, mechanism.end, sasl.end);
  assert.equal(credentials.end, sasl.end);
  assert.equal(bindRequest.end, outer.end);
  assert.equal(sasl.end, bindRequest.end);
  assert.deepEqual([outer.tag, messageId.tag, bindRequest.tag, version.tag, dn.tag, sasl.tag, mechanism.tag, credentials.tag], [0x30, 0x02, 0x60, 0x02, 0x04, 0xa3, 0x04, 0x04]);
  assert.equal(version.value.toString("hex"), "03");
  assert.equal(dn.length, 0);
  assert.equal(mechanism.value.toString("ascii"), "GSSAPI");
  return { outer, messageId, bindRequest, version, dn, sasl, mechanism, credentials };
}
function mockServer(request: Buffer): Buffer {
  const parsed = independentlyParseBindRequest(request);
  assert.equal(parsed.outer.end, request.length);
  return bindResponse(14, Buffer.from([0x01]));
}

test("binary SASL BindRequest uses LDAP v3 and preserves arbitrary octets", () => {
  const request = encodeSaslBindRequest(1, "GSSAPI", Buffer.from([0xff, 0x00, 0x80]));
  assert.equal(request.toString("hex"), "301902010160140201030400a30d04064753534150490403ff0080");
});

test("independent BER parsing accepts long-form credential boundaries and an 8122-byte mock response", () => {
  const expectedLengthHex = new Map([[127, "7f"], [128, "8180"], [255, "81ff"], [256, "820100"], [4095, "820fff"], [4096, "821000"], [8122, "821fba"]]);
  for (const [size, lengthHex] of expectedLengthHex) {
    const request = encodeSaslBindRequest(1, "GSSAPI", Buffer.alloc(size, 0xa5));
    const parsed = independentlyParseBindRequest(request);
    assert.equal(parsed.credentials.length, size);
    assert.equal(parsed.credentials.lengthHex, lengthHex);
    assert.equal(parsed.outer.start, 0);
    assert.equal(parsed.messageId.start, parsed.outer.contentStart);
    assert.equal(parsed.bindRequest.start, parsed.messageId.end);
    assert.equal(parsed.version.start, parsed.bindRequest.contentStart);
    assert.equal(parsed.dn.start, parsed.version.end);
    assert.equal(parsed.sasl.start, parsed.dn.end);
    assert.equal(parsed.mechanism.start, parsed.sasl.contentStart);
    assert.equal(parsed.credentials.start, parsed.mechanism.end);
    assert.equal(parsed.credentials.end, parsed.sasl.end);
    assert.equal(parsed.bindRequest.end, parsed.outer.end);
    assert.equal(parsed.outer.end, request.length);
    assert.deepEqual(decodeSaslBindResponse(mockServer(request)), { messageId: 1, resultCode: 14, serverCredentials: Buffer.from([0x01]) });
  }
});

test("an empty GSSAPI response omits the optional credentials field", () => {
  const request = encodeSaslBindRequest(3, "GSSAPI", Buffer.alloc(0));
  assert.equal(request.toString("hex"), "3014020103600f0201030400a3080406475353415049");
});

test("SASL frame decoding handles fragmented responses and preserves credentials", () => {
  const decoder = new SaslFrameDecoder();
  const frame = bindResponse(14, Buffer.from([0xff, 0x00, 0x80]));
  assert.deepEqual(decoder.push(frame.subarray(0, 2)), []);
  assert.deepEqual(decoder.push(frame.subarray(2, 7)), []);
  const frames = decoder.push(frame.subarray(7));
  assert.equal(frames.length, 1);
  assert.deepEqual(decodeSaslBindResponse(frames[0]!), { messageId: 1, resultCode: 14, serverCredentials: Buffer.from([0xff, 0x00, 0x80]) });
});

test("SASL handoff preserves bytes trailing the final BindResponse", () => {
  const decoder = new SaslFrameDecoder();
  const response = bindResponse(0);
  const protectedBytes = Buffer.from([0, 0, 0, 3, 1, 2, 3]);
  assert.deepEqual(decoder.push(Buffer.concat([response, protectedBytes])), [response]);
  assert.deepEqual(decoder.takeBuffered(), protectedBytes);
});

test("SASL response decoding preserves bounded diagnostics", () => {
  const diagnostic = "80090308: AcceptSecurityContext error, data 775, v1db1";
  assert.equal(decodeSaslBindResponse(bindResponse(49, undefined, diagnostic)).diagnosticMessage, diagnostic);
  rejects(() => decodeSaslBindResponse(bindResponse(49, undefined, "x".repeat(SASL_MAX_DIAGNOSTIC_BYTES + 1))));
});

test("SASL response decoding rejects malformed and oversized messages", () => {
  rejects(() => decodeSaslBindResponse(Buffer.from([0x30, 0x00, 0x01])));
  rejects(() => decodeSaslBindResponse(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01])));
  const decoder = new SaslFrameDecoder();
  rejects(() => decoder.push(Buffer.from([0x30, 0x84, 0x00, 0x01, 0x04, 0x01])));
});

// Active Directory's encoding, measured live: every length is four-octet long form, minimal or not.
function adTlv(tag: number, value: Uint8Array): Buffer {
  const bytes = Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length, 0);
  return Buffer.concat([Buffer.from([tag, 0x84]), length, bytes]);
}
function adBindResponse(resultCode: number, credentials: Uint8Array): Buffer {
  const body = Buffer.concat([
    adTlv(0x0a, Buffer.from([resultCode])),
    adTlv(0x04, Buffer.alloc(0)),
    adTlv(0x04, Buffer.alloc(0)),
    adTlv(0x87, credentials),
  ]);
  return adTlv(0x30, Buffer.concat([adTlv(0x02, Buffer.from([2])), adTlv(0x61, body)]));
}

test("an AD-style mock server's four-octet lengths decode below and above 128 content bytes", () => {
  for (const credentialBytes of [32, 200]) {
    const credentials = Buffer.alloc(credentialBytes, 0x5a);
    const frame = adBindResponse(14, credentials);
    const contentBytes = frame.length - 6;
    assert.equal(frame[1], 0x84);
    assert.equal(contentBytes < 0x80, credentialBytes === 32);
    const decoder = new SaslFrameDecoder();
    assert.deepEqual(decoder.push(frame.subarray(0, 3)), []);
    assert.deepEqual(decoder.push(frame.subarray(3, 6)), []);
    const frames = decoder.push(frame.subarray(6));
    assert.equal(frames.length, 1);
    assert.deepEqual(decodeSaslBindResponse(frames[0]!), { messageId: 2, resultCode: 14, serverCredentials: credentials });
  }
});

test("SASL frame decoder accepts long-form length headers split across chunks", () => {
  const decoder = new SaslFrameDecoder();
  const frame = bindResponse(0, Buffer.alloc(120));
  assert.equal(frame[1], 0x81);
  assert.deepEqual(decoder.push(frame.subarray(0, 2)), []);
  assert.equal(decoder.push(frame.subarray(2)).length, 1);
});
