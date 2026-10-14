import { CliError } from "../core.js";
import { SASL_MAX_TOKEN_BYTES } from "./sasl.js";
import { trace, traceEnabled } from "./trace.js";

const LDAP_SEQUENCE = 0x30;
const LDAP_INTEGER = 0x02;
const LDAP_ENUMERATION = 0x0a;
const LDAP_OCTET_STRING = 0x04;
const LDAP_BIND_REQUEST = 0x60;
const LDAP_BIND_RESPONSE = 0x61;
const LDAP_SASL_AUTHENTICATION = 0xa3;
const LDAP_SERVER_SASL_CREDENTIALS = 0x87;
export const SASL_MAX_DIAGNOSTIC_BYTES = 1024;
const MAX_FRAME_BYTES = SASL_MAX_TOKEN_BYTES + SASL_MAX_DIAGNOSTIC_BYTES;

export type BinarySaslBindResponse = Readonly<{
  messageId: number;
  resultCode: number;
  diagnosticMessage?: string;
  serverCredentials?: Buffer;
}>;

type Tlv = Readonly<{ tag: number; value: Buffer; end: number }>;

function negotiationFailure(message: string, phase = "ldap-sasl-wire"): CliError {
  trace("gssapi-negotiation-failure", () => ({ phase }));
  return new CliError("GSSAPI_NEGOTIATION_FAILED", message, ["The selected SASL mechanism did not complete its bounded RFC 4752 exchange; no fallback occurred"]);
}

function lengthBytes(length: number): Buffer {
  if (!Number.isInteger(length) || length < 0 || length > 0x0fffffff) throw negotiationFailure("LDAP message is too large");
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  for (let value = length; value > 0; value = Math.floor(value / 0x100)) bytes.unshift(value & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, value: Uint8Array): Buffer {
  const bytes = Buffer.from(value);
  return Buffer.concat([Buffer.from([tag]), lengthBytes(bytes.length), bytes]);
}

type TraceFieldValue = string | number | boolean;

type StructuralTlv = Readonly<{
  tag: number;
  lengthHex: string;
  length: number;
  start: number;
  end: number;
  contentStart: number;
}>;

function structuralTlv(buffer: Buffer, start: number, limit: number): StructuralTlv {
  const firstLength = buffer[start + 1];
  if (firstLength === undefined) throw negotiationFailure("LDAP BindRequest structural trace failed");
  const count = firstLength < 0x80 ? 0 : firstLength & 0x7f;
  const contentStart = start + 2 + count;
  if (count === 0 && firstLength >= 0x80 || count > 4 || contentStart > limit) throw negotiationFailure("LDAP BindRequest structural trace failed");
  let length = count === 0 ? firstLength : 0;
  for (let index = 0; index < count; index += 1) length = length * 0x100 + buffer[start + 2 + index]!;
  const end = contentStart + length;
  if (end > limit) throw negotiationFailure("LDAP BindRequest structural trace failed");
  return { tag: buffer[start]!, lengthHex: buffer.subarray(start + 1, contentStart).toString("hex"), length, start, end, contentStart };
}

function structuralFields(prefix: string, value: StructuralTlv | undefined, parent: StructuralTlv | undefined): Record<string, TraceFieldValue> {
  if (!value) return { [`${prefix}Present`]: false, [`${prefix}Tag`]: -1, [`${prefix}LengthHex`]: "", [`${prefix}Length`]: 0, [`${prefix}Start`]: -1, [`${prefix}End`]: -1, [`${prefix}NestingValid`]: true, [`${prefix}EndEqualsParent`]: false };
  return {
    [`${prefix}Present`]: true,
    [`${prefix}Tag`]: value.tag,
    [`${prefix}LengthHex`]: value.lengthHex,
    [`${prefix}Length`]: value.length,
    [`${prefix}Start`]: value.start,
    [`${prefix}End`]: value.end,
    [`${prefix}NestingValid`]: parent === undefined || value.start >= parent.contentStart && value.end <= parent.end,
    [`${prefix}EndEqualsParent`]: parent !== undefined && value.end === parent.end,
  };
}

function traceBindRequestStructure(request: Buffer, messageId: number, mechanism: string): void {
  const outer = structuralTlv(request, 0, request.length);
  const id = structuralTlv(request, outer.contentStart, outer.end);
  const bind = structuralTlv(request, id.end, outer.end);
  const version = structuralTlv(request, bind.contentStart, bind.end);
  const dn = structuralTlv(request, version.end, bind.end);
  const sasl = structuralTlv(request, dn.end, bind.end);
  const mechanismTlv = structuralTlv(request, sasl.contentStart, sasl.end);
  const credentialsTlv = mechanismTlv.end < sasl.end ? structuralTlv(request, mechanismTlv.end, sasl.end) : undefined;
  const fields: Record<string, TraceFieldValue> = {
    totalRequestBytes: request.length,
    messageIdValue: messageId,
    mechanismName: mechanism,
    versionValue: request[version.contentStart] ?? -1,
    dnEmpty: dn.length === 0,
    structuralNestingValid: outer.end === request.length && id.start === outer.contentStart && bind.end === outer.end && version.start === bind.contentStart && dn.start === version.end && sasl.start === dn.end && mechanismTlv.start === sasl.contentStart && (credentialsTlv === undefined ? mechanismTlv.end === sasl.end : credentialsTlv.end === sasl.end),
    outerEndEqualsTotal: outer.end === request.length,
    bindRequestEndEqualsOuterContent: bind.end === outer.end,
    saslEndEqualsBindRequest: sasl.end === bind.end,
  };
  Object.assign(fields, structuralFields("outer", outer, undefined), structuralFields("messageId", id, outer), structuralFields("bindRequest", bind, outer), structuralFields("version", version, bind), structuralFields("dn", dn, bind), structuralFields("sasl", sasl, bind), structuralFields("mechanism", mechanismTlv, sasl), structuralFields("credentials", credentialsTlv, sasl));
  trace("gssapi-bind-structure", () => fields);
}

function integerBytes(value: number): Buffer {
  if (!Number.isInteger(value) || value <= 0 || value > 0x7fffffff) throw negotiationFailure("LDAP message id is invalid");
  const bytes: number[] = [];
  for (let current = value; current > 0; current = Math.floor(current / 0x100)) bytes.unshift(current & 0xff);
  if ((bytes[0] ?? 0) & 0x80) bytes.unshift(0);
  return Buffer.from(bytes);
}

/** Encodes only the LDAP SASL BindRequest form used by the sealed GSSAPI transport. */
export function encodeSaslBindRequest(messageId: number, mechanism: "GSSAPI" | "GSS-SPNEGO", credentials: Uint8Array): Buffer {
  if (!(credentials instanceof Uint8Array) || credentials.length > SASL_MAX_TOKEN_BYTES) throw negotiationFailure("client SASL credentials are not a bounded binary token");
  const saslCredentials = Buffer.concat([tlv(LDAP_OCTET_STRING, Buffer.from(mechanism, "ascii")), ...(credentials.length ? [tlv(LDAP_OCTET_STRING, credentials)] : [])]);
  const authentication = tlv(LDAP_BIND_REQUEST, Buffer.concat([tlv(LDAP_INTEGER, integerBytes(3)), tlv(LDAP_OCTET_STRING, Buffer.alloc(0)), tlv(LDAP_SASL_AUTHENTICATION, saslCredentials)]));
  const request = tlv(LDAP_SEQUENCE, Buffer.concat([tlv(LDAP_INTEGER, integerBytes(messageId)), authentication]));
  if (traceEnabled) traceBindRequestStructure(request, messageId, mechanism);
  return request;
}

function readLength(buffer: Buffer, offset: number): { length: number; next: number } {
  const first = buffer[offset];
  if (first === undefined) throw negotiationFailure("LDAP message length is incomplete");
  if (first < 0x80) return { length: first, next: offset + 1 };
  const count = first & 0x7f;
  if (count === 0 || count > 4 || offset + count >= buffer.length) throw negotiationFailure("LDAP message length is malformed");
  let length = 0;
  for (let index = 1; index <= count; index++) length = length * 0x100 + (buffer[offset + index] ?? 0);
  // RFC 4511 §5.1 requires a definite length, not a minimal one: Active Directory encodes every LDAPMessage
  // length in four-octet long form, including values below 128, so only the frame bound may reject a length.
  if (length > MAX_FRAME_BYTES) throw negotiationFailure("LDAP message length is outside the bounded SASL transport");
  return { length, next: offset + count + 1 };
}

function readTlv(buffer: Buffer, offset: number, expectedTag?: number): Tlv {
  const tag = buffer[offset];
  if (tag === undefined) throw negotiationFailure("LDAP BindResponse is truncated");
  if (expectedTag !== undefined && tag !== expectedTag) throw negotiationFailure("LDAP BindResponse has an unexpected field");
  const encoded = readLength(buffer, offset + 1);
  const end = encoded.next + encoded.length;
  if (end > buffer.length) throw negotiationFailure("LDAP BindResponse is truncated");
  return { tag, value: buffer.subarray(encoded.next, end), end };
}

function readUnsignedInteger(value: Buffer, label: string): number {
  if (!value.length || value.length > 4 || value[0]! & 0x80) throw negotiationFailure(`${label} is malformed`);
  let result = 0;
  for (const byte of value) result = result * 0x100 + byte;
  return result;
}

/** Decodes one complete LDAP BindResponse. */
export function decodeSaslBindResponse(frame: Uint8Array): BinarySaslBindResponse {
  if (!(frame instanceof Uint8Array)) throw negotiationFailure("LDAP BindResponse is not binary");
  const buffer = Buffer.from(frame);
  const outer = readTlv(buffer, 0, LDAP_SEQUENCE);
  if (outer.end !== buffer.length) throw negotiationFailure("LDAP BindResponse has trailing bytes");
  let offset = 0;
  const id = readTlv(outer.value, offset, LDAP_INTEGER);
  offset = id.end;
  const messageId = readUnsignedInteger(id.value, "LDAP message id");
  if (messageId === 0) throw negotiationFailure("LDAP BindResponse has an invalid message id");
  const response = readTlv(outer.value, offset, LDAP_BIND_RESPONSE);
  if (response.end !== outer.value.length) {
    const controls = readTlv(outer.value, response.end, 0xa0);
    if (controls.end !== outer.value.length) throw negotiationFailure("LDAP BindResponse has trailing fields");
  }
  let responseOffset = 0;
  const status = readTlv(response.value, responseOffset, LDAP_ENUMERATION);
  responseOffset = status.end;
  const matchedDn = readTlv(response.value, responseOffset, LDAP_OCTET_STRING);
  responseOffset = matchedDn.end;
  const diagnostic = readTlv(response.value, responseOffset, LDAP_OCTET_STRING);
  responseOffset = diagnostic.end;
  if (diagnostic.value.length > SASL_MAX_DIAGNOSTIC_BYTES) throw negotiationFailure("LDAP BindResponse diagnostic exceeds the text limit");
  const diagnosticMessage = diagnostic.value.length ? diagnostic.value.toString("utf8") : undefined;
  let serverCredentials: Buffer | undefined;
  while (responseOffset < response.value.length) {
    const field = readTlv(response.value, responseOffset);
    responseOffset = field.end;
    if (field.tag === LDAP_SERVER_SASL_CREDENTIALS) {
      if (serverCredentials !== undefined) throw negotiationFailure("LDAP BindResponse contains duplicate SASL credentials");
      if (field.value.length > SASL_MAX_TOKEN_BYTES) throw negotiationFailure("server SASL credentials exceed the token limit");
      serverCredentials = Buffer.from(field.value);
    } else if (field.tag !== 0xa3) {
      throw negotiationFailure("LDAP BindResponse contains an unexpected field");
    }
  }
  return {
    messageId,
    resultCode: readUnsignedInteger(status.value, "LDAP result code"),
    ...(diagnosticMessage === undefined ? {} : { diagnosticMessage }),
    ...(serverCredentials === undefined ? {} : { serverCredentials }),
  };
}

/** Splits arbitrary socket chunks into bounded BER messages. */
export class SaslFrameDecoder {
  private buffered = Buffer.alloc(0);

  push(chunk: Uint8Array): readonly Buffer[] {
    if (!(chunk instanceof Uint8Array)) throw negotiationFailure("LDAP socket data is not binary");
    if (chunk.length > MAX_FRAME_BYTES * 2 || this.buffered.length > MAX_FRAME_BYTES * 2 - chunk.length) throw negotiationFailure("LDAP SASL response buffer exceeds the bounded transport");
    this.buffered = Buffer.concat([this.buffered, Buffer.from(chunk)]);
    const frames: Buffer[] = [];
    while (this.buffered.length >= 2) {
      const lengthByte = this.buffered[1]!;
      if (lengthByte === 0x80 || lengthByte > 0x84) throw negotiationFailure("LDAP SASL response has an invalid length header");
      const longLengthBytes = lengthByte & 0x7f;
      if (lengthByte >= 0x80 && this.buffered.length < 2 + longLengthBytes) break;
      const encoded = readLength(this.buffered, 1);
      const total = encoded.next + encoded.length;
      if (total > MAX_FRAME_BYTES) throw negotiationFailure("LDAP SASL response exceeds the frame limit");
      if (this.buffered.length < total) break;
      frames.push(Buffer.from(this.buffered.subarray(0, total)));
      this.buffered = Buffer.from(this.buffered.subarray(total));
      break;
    }
    return frames;
  }

  takeBuffered(): Buffer {
    const buffered = this.buffered;
    this.buffered = Buffer.alloc(0);
    return buffered;
  }
}
