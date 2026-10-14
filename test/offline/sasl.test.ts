import assert from "node:assert/strict";
import test from "node:test";
import { CliError } from "../../src/core.js";
import { negotiateNoSecurityLayer, runSaslExchange, SASL_MAX_AGGREGATE_BYTES, SASL_MAX_CONTINUATIONS, SASL_MAX_TOKEN_BYTES, type SaslBindResponse } from "../../src/directory/sasl.js";
import type { GssapiExchange } from "../../src/directory/gssapi.js";

function fakeExchange(initial: Uint8Array, steps: readonly Uint8Array[] = [], offer: Uint8Array = Buffer.from([0x01, 0x00, 0x00, 0x00])): GssapiExchange & { seen: Buffer[]; wrapped: Buffer[] } {
  const seen: Buffer[] = [];
  const wrapped: Buffer[] = [];
  let stepIndex = 0;
  return {
    seen,
    wrapped,
    initial: async () => Buffer.from(initial),
    step: async serverToken => { seen.push(Buffer.from(serverToken)); const value = steps[stepIndex++]; return { token: Buffer.from(value), established: stepIndex === steps.length }; },
    unwrap: async serverToken => { seen.push(Buffer.from(serverToken)); return Buffer.from(offer); },
    wrap: async clientData => { wrapped.push(Buffer.from(clientData)); return Buffer.from(clientData); },
  };
}
function code(error: unknown): string {
  assert.ok(error instanceof CliError);
  return error.code;
}
function sender(responses: readonly SaslBindResponse[]): { send: (mechanism: string, credentials: Uint8Array) => Promise<SaslBindResponse>; mechanisms: string[]; credentials: Buffer[] } {
  let index = 0;
  const mechanisms: string[] = [];
  const credentials: Buffer[] = [];
  return {
    mechanisms,
    credentials,
    send: async (mechanism, value) => { mechanisms.push(mechanism); credentials.push(Buffer.from(value)); return responses[index++] ?? { resultCode: 0 }; },
  };
}
async function rejectsNegotiation(action: () => Promise<unknown>, pattern?: RegExp): Promise<void> {
  await assert.rejects(action, error => error instanceof CliError && error.code === "GSSAPI_NEGOTIATION_FAILED" && (!pattern || pattern.test(error.message)));
}

test("RFC 4752 no-layer negotiation validates the offer and emits the exact four-byte selection", async () => {
  const exchange = fakeExchange(Buffer.from([1]));
  const result = await negotiateNoSecurityLayer(exchange, Buffer.from([0x07, 0x12, 0x34, 0x56]));
  assert.deepEqual(result, Buffer.from([0x01, 0x00, 0x00, 0x00]));
  assert.deepEqual(exchange.wrapped, [Buffer.from([0x01, 0x00, 0x00, 0x00])]);
});
test("RFC 4752 rejects malformed offers and servers that require a security layer", async () => {
  for (const offer of [Buffer.alloc(0), Buffer.from([1, 0, 0]), Buffer.from([1, 0, 0, 0, 0]), Buffer.from([0x80, 0, 0, 0]), Buffer.from([0x02, 0, 0, 0]), Buffer.from([0x01, 0x00, 0x10, 0x00])]) {
    await rejectsNegotiation(() => negotiateNoSecurityLayer(fakeExchange(Buffer.from([1])), offer));
  }
});
test("a protected plan validates the RFC 4752 offer and returns bounded layer limits", async () => {
  const selections: Buffer[] = [];
  const exchange: GssapiExchange = {
    initial: async () => Buffer.from([1]),
    step: async () => ({ token: Buffer.from([2]), established: true }),
    unwrap: async () => Buffer.from([3, 0, 0x10, 0]),
    unwrapWithResult: async () => ({ token: Buffer.from([3, 0, 0x10, 0]), confidential: false, integrity: true }),
    wrap: async value => Buffer.from(value),
    wrapWithResult: async value => { selections.push(Buffer.from(value)); return { token: Buffer.from(value), confidential: false, integrity: true }; },
    wrapSizeLimit: async maxWrappedBytes => maxWrappedBytes - 32,
  };
  const wire = sender([{ resultCode: 14, serverCredentials: Buffer.from([2]) }, { resultCode: 14, serverCredentials: Buffer.from([3]) }, { resultCode: 0 }]);
  const result = await runSaslExchange(exchange, "GSSAPI", wire.send, {}, { requiredProtection: "integrity" });
  assert.deepEqual(result, { protection: "integrity", maxPlaintextBytes: 4064, maxWrappedBytes: 4096, maxInboundPlaintextBytes: 65536, maxInboundWrappedBytes: 65536 });
  assert.deepEqual(selections, [Buffer.from([2, 1, 0, 0])]);
});
test("protected plans reject unproven inbound and outbound protection", async () => {
  const base: GssapiExchange = {
    initial: async () => Buffer.from([1]),
    step: async () => ({ token: Buffer.from([2]), established: true }),
    unwrap: async () => Buffer.from([3, 0, 0x10, 0]),
    unwrapWithResult: async () => ({ token: Buffer.from([3, 0, 0x10, 0]), confidential: false, integrity: false }),
    wrap: async value => Buffer.from(value),
    wrapWithResult: async value => ({ token: Buffer.from(value), confidential: false, integrity: false }),
    wrapSizeLimit: async maxWrappedBytes => maxWrappedBytes - 32,
  };
  const inbound = sender([{ resultCode: 14, serverCredentials: Buffer.from([2]) }, { resultCode: 14, serverCredentials: Buffer.from([3]) }]);
  await rejectsNegotiation(() => runSaslExchange(base, "GSSAPI", inbound.send, {}, { requiredProtection: "integrity" }), /inbound/);
  const outbound = sender([{ resultCode: 14, serverCredentials: Buffer.from([2]) }, { resultCode: 14, serverCredentials: Buffer.from([3]) }]);
  const outboundExchange = { ...base, unwrapWithResult: async () => ({ token: Buffer.from([3, 0, 0x10, 0]), confidential: false, integrity: true }) };
  await rejectsNegotiation(() => runSaslExchange(outboundExchange, "GSSAPI", outbound.send, {}, { requiredProtection: "integrity" }), /outbound/);
});
test("an established context unwraps the next result-code 14 offer and selects no layer", async () => {
  const exchange = fakeExchange(Buffer.from([0xff, 0x00]), [Buffer.from([0x80, 0x01, 0xfe])], Buffer.from([0x03, 0xaa, 0xbb, 0xcc]));
  const wire = sender([
    { resultCode: 14, serverCredentials: Buffer.from([0x00, 0xfe, 0x80]) },
    { resultCode: 14, serverCredentials: Buffer.from([0xde, 0xad, 0xbe, 0xef]) },
    { resultCode: 0 },
  ]);
  await runSaslExchange(exchange, "GSSAPI", wire.send);
  assert.deepEqual(wire.mechanisms, ["GSSAPI", "GSSAPI", "GSSAPI"]);
  assert.deepEqual(wire.credentials, [Buffer.from([0xff, 0x00]), Buffer.from([0x80, 0x01, 0xfe]), Buffer.from([0x01, 0, 0, 0])]);
  assert.deepEqual(exchange.seen, [Buffer.from([0x00, 0xfe, 0x80]), Buffer.from([0xde, 0xad, 0xbe, 0xef])]);
});
test("LDAP success cannot replace the mandatory security-layer exchange", async () => {
  for (const response of [{ resultCode: 0 }, { resultCode: 0, serverCredentials: Buffer.from([0xde, 0xad]) }]) {
    const exchange = fakeExchange(Buffer.from([0x01]));
    const wire = sender([response]);
    await rejectsNegotiation(() => runSaslExchange(exchange, "GSSAPI", wire.send), /before mandatory/);
    assert.deepEqual(wire.credentials, [Buffer.from([0x01])]);
    assert.deepEqual(exchange.seen, []);
  }
});
test("mechanism changes and non-success responses are terminal without fallback", async () => {
  const exchange = fakeExchange(Buffer.from([1]));
  const wire = sender([{ resultCode: 14, mechanism: "PLAIN", serverCredentials: Buffer.from([2]) }]);
  await rejectsNegotiation(() => runSaslExchange(exchange, "GSSAPI", wire.send), /switched/);
  assert.deepEqual(wire.mechanisms, ["GSSAPI"]);
  const diagnostic = "80090308: AcceptSecurityContext error, data 775, private server detail";
  const failed = sender([{ resultCode: 49, diagnosticMessage: diagnostic }]);
  await assert.rejects(
    () => runSaslExchange(exchange, "GSSAPI", failed.send),
    error => error instanceof CliError && error.code === "ACCOUNT_LOCKED" && !error.message.includes("private server detail"),
  );
  assert.deepEqual(failed.mechanisms, ["GSSAPI"]);
});
test("continuation, per-token, and aggregate caps bound one exchange", async () => {
  const continuationResponses = Array.from({ length: SASL_MAX_CONTINUATIONS + 1 }, () => ({ resultCode: 14, serverCredentials: Buffer.from([2]) }));
  const continuationWire = sender(continuationResponses);
  const exchange = fakeExchange(Buffer.from([1]), Array.from({ length: SASL_MAX_CONTINUATIONS + 1 }, () => Buffer.from([3])));
  await rejectsNegotiation(() => runSaslExchange(exchange, "GSSAPI", continuationWire.send), /continuation/);
  assert.equal(continuationWire.mechanisms.length, SASL_MAX_CONTINUATIONS + 1);

  const large = sender([{ resultCode: 14, serverCredentials: Buffer.from([1, 2, 3]) }]);
  await rejectsNegotiation(() => runSaslExchange(fakeExchange(Buffer.alloc(2)), "GSSAPI", large.send, { maxTokenBytes: 1 }), /token/);
  const aggregate = sender([{ resultCode: 14, serverCredentials: Buffer.from([1, 2, 3]) }]);
  await rejectsNegotiation(() => runSaslExchange(fakeExchange(Buffer.from([1, 2])), "GSSAPI", aggregate.send, { maxAggregateBytes: 4 }), /aggregate/);
  assert.ok(SASL_MAX_TOKEN_BYTES > 0 && SASL_MAX_AGGREGATE_BYTES > SASL_MAX_TOKEN_BYTES);
});
test("provider and sender values must remain binary, with no post-bind fallback", async () => {
  const bad: GssapiExchange = {
    initial: async () => Buffer.from([1]),
    step: async () => ({ token: "not bytes" as unknown as Buffer }),
    unwrap: async value => Buffer.from(value),
    wrap: async value => Buffer.from(value),
  };
  const wire = sender([{ resultCode: 14, serverCredentials: Buffer.from([2]) }]);
  await rejectsNegotiation(() => runSaslExchange(bad, "GSSAPI", wire.send), /binary|token/);
  const postNegotiation = sender([
    { resultCode: 14, serverCredentials: Buffer.from([2]) },
    { resultCode: 14, serverCredentials: Buffer.from([3]) },
    { resultCode: 14, serverCredentials: Buffer.from([4]) },
  ]);
  await rejectsNegotiation(() => runSaslExchange(fakeExchange(Buffer.from([1]), [Buffer.from([5])]), "GSSAPI", postNegotiation.send), /after/);
  assert.deepEqual(postNegotiation.mechanisms, ["GSSAPI", "GSSAPI", "GSSAPI"]);
  assert.equal(code(new CliError("GSSAPI_NEGOTIATION_FAILED", "x")), "GSSAPI_NEGOTIATION_FAILED");
});

test("Active Directory's empty final serverSaslCreds completes the exchange, a populated one does not", async () => {
  const rounds = (final: SaslBindResponse): readonly SaslBindResponse[] => [
    { resultCode: 14, serverCredentials: Buffer.from([0x02]) },
    { resultCode: 14, serverCredentials: Buffer.from([0x03]) },
    final,
  ];
  const accepted = await runSaslExchange(fakeExchange(Buffer.from([1]), [Buffer.from([2])]), "GSSAPI", sender(rounds({ resultCode: 0, serverCredentials: Buffer.alloc(0) })).send);
  assert.equal(accepted.protection, "none");
  await rejectsNegotiation(
    () => runSaslExchange(fakeExchange(Buffer.from([1]), [Buffer.from([2])]), "GSSAPI", sender(rounds({ resultCode: 0, serverCredentials: Buffer.from([0x99]) })).send),
    /credentials after final negotiation/,
  );
});
