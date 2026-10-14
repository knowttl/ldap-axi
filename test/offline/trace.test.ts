import assert from "node:assert/strict";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import test from "node:test";

const script = `
  import { trace } from "./dist/src/directory/trace.js";
  trace("trace-contract", () => ({ phase: "test", bytes: 3 }));
  trace("trace-contract", () => ({ phase: "test", bytes: 4 }));
`;

const exchangeTraceScript = `
  import { createKerberosProvider } from "./dist/src/directory/gssapi.js";
  import { runSaslExchange } from "./dist/src/directory/sasl.js";
  import { encodeSaslBindRequest } from "./dist/src/directory/sasl-wire.js";
  let providerSteps = 0;
  const provider = createKerberosProvider(async () => ({
    LDAP_AXI_PATCH_LEVEL: 1,
    GSS_C_MUTUAL_FLAG: 2,
    GSS_C_SEQUENCE_FLAG: 8,
    GSS_C_INTEG_FLAG: 32,
    GSS_C_CONF_FLAG: 16,
    GSS_MECH_OID_KRB5: 9,
    initializeClient: async () => ({
      step: async () => {
        providerSteps += 1;
        if (providerSteps > 1) throw new Error("private provider detail");
        return Buffer.from([1]).toString("base64");
      },
      unwrap: async value => value,
      wrap: async value => value,
      unwrapWithResult: async value => ({ response: value, confidential: false, integrity: true }),
      wrapWithResult: async value => ({ response: value, confidential: false, integrity: true }),
      wrapSizeLimit: async value => value - 1,
      contextComplete: false,
      contextFlags: 32,
    }),
  }), "linux");
  encodeSaslBindRequest(1, "GSSAPI", Buffer.alloc(8122));
  const prepared = await provider.prepare("ldap@directory.example.test", { channelBindingData: Buffer.from([1, 2]), protection: "integrity" });
  if (prepared.kind !== "prepared") throw new Error("provider preparation failed");
  await prepared.exchange.step(Buffer.from([3, 4])).catch(() => undefined);
  let sends = 0;
  await runSaslExchange({
    initial: async () => Buffer.from([1]),
    step: async () => ({ token: Buffer.from([2]), established: true }),
    unwrap: async value => value,
    unwrapWithResult: async () => ({ token: Buffer.from([2, 0, 0, 4]), confidential: false, integrity: true }),
    wrap: async value => Buffer.from(value),
    wrapWithResult: async value => ({ token: Buffer.from(value), confidential: false, integrity: true }),
    wrapSizeLimit: async value => value - 1,
  }, "GSSAPI", async () => {
    sends += 1;
    return sends === 1
      ? { resultCode: 14, serverCredentials: Buffer.from([2]) }
      : sends === 2
        ? { resultCode: 14, serverCredentials: Buffer.from([2, 0, 0, 4]) }
        : { resultCode: 0 };
  }, undefined, { requiredProtection: "integrity" });
`;

function runTrace(enabled: boolean, source = script): SpawnSyncReturns<string> {
  const env = { ...process.env };
  if (enabled) env.LDAP_AXI_GSSAPI_TRACE = "1";
  else delete env.LDAP_AXI_GSSAPI_TRACE;
  return spawnSync(process.execPath, ["--input-type=module", "--eval", source], { cwd: process.cwd(), env, encoding: "utf8" });
}

test("redacted trace emits only documented fields when enabled", () => {
  const result = runTrace(true);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
  const records = result.stderr.trim().split("\n").map(line => JSON.parse(line.replace(/^ldap-axi-trace /, "")) as Record<string, unknown>);
  assert.equal(records.length, 2);
  assert.deepEqual(records.map(record => record.bytes), [3, 4]);
  for (const record of records) {
    assert.equal(record.event, "trace-contract");
    assert.equal(record.phase, "test");
    assert.equal(typeof record.elapsedMs, "number");
    assert.deepEqual(Object.keys(record).sort(), ["bytes", "elapsedMs", "event", "phase"]);
  }
  assert.ok(Number(records[1]!.elapsedMs) >= Number(records[0]!.elapsedMs));
});

test("exchange tracing records only redacted provider, step, and RFC 4752 metadata", () => {
  const result = runTrace(true, exchangeTraceScript);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
  const records = result.stderr.trim().split("\n").map(line => JSON.parse(line.replace(/^ldap-axi-trace /, "")) as Record<string, unknown>);
  const events = new Set(records.map(record => record.event));
  for (const event of [
    "gssapi-provider-load-start",
    "gssapi-provider-load-result",
    "gssapi-bind-structure",
    "gssapi-provider-initialize-start",
    "gssapi-provider-initialize-result",
    "gssapi-step-request",
    "gssapi-step-return",
    "gssapi-step-rejection",
    "gssapi-rfc4752-offer-unwrap",
    "gssapi-rfc4752-offer",
    "gssapi-rfc4752-selection-wrap-start",
    "gssapi-rfc4752-selection-wrap-result",
  ]) assert.equal(events.has(event), true, `missing ${event}`);
  const structure = records.find(record => record.event === "gssapi-bind-structure");
  assert.equal(structure?.totalRequestBytes, 8154);
  assert.equal(structure?.credentialsLength, 8122);
  assert.equal(structure?.credentialsLengthHex, "821fba");
  assert.equal(structure?.structuralNestingValid, true);
  for (const record of records) {
    assert.equal(typeof record.elapsedMs, "number");
    assert.equal(Object.values(record).some(value => typeof value === "object"), false);
    assert.doesNotMatch(JSON.stringify(record), /directory\.example\.test|ldap@|provider preparation failed|GSSAPI initial/);
  }
});

test("redacted trace is silent when disabled", () => {
  const result = runTrace(false);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "");
});

test("disabled trace initializes no timing or metadata instrumentation", () => {
  const result = runTrace(false, `
    import { performance } from "node:perf_hooks";
    let timingSamples = 0;
    let metadataBuilds = 0;
    Object.defineProperty(performance, "now", { value: () => { timingSamples += 1; return 1; } });
    const { trace } = await import("./dist/src/directory/trace.js");
    trace("trace-contract", () => { metadataBuilds += 1; return { phase: "test" }; });
    process.stdout.write(JSON.stringify({ timingSamples, metadataBuilds }));
  `);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { timingSamples: 0, metadataBuilds: 0 });
  assert.equal(result.stderr, "");
});
