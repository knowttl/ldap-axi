import assert from "node:assert/strict";
import test from "node:test";
import { createKerberosProvider, GSSAPI_MAX_CHANNEL_BINDING_BYTES, requireConfidentiality, type GssapiPreparation } from "../../src/directory/gssapi.js";
import { CliError } from "../../src/core.js";
import { runSaslExchange } from "../../src/directory/sasl.js";

function prepared(value: GssapiPreparation): asserts value is Extract<GssapiPreparation, { kind: "prepared" }> {
  assert.equal(value.kind, "prepared");
}

for (const { platform, codes, kind } of [
  { platform: "linux", codes: { gssMajor: 7 << 16, gssMinor: 0 }, kind: "no_credentials" },
  { platform: "linux", codes: { gssMajor: 13 << 16, gssMinor: -1765328189 >>> 0 }, kind: "no_credentials" },
  { platform: "linux", codes: { gssMajor: 13 << 16, gssMinor: -1765328243 >>> 0 }, kind: "no_credentials" },
  { platform: "linux", codes: { gssMajor: 13 << 16, gssMinor: -1765328352 >>> 0 }, kind: "credentials_expired" },
  { platform: "linux", codes: { gssMajor: 11 << 16, gssMinor: 0 }, kind: "credentials_expired" },
  { platform: "win32", codes: { sspiCode: 0x8009030e }, kind: "no_credentials" },
  { platform: "win32", codes: { sspiCode: 0x80090317 }, kind: "credentials_expired" },
  { platform: "linux", codes: { gssMajor: 13 << 16, gssMinor: -1765328377 >>> 0 }, kind: "failed" },
] as const) {
  test(`native ${platform} error ${JSON.stringify(codes)} maps by code at initialization and first step`, async () => {
    const error = Object.assign(new Error("private localized native details"), codes);
    const initialization = createKerberosProvider(async () => ({ LDAP_AXI_PATCH_LEVEL: 1, initializeClient: async () => { throw error; } }), platform);
    assert.deepEqual(await initialization.prepare("ldap@directory.example.test"), { kind });
    const firstStep = createKerberosProvider(async () => ({ LDAP_AXI_PATCH_LEVEL: 1, initializeClient: async () => ({ step: async () => { throw error; }, wrap: async () => "", unwrap: async () => "" }) }), platform);
    assert.deepEqual(await firstStep.prepare("ldap@directory.example.test"), { kind });
  });
  test(`native ${platform} continuation error ${JSON.stringify(codes)} retains its public classification`, async () => {
    for (const protection of ["none", "confidentiality"] as const) {
      const provider = createKerberosProvider(async () => ({ LDAP_AXI_PATCH_LEVEL: 1, initializeClient: async () => ({
        step: async (challenge: string) => { if (challenge) throw Object.assign(new Error("private localized native details"), codes); return "AQ=="; },
        wrap: async () => "", unwrap: async () => "",
        wrapWithResult: async () => ({ response: "", confidential: true, integrity: true }),
        unwrapWithResult: async () => ({ response: "", confidential: true, integrity: true }),
        wrapSizeLimit: async () => 1024,
      }) }), platform);
      const result = await provider.prepare("ldap@directory.example.test", { protection });
      prepared(result);
      let binds = 0;
      await assert.rejects(() => runSaslExchange(result.exchange, result.mechanism!, async () => {
        binds += 1;
        return { resultCode: 14, serverCredentials: Buffer.from([1]) };
      }, {}, { requiredProtection: protection }), (error: unknown) => {
        assert.ok(error instanceof CliError);
        assert.equal(error.code, kind === "failed" ? "GSSAPI_NEGOTIATION_FAILED" : "GSSAPI_CREDENTIAL_UNAVAILABLE");
        if (kind !== "failed") assert.match(error.help.join(" "), platform === "win32" ? /Sign in with a domain account/ : /kinit/);
        assert.doesNotMatch(`${error.message} ${error.help.join(" ")}`, /private|localized|native details/);
        return true;
      });
      assert.equal(binds, 1);
    }
  });
}

test("provider adapter converts base64 tokens to and from Buffers", async () => {
  const calls: Array<{ challenge: string; options?: unknown }> = [];
  let complete = false;
  const client = {
    get contextComplete() { return complete; },
    step: async (challenge: string) => {
      calls.push({ challenge });
      if (challenge === "") return "/wA=";
      complete = true;
      return "AP/g";
    },
    unwrap: async (challenge: string) => { calls.push({ challenge }); return "AAM="; },
    wrap: async (challenge: string, options?: unknown) => { calls.push({ challenge, options }); return "AQID"; },
  };
  const provider = createKerberosProvider(async () => ({
    LDAP_AXI_PATCH_LEVEL: 1,
    initializeClient: async (service: string, options?: unknown) => {
      assert.equal(service, "ldap@directory.example.test");
      assert.deepEqual(options, { flags: 42, mechOID: 9 });
      return client;
    },
    GSS_C_MUTUAL_FLAG: 2,
    GSS_C_SEQUENCE_FLAG: 8,
    GSS_C_INTEG_FLAG: 32,
    GSS_MECH_OID_KRB5: 9,
  }), "linux");
  const result = await provider.prepare("ldap@directory.example.test");
  prepared(result);
  assert.deepEqual(await result.exchange.initial(), Buffer.from([0xff, 0x00]));
  assert.deepEqual(await result.exchange.step(Buffer.from([0x01])), { token: Buffer.from([0x00, 0xff, 0xe0]), established: true });
  assert.deepEqual(await result.exchange.unwrap(Buffer.from([0x02])), Buffer.from([0x00, 0x03]));
  assert.deepEqual(await result.exchange.wrap(Buffer.from([0x01, 0x02, 0x03])), Buffer.from([0x01, 0x02, 0x03]));
  assert.deepEqual(calls, [
    { challenge: "" },
    { challenge: "AQ==" },
    { challenge: "Ag==" },
    { challenge: "AQID", options: { protect: false } },
  ]);
  assert.equal(result.mechanism, "GSSAPI");
});

test("provider adapter preserves an empty continuation output", async () => {
  let complete = false;
  const result = await createKerberosProvider(async () => ({
    LDAP_AXI_PATCH_LEVEL: 1,
    initializeClient: async () => ({
      get contextComplete() { return complete; },
      step: async (challenge: string) => {
        if (challenge === "") return "AQ==";
        complete = true;
        return null;
      },
      unwrap: async () => "AA==",
      wrap: async () => "AQ==",
    }),
  }), "linux").prepare("ldap@directory.example.test");
  prepared(result);
  assert.deepEqual(await result.exchange.step(Buffer.from([0x02])), { token: Buffer.alloc(0), established: true });
});

test("the adapter copies bounded channel-binding bytes into initialization options", async () => {
  const source = new Uint8Array([0x00, 0xff, 0x01]);
  let received: Uint8Array | undefined;
  const result = await createKerberosProvider(async () => ({
    LDAP_AXI_PATCH_LEVEL: 1,
    initializeClient: async (_service: string, options?: Readonly<Record<string, unknown>>) => {
      received = options?.channelBindingData as Uint8Array;
      return { step: async () => "AQ==", unwrap: async () => "AA==", wrap: async () => "AQ==" };
    },
  }), "linux").prepare("ldap@directory.example.test", { channelBindingData: source });
  prepared(result);
  source[0] = 0x7f;
  assert.deepEqual(received, Buffer.from([0x00, 0xff, 0x01]));
  assert.deepEqual(await result.exchange.step(Buffer.from([0x02])), { token: Buffer.from([0x01]), established: false });
});

test("preparation options are rejected before provider loading", async () => {
  let loaded = false;
  const provider = createKerberosProvider(async () => {
    loaded = true;
    return {};
  }, "linux");
  await assert.rejects(() => provider.prepare("ldap@directory.example.test", { channelBindingData: new Uint8Array(GSSAPI_MAX_CHANNEL_BINDING_BYTES + 1) }), RangeError);
  await assert.rejects(() => provider.prepare("ldap@directory.example.test", { channelBindingData: "not-bytes" as unknown as Uint8Array }), TypeError);
  await assert.rejects(() => provider.prepare("ldap@directory.example.test", { protection: "privacy" as "none" }), TypeError);
  assert.equal(loaded, false);
});

test("the adapter preserves the absent no-bindings path", async () => {
  let options: Readonly<Record<string, unknown>> | undefined;
  const result = await createKerberosProvider(async () => ({
    LDAP_AXI_PATCH_LEVEL: 1,
    initializeClient: async (_service: string, value?: Readonly<Record<string, unknown>>) => {
      options = value;
      return { step: async () => "AQ==", unwrap: async () => "AA==", wrap: async () => "AQ==" };
    },
  }), "linux").prepare("ldap@directory.example.test");
  prepared(result);
  assert.ok(options);
  assert.equal("channelBindingData" in options, false);
});

test("wrapWithResult exposes actual confidentiality and rejects false results", async () => {
  const result = await createKerberosProvider(async () => ({
    LDAP_AXI_PATCH_LEVEL: 1,
    initializeClient: async () => ({
      step: async () => "AQ==",
      unwrap: async () => "AA==",
      wrap: async () => "AQ==",
      wrapWithResult: async (_challenge: string, options?: Readonly<{ protect?: boolean }>) => ({
        response: options?.protect ? "Ag==" : "AQ==",
        confidential: options?.protect === true,
        integrity: true,
      }),
      wrapSizeLimit: async (maxWrappedBytes: number) => maxWrappedBytes - 48,
    }),
  }), "linux").prepare("ldap@directory.example.test");
  prepared(result);
  const clear = await result.exchange.wrapWithResult!(Buffer.from([0x01]), { protect: false });
  assert.equal(clear.confidential, false);
  assert.equal(clear.integrity, true);
  assert.throws(() => requireConfidentiality(clear), error => error instanceof Error && error.message === "GSSAPI confidentiality was not provided" && !error.message.includes("AQ=="));
  const sealed = await result.exchange.wrapWithResult!(Buffer.from([0x01]), { protect: true });
  assert.equal(await result.exchange.wrapSizeLimit!(4096, { protect: true }), 4048);
  assert.equal(sealed.confidential, true);
  assert.deepEqual(requireConfidentiality(sealed), Buffer.from([0x02]));
});

test("provider results require explicit per-operation integrity proof", async () => {
  const result = await createKerberosProvider(async () => ({
    LDAP_AXI_PATCH_LEVEL: 1,
    initializeClient: async () => ({
      step: async () => "AQ==",
      unwrap: async () => "AA==",
      unwrapWithResult: async () => ({ response: "AA==", confidential: false }),
      wrap: async () => "AQ==",
      wrapWithResult: async () => ({ response: "AQ==", confidential: false }),
      wrapSizeLimit: async (maxWrappedBytes: number) => maxWrappedBytes - 32,
    }),
  }), "linux").prepare("ldap@directory.example.test", { protection: "integrity" });
  prepared(result);
  await assert.rejects(() => result.exchange.wrapWithResult!(Buffer.from([0x01])), /protection result is malformed/);
  await assert.rejects(() => result.exchange.unwrapWithResult!(Buffer.from([0x01])), /protection result is malformed/);
});

test("Windows-compatible provider result does not infer confidentiality from protect intent", async () => {
  const result = await createKerberosProvider(async () => ({
    LDAP_AXI_PATCH_LEVEL: 1,
    initializeClient: async () => ({
      step: async () => "AQ==",
      unwrap: async () => "AA==",
      wrap: async () => "AQ==",
      wrapWithResult: async () => ({ response: "AQ==", confidential: false, integrity: true }),
    }),
  }), "win32").prepare("ldap/directory.example.test");
  prepared(result);
  const wrapped = await result.exchange.wrapWithResult!(Buffer.from([0x01]), { protect: true });
  assert.equal(wrapped.confidential, false);
  assert.equal(wrapped.integrity, true);
  assert.throws(() => requireConfidentiality(wrapped), /confidentiality was not provided/);
});

test("only the patched provider reaches native initialization", async () => {
  let unpatchedInitializations = 0;
  const unpatched = await createKerberosProvider(async () => ({
    initializeClient: async () => {
      unpatchedInitializations += 1;
      throw new Error("must not initialize");
    },
  }), "linux").prepare("ldap@directory.example.test");
  assert.deepEqual(unpatched, { kind: "provider_unavailable" });
  assert.equal(unpatchedInitializations, 0);

  let patchedInitializations = 0;
  const patched = await createKerberosProvider(async () => ({
    LDAP_AXI_PATCH_LEVEL: 1,
    initializeClient: async () => {
      patchedInitializations += 1;
      return { step: async () => "AQ==", unwrap: async () => "AA==", wrap: async () => "AQ==" };
    },
  }), "linux").prepare("ldap@directory.example.test");
  prepared(patched);
  assert.equal(patchedInitializations, 1);
});

test("provider loading and native initialization failures are stable and redact native prose", async () => {
  const unavailable = await createKerberosProvider(async () => { throw new Error("Opening library /sensitive/path failed"); }, "linux").prepare("ldap@directory.example.test");
  assert.deepEqual(unavailable, { kind: "provider_unavailable" });
  const failed = await createKerberosProvider(async () => ({ LDAP_AXI_PATCH_LEVEL: 1, initializeClient: async () => { throw new Error("localized ticket cache details"); } }), "linux").prepare("ldap@directory.example.test");
  assert.deepEqual(failed, { kind: "failed" });
  assert.doesNotMatch(JSON.stringify(failed), /localized|sensitive|path/);
});

test("a Linux dynamic-loader failure reports the exact missing library and nothing else", async () => {
  const dlopenFailure = new Error("/opt/app/build/Release/kerberos.node: libgssapi_krb5.so.2: cannot open shared object file: No such file or directory");
  const named = await createKerberosProvider(async () => { throw dlopenFailure; }, "linux").prepare("ldap@directory.example.test");
  assert.deepEqual(named, { kind: "provider_unavailable", missingLibrary: "libgssapi_krb5.so.2" });
  assert.doesNotMatch(JSON.stringify(named), /opt|kerberos\.node|No such file/);

  const onWindows = await createKerberosProvider(async () => { throw dlopenFailure; }, "win32").prepare("ldap@directory.example.test");
  assert.deepEqual(onWindows, { kind: "provider_unavailable" });

  for (const message of ["Opening library /sensitive/path failed", "/sensitive/path: cannot open shared object file: No such file or directory", "../evil.so: cannot open shared object file"]) {
    const unnamed = await createKerberosProvider(async () => { throw new Error(message); }, "linux").prepare("ldap@directory.example.test");
    assert.deepEqual(unnamed, { kind: "provider_unavailable" });
  }
});

test("Windows adapter requests one OS-selected Negotiate context", async () => {
  let options: unknown;
  const result = await createKerberosProvider(async () => ({
    LDAP_AXI_PATCH_LEVEL: 1,
    initializeClient: async (_service: string, value?: unknown) => { options = value; return { step: async () => "AQ==", unwrap: async () => "AA==", wrap: async () => "AQ==" }; },
    GSS_C_MUTUAL_FLAG: 2,
    GSS_C_SEQUENCE_FLAG: 8,
    GSS_MECH_OID_SPNEGO: 6,
  }), "win32").prepare("ldap/directory.example.test");
  prepared(result);
  assert.equal(result.mechanism, "GSS-SPNEGO");
  assert.deepEqual(options, { flags: 10, mechOID: 6 });
});

test("protection requirements request and verify native capabilities", async () => {
  const cases = [
    { platform: "linux" as const, protection: "none" as const, expectedFlags: 42, contextFlags: 0 },
    { platform: "linux" as const, protection: "integrity" as const, expectedFlags: 42, contextFlags: 32 },
    { platform: "linux" as const, protection: "confidentiality" as const, expectedFlags: 58, contextFlags: 48 },
    { platform: "win32" as const, protection: "none" as const, expectedFlags: 10, contextFlags: 0 },
    { platform: "win32" as const, protection: "integrity" as const, expectedFlags: 42, contextFlags: 32 },
    { platform: "win32" as const, protection: "confidentiality" as const, expectedFlags: 58, contextFlags: 48 },
  ];
  for (const item of cases) {
    let flags: unknown;
    const result = await createKerberosProvider(async () => ({
      LDAP_AXI_PATCH_LEVEL: 1,
      initializeClient: async (_service: string, options?: Readonly<Record<string, unknown>>) => {
        flags = options?.flags;
        return {
          contextComplete: true,
          contextFlags: item.contextFlags,
          username: item.platform === "win32" ? "EXAMPLE\\user" : undefined,
          step: async () => "AQ==",
          unwrap: async () => "AA==",
          unwrapWithResult: async () => ({ response: "AA==", confidential: false, integrity: true }),
          wrap: async () => "AQ==",
          wrapWithResult: async () => ({ response: "AQ==", confidential: false, integrity: true }),
          wrapSizeLimit: async (maxWrappedBytes: number) => maxWrappedBytes - 32,
        };
      },
      GSS_C_MUTUAL_FLAG: 2,
      GSS_C_SEQUENCE_FLAG: 8,
      GSS_C_CONF_FLAG: 16,
      GSS_C_INTEG_FLAG: 32,
    }), item.platform).prepare("ldap@directory.example.test", { protection: item.protection });
    prepared(result);
    assert.equal(flags, item.expectedFlags);
  }

  const missing = await createKerberosProvider(async () => ({
    LDAP_AXI_PATCH_LEVEL: 1,
    initializeClient: async () => ({
      contextComplete: true,
      contextFlags: 32,
      step: async () => "AQ==",
      unwrap: async () => "AA==",
      unwrapWithResult: async () => ({ response: "AA==", confidential: false, integrity: true }),
      wrap: async () => "AQ==",
      wrapWithResult: async () => ({ response: "AQ==", confidential: false, integrity: true }),
      wrapSizeLimit: async (maxWrappedBytes: number) => maxWrappedBytes - 32,
    }),
  }), "linux").prepare("ldap@directory.example.test", { protection: "confidentiality" });
  assert.deepEqual(missing, { kind: "failed" });
});

test("a continuation rejects missing required protection capabilities", async () => {
  let complete = false;
  let steps = 0;
  const result = await createKerberosProvider(async () => ({
    LDAP_AXI_PATCH_LEVEL: 1,
    initializeClient: async () => ({
      get contextComplete() { return complete; },
      contextFlags: 32,
      step: async () => {
        steps += 1;
        if (steps === 2) complete = true;
        return "AQ==";
      },
      unwrap: async () => "AA==",
      unwrapWithResult: async () => ({ response: "AA==", confidential: false, integrity: true }),
      wrap: async () => "AQ==",
      wrapWithResult: async () => ({ response: "AQ==", confidential: false, integrity: true }),
      wrapSizeLimit: async (maxWrappedBytes: number) => maxWrappedBytes - 32,
    }),
  }), "linux").prepare("ldap@directory.example.test", { protection: "confidentiality" });
  prepared(result);
  await assert.rejects(() => result.exchange.step(Buffer.from([0x02])), /required protection was not established/);
});

test("Windows adapter waits for SSPI success across multiple challenges", async () => {
  let username: string | null = null;
  let steps = 0;
  const result = await createKerberosProvider(async () => ({
    LDAP_AXI_PATCH_LEVEL: 1,
    initializeClient: async () => ({
      contextComplete: true,
      get username() { return username; },
      step: async () => {
        steps += 1;
        if (steps === 3) username = "EXAMPLE\\user";
        return "AQ==";
      },
      unwrap: async () => "AA==",
      wrap: async () => "AQ==",
    }),
  }), "win32").prepare("ldap/directory.example.test");
  prepared(result);
  assert.deepEqual(await result.exchange.step(Buffer.from([0x02])), { token: Buffer.from([0x01]), established: false });
  assert.deepEqual(await result.exchange.step(Buffer.from([0x03])), { token: Buffer.from([0x01]), established: true });
});
