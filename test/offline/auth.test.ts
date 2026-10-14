import assert from "node:assert/strict";
import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { resolveSettings } from "../../src/config.js";
import { CliError } from "../../src/core.js";
import { openDirectory } from "../../src/directory/client.js";
import { deriveGssapiService, executeSelectedGssapi, parseAuthMode, selectAuthPlan, type AuthPlan } from "../../src/directory/auth.js";
import { GssapiPreparationError, type GssapiExchange, type GssapiPreparation, type GssapiProvider } from "../../src/directory/gssapi.js";

const exchange: GssapiExchange = {
  initial: async () => Buffer.from([0x01]),
  step: async () => ({ token: Buffer.from([0x02]), established: true }),
  unwrap: async value => Buffer.from(value),
  unwrapWithResult: async value => ({ token: Buffer.from(value), confidential: false, integrity: true }),
  wrap: async value => Buffer.from(value),
  wrapWithResult: async value => ({ token: Buffer.from(value), confidential: false, integrity: true }),
  wrapSizeLimit: async maxWrappedBytes => maxWrappedBytes,
};
function provider(result: GssapiPreparation): GssapiProvider & { services: string[] } {
  const services: string[] = [];
  return { services, prepare: async service => { services.push(service); return result; } };
}
function code(error: unknown): string {
  assert.ok(error instanceof CliError);
  return error.code;
}
async function rejectsCode(action: () => Promise<unknown>, expected: string): Promise<void> {
  await assert.rejects(action, error => error instanceof CliError && error.code === expected);
}
async function completeSelectedGssapi(plan: AuthPlan): Promise<void> {
  let request = 0;
  await executeSelectedGssapi(plan, async () => {
    request += 1;
    if (request === 1) return { resultCode: 14, serverCredentials: Buffer.from([2]) };
    if (request === 2) return { resultCode: 14, serverCredentials: Buffer.from([3, 1, 0, 0]) };
    return { resultCode: 0 };
  });
}

for (const value of ["auto", "gssapi", "simple"] as const) test(`parseAuthMode accepts ${value}`, () => assert.equal(parseAuthMode(value), value));
test("parseAuthMode rejects every other value", () => {
  for (const value of ["", "AUTO", "kerberos", undefined, 1]) assert.throws(() => parseAuthMode(value), error => code(error) === "VALIDATION_ERROR");
});
test("URL-derived services use one host without reverse-DNS or candidate fallback", () => {
  assert.equal(deriveGssapiService("ldaps://directory.example.test:636", "linux"), "ldap@directory.example.test");
  assert.equal(deriveGssapiService("ldaps://directory.example.test:636", "darwin"), "ldap@directory.example.test");
  assert.equal(deriveGssapiService("ldaps://directory.example.test:636", "win32"), "ldap/directory.example.test");
  assert.equal(deriveGssapiService("ldaps://[2001:db8::1]:636", "linux"), "ldap@2001:db8::1");
});
test("IP literals require an explicit service override", async () => {
  await rejectsCode(() => selectAuthPlan({ requested: "auto", url: "ldaps://127.0.0.1:636", provider: provider({ kind: "no_credentials" }) }), "VALIDATION_ERROR");
  const plan = await selectAuthPlan({ requested: "auto", url: "ldaps://127.0.0.1:636", serviceOverride: "ldap/directory.example.test", credentials: { dn: "uid=synthetic", password: "pw" }, provider: provider({ kind: "no_credentials" }) });
  await rejectsCode(() => completeSelectedGssapi(plan), "GSSAPI_CREDENTIAL_UNAVAILABLE");
});
test("explicit simple selection never consults GSSAPI and preserves the credential source", async () => {
  const ambient = provider({ kind: "prepared", exchange });
  const plan = await selectAuthPlan({ requested: "simple", url: "ldaps://directory.example.test", credentials: { dn: "uid=synthetic", password: "pw" }, credentialSource: "environment", provider: ambient });
  assert.equal(plan.mode, "simple");
  assert.equal(plan.credentialSource, "environment");
  assert.deepEqual(plan.credentials, { dn: "uid=synthetic", password: "pw" });
  assert.deepEqual(ambient.services, []);
  assert.equal(Object.isFrozen(plan), true);
  assert.equal(Object.isFrozen(plan.credentials), true);
});
test("the selected GSSAPI plan drives only its sealed exchange and exposes no provider object", async () => {
  const plan = await selectAuthPlan({ requested: "gssapi", url: "ldaps://directory.example.test", platform: "linux", provider: provider({ kind: "prepared", exchange }) });
  const sent: Buffer[] = [];
  await executeSelectedGssapi(plan, async (mechanism, value) => {
    assert.equal(mechanism, "GSSAPI");
    sent.push(Buffer.from(value));
    if (sent.length === 1) return { resultCode: 14, serverCredentials: Buffer.from([2]) };
    if (sent.length === 2) return { resultCode: 14, serverCredentials: Buffer.from([3, 1, 0, 0]) };
    return { resultCode: 0 };
  });
  assert.deepEqual(sent, [Buffer.from([1]), Buffer.from([2]), Buffer.from([1, 0, 0, 0])]);
  assert.equal("initial" in plan, false);
});
test("the URL scheme selects the layer: none under TLS, mandatory confidentiality on plain LDAP", async () => {
  const tls = await selectAuthPlan({ requested: "gssapi", url: "ldaps://directory.example.test", provider: provider({ kind: "prepared", exchange }) });
  const startTls = await selectAuthPlan({ requested: "gssapi", url: "ldap://directory.example.test", startTls: true, provider: provider({ kind: "prepared", exchange }) });
  const plain = await selectAuthPlan({ requested: "gssapi", url: "ldap://directory.example.test", provider: provider({ kind: "prepared", exchange }) });
  assert.deepEqual([tls.protection, startTls.protection, plain.protection], ["none", "none", "confidentiality"]);
  const sent: Buffer[] = [];
  const layer = await executeSelectedGssapi(plain, async (_mechanism, value) => {
    sent.push(Buffer.from(value));
    if (sent.length === 1) return { resultCode: 14, serverCredentials: Buffer.from([2]) };
    if (sent.length === 2) return { resultCode: 14, serverCredentials: Buffer.from([0x07, 0x00, 0x10, 0x00]) };
    return { resultCode: 0 };
  });
  assert.equal(layer.protection, "confidentiality");
  assert.deepEqual(sent[2], Buffer.from([0x04, 0x01, 0x00, 0x00]));
});
test("a requested protection that disagrees with the URL scheme is terminal", async () => {
  await rejectsCode(() => selectAuthPlan({ requested: "gssapi", url: "ldaps://directory.example.test", protection: "confidentiality", provider: provider({ kind: "prepared", exchange }) }), "VALIDATION_ERROR");
  await rejectsCode(() => selectAuthPlan({ requested: "gssapi", url: "ldap://directory.example.test", protection: "none", provider: provider({ kind: "prepared", exchange }) }), "VALIDATION_ERROR");
  const accepted = await selectAuthPlan({ requested: "gssapi", url: "ldap://directory.example.test", protection: "confidentiality", provider: provider({ kind: "prepared", exchange }) });
  assert.equal(accepted.protection, "confidentiality");
});
test("auto selects GSSAPI from a prepared ambient context before any LDAP transport", async () => {
  const ambient = provider({ kind: "prepared", exchange, mechanism: "GSSAPI" });
  const plan = await selectAuthPlan({ requested: "auto", url: "ldaps://directory.example.test", platform: "linux", credentials: { dn: "uid=synthetic", password: "pw" }, credentialSource: "credentials-file", provider: ambient });
  assert.deepEqual({ mode: plan.mode, mechanism: plan.mechanism, service: plan.service }, { mode: "gssapi", mechanism: "GSSAPI", service: "ldap@directory.example.test" });
  assert.equal(plan.credentials, undefined);
  assert.deepEqual(ambient.services, []);
  await completeSelectedGssapi(plan);
  assert.deepEqual(ambient.services, ["ldap@directory.example.test"]);
});
test("auto fails before networking for typed ambient absence or expiry", async () => {
  for (const kind of ["no_credentials", "credentials_expired"] as const) {
    const plan = await selectAuthPlan({ requested: "auto", url: "ldaps://directory.example.test", credentials: { dn: "uid=synthetic", password: "pw" }, credentialSource: "environment", provider: provider({ kind }) });
    await rejectsCode(() => completeSelectedGssapi(plan), "GSSAPI_CREDENTIAL_UNAVAILABLE");
  }
});
test("auto has no fallback for provider absence or any other preparation failure", async () => {
  const credential = { dn: "uid=synthetic", password: "pw" };
  await rejectsCode(() => selectAuthPlan({ requested: "auto", url: "ldaps://directory.example.test", credentials: credential }), "GSSAPI_UNAVAILABLE");
  for (const [result, expected] of [
    [{ kind: "provider_unavailable" } as GssapiPreparation, "GSSAPI_UNAVAILABLE"],
    [{ kind: "failed" } as GssapiPreparation, "GSSAPI_PREPARATION_FAILED"],
    [{ kind: "prepared" } as GssapiPreparation, "GSSAPI_PREPARATION_FAILED"],
  ] as const) {
    const plan = await selectAuthPlan({ requested: "auto", url: "ldaps://directory.example.test", credentials: credential, provider: provider(result) });
    await rejectsCode(() => completeSelectedGssapi(plan), expected);
  }
  for (const [error, expected] of [[new GssapiPreparationError({ kind: "failed" }), "GSSAPI_PREPARATION_FAILED"], [new GssapiPreparationError({ kind: "no_credentials" }), "GSSAPI_CREDENTIAL_UNAVAILABLE"]] as const) {
    const plan = await selectAuthPlan({ requested: "auto", url: "ldaps://directory.example.test", credentials: credential, provider: { prepare: async () => { throw error; } } });
    await rejectsCode(() => completeSelectedGssapi(plan), expected);
  }
});
test("auto reports typed ambient absence before networking", async () => {
  const plan = await selectAuthPlan({ requested: "auto", url: "ldaps://directory.example.test", provider: provider({ kind: "no_credentials" }) });
  await rejectsCode(() => completeSelectedGssapi(plan), "GSSAPI_CREDENTIAL_UNAVAILABLE");
});
test("provider unavailable names the Linux dynamic-loader remedy", async () => {
  const plan = await selectAuthPlan({ requested: "gssapi", url: "ldaps://directory.example.test", provider: provider({ kind: "provider_unavailable" }) });
  await assert.rejects(() => completeSelectedGssapi(plan), error => {
    assert.ok(error instanceof CliError);
    assert.equal(error.code, "GSSAPI_UNAVAILABLE");
    assert.match(error.help[0]!, /libgssapi_krb5\.so\.2/);
    assert.match(error.help[0]!, /Nix\/WSL/);
    return true;
  });
});
test("a named missing library becomes the first GSSAPI_UNAVAILABLE remedy", async () => {
  const unavailable: GssapiPreparation = { kind: "provider_unavailable", missingLibrary: "libgssapi_krb5.so.2" };
  const plan = await selectAuthPlan({ requested: "gssapi", url: "ldaps://directory.example.test", provider: provider(unavailable) });
  await assert.rejects(() => completeSelectedGssapi(plan), error => {
    assert.ok(error instanceof CliError);
    assert.equal(error.code, "GSSAPI_UNAVAILABLE");
    assert.match(error.help[0]!, /Install the system library libgssapi_krb5\.so\.2/);
    assert.equal(error.help.length, 3);
    return true;
  });
  const thrown = await selectAuthPlan({ requested: "gssapi", url: "ldaps://directory.example.test", provider: { prepare: async () => { throw new GssapiPreparationError(unavailable); } } });
  await assert.rejects(() => completeSelectedGssapi(thrown), error => {
    assert.ok(error instanceof CliError);
    assert.match(error.help[0]!, /libgssapi_krb5\.so\.2/);
    return true;
  });
});
test("explicit GSSAPI never falls back to simple credentials", async () => {
  const credential = { dn: "uid=synthetic", password: "pw" };
  for (const kind of ["no_credentials", "credentials_expired"] as const) {
    const plan = await selectAuthPlan({ requested: "gssapi", url: "ldaps://directory.example.test", credentials: credential, provider: provider({ kind }) });
    await rejectsCode(() => completeSelectedGssapi(plan), "GSSAPI_CREDENTIAL_UNAVAILABLE");
  }
  const unavailable = await selectAuthPlan({ requested: "gssapi", url: "ldaps://directory.example.test", provider: provider({ kind: "provider_unavailable" }) });
  await rejectsCode(() => completeSelectedGssapi(unavailable), "GSSAPI_UNAVAILABLE");
});
test("the client rejects conflicting plans and unverified GSSAPI before opening LDAP", async () => {
  const plan = await selectAuthPlan({ requested: "simple", url: "ldaps://directory.example.test", credentials: { dn: "uid=synthetic", password: "pw" } });
  await rejectsCode(() => openDirectory({ url: "ldaps://directory.example.test", startTls: false, caOnly: false, tlsNoVerify: false, insecurePlaintext: false, authPlan: plan, anonymous: true }), "VALIDATION_ERROR");
  const gssapi = await selectAuthPlan({ requested: "gssapi", url: "ldaps://directory.example.test", provider: provider({ kind: "prepared", exchange }) });
  await rejectsCode(() => openDirectory({ url: "ldaps://directory.example.test", startTls: false, caOnly: false, tlsNoVerify: true, insecurePlaintext: false, authPlan: gssapi, anonymous: false }), "TLS_REQUIRED");
});
test("plain GSSAPI carries the confidentiality layer instead of requiring --insecure-plaintext", async () => {
  const plan = await selectAuthPlan({ requested: "gssapi", url: "ldap://directory.example.test", provider: provider({ kind: "prepared", exchange }) });
  assert.equal(plan.protection, "confidentiality");
  await rejectsCode(() => openDirectory({ url: "ldap://127.0.0.1:1", startTls: false, caOnly: false, tlsNoVerify: false, insecurePlaintext: false, authPlan: plan, anonymous: false, gssapiService: "ldap@directory.example.test", timeoutMs: 1_000 }), "GSSAPI_NEGOTIATION_FAILED");
});
test("anonymous is selected only when no authenticated input was selected", async () => {
  const plan = await selectAuthPlan({ requested: "auto", url: "ldaps://directory.example.test", anonymous: true });
  assert.equal(plan.mode, "anonymous");
  await rejectsCode(() => selectAuthPlan({ requested: "auto", url: "ldaps://directory.example.test", anonymous: true, credentials: { dn: "uid=synthetic", password: "pw" } }), "VALIDATION_ERROR");
  await rejectsCode(() => selectAuthPlan({ requested: "auto", url: "ldaps://directory.example.test", anonymous: true, authExplicit: true }), "VALIDATION_ERROR");
  await rejectsCode(() => selectAuthPlan({ requested: "auto", url: "ldaps://directory.example.test", anonymous: true, serviceOverride: "ldap/directory.example.test" }), "VALIDATION_ERROR");
});
test("CLI auth settings override the selected profile without mixing environment fields", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ldap-axi-auth-"));
  const configFile = join(directory, "config.json");
  await writeFile(configFile, JSON.stringify({ version: 1, profiles: { selected: { url: "ldaps://directory.example.test", auth: "gssapi", gssapiService: "ldap/profile.example.test", gssapiProtection: "none" } } }));
  await chmod(configFile, 0o600);
  const names = ["LDAP_AXI_CONFIG_FILE", "LDAP_AXI_CREDENTIALS_FILE", "LDAP_AXI_AUTH", "LDAP_AXI_GSSAPI_SERVICE", "LDAP_AXI_GSSAPI_PROTECTION"] as const;
  const saved = new Map(names.map(name => [name, process.env[name]]));
  process.env.LDAP_AXI_CONFIG_FILE = configFile;
  process.env.LDAP_AXI_CREDENTIALS_FILE = join(directory, "missing-credentials.env");
  delete process.env.LDAP_AXI_AUTH;
  delete process.env.LDAP_AXI_GSSAPI_SERVICE;
  try {
    assert.equal((await resolveSettings({ profile: "selected" })).auth, "gssapi");
    assert.equal((await resolveSettings({ profile: "selected" })).gssapiProtection, "none");
    process.env.LDAP_AXI_AUTH = "auto";
    process.env.LDAP_AXI_GSSAPI_SERVICE = "ldap/env.example.test";
    process.env.LDAP_AXI_GSSAPI_PROTECTION = "none";
    assert.equal((await resolveSettings({ profile: "selected" })).auth, "gssapi");
    assert.equal((await resolveSettings({ profile: "selected" })).gssapiService, "ldap/profile.example.test");
    assert.equal((await resolveSettings({ profile: "selected", auth: "auto", gssapiService: "ldap/cli.example.test" })).auth, "auto");
    assert.equal((await resolveSettings({ profile: "selected", auth: "auto", gssapiService: "ldap/cli.example.test", gssapiProtection: "confidentiality" })).gssapiService, "ldap/cli.example.test");
    assert.deepEqual((await resolveSettings({ profile: "selected", gssapiProtection: "confidentiality" })).gssapiProtection, "confidentiality");
    delete process.env.LDAP_AXI_AUTH;
    delete process.env.LDAP_AXI_GSSAPI_SERVICE;
    delete process.env.LDAP_AXI_GSSAPI_PROTECTION;
    const sole = await resolveSettings({});
    assert.equal(sole.auth, "gssapi");
    assert.equal(sole.gssapiService, "ldap/profile.example.test");
    assert.equal(sole.gssapiProtection, "none");
  } finally {
    for (const name of names) {
      const value = saved.get(name);
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  }
});
test("a half environment credential pair is terminal before the credentials file or GSSAPI", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ldap-axi-half-"));
  const configFile = join(directory, "config.json");
  const credentialsFile = join(directory, "credentials.env");
  await writeFile(credentialsFile, "LDAP_AXI_BIND_DN=uid=file\nLDAP_AXI_BIND_PASSWORD=pw\n");
  await chmod(credentialsFile, 0o600);
  const names = ["LDAP_AXI_CONFIG_FILE", "LDAP_AXI_CREDENTIALS_FILE", "LDAP_AXI_BIND_DN", "LDAP_AXI_BIND_PASSWORD"] as const;
  const saved = new Map(names.map(name => [name, process.env[name]]));
  process.env.LDAP_AXI_CONFIG_FILE = configFile;
  process.env.LDAP_AXI_CREDENTIALS_FILE = credentialsFile;
  process.env.LDAP_AXI_BIND_DN = "uid=environment";
  delete process.env.LDAP_AXI_BIND_PASSWORD;
  try {
    await assert.rejects(() => resolveSettings({}), error => error instanceof CliError && error.code === "CREDENTIAL_INCOMPLETE" && /PASSWORD/.test(error.message));
  } finally {
    for (const name of names) {
      const value = saved.get(name);
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  }
});
