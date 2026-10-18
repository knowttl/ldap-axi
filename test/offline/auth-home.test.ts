import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { authStatus, readNativeStatus } from "../../src/auth.js";
import { run } from "../../src/cli.js";
import { COMMANDS, homeView, LDAP_AXI_DESCRIPTION } from "../../src/home.js";
import { selectAuthPlan } from "../../src/directory/auth.js";
import { createSkillMarkdown } from "../../src/skill.js";
import { RecordedDirectory } from "../support/fixtures.js";

const provider = { prepare: async () => ({ kind: "failed" as const }) };
const offlineInput = {
  startTls: false,
  tlsNoVerify: false,
  caMode: "default" as const,
  authMode: "auto" as const,
  authSource: "default" as const,
  credentialsPermissions: "not-used" as const,
};
const isolatedConfig = (): Record<string, string | undefined> => ({
  LDAP_AXI_CONFIG: join(process.cwd(), "test", "nonexistent-config.json"),
  LDAP_AXI_CREDENTIALS_FILE: join(process.cwd(), "test", "nonexistent-credentials.env"),
  LDAP_AXI_URL: undefined,
  LDAP_AXI_BIND_DN: undefined,
  LDAP_AXI_BIND_PASSWORD: undefined,
  LDAP_AXI_AUTH: undefined,
});
async function withEnvironment(values: Record<string, string | undefined>, body: () => Promise<void>): Promise<void> {
  const previous = Object.fromEntries(Object.keys(values).map(name => [name, process.env[name]]));
  for (const [name, value] of Object.entries(values)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; }
  try { await body(); } finally {
    for (const [name, value] of Object.entries(previous)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; }
  }
}

test("the home view identifies the tool and lists the implemented nouns", () => {
  const home = homeView("/durable/bin/ldap-axi", "ldaps://directory.example.test", false);
  assert.equal(home.data.bin, "/durable/bin/ldap-axi");
  assert.equal(home.data.description, LDAP_AXI_DESCRIPTION);
  assert.equal(home.data.server, "ldaps://directory.example.test");
  assert.equal(home.data.credentials, "not configured");
  assert.deepEqual(home.data.commands, [...COMMANDS]);
  assert.ok(COMMANDS.includes("auth status"));
  assert.match(home.help[0], /auth status/);
  const unconfigured = homeView("/durable/bin/ldap-axi", undefined, true);
  assert.equal(unconfigured.data.server, undefined);
  assert.equal(unconfigured.data.credentials, "configured for simple auth");
  assert.match(unconfigured.help[0], /LDAP_AXI_URL/);
  assert.ok(createSkillMarkdown().includes(LDAP_AXI_DESCRIPTION));
});

test("auth status reports the scheme-selected mechanism, layer, and channel binding without connecting", async () => {
  const tls = await authStatus({ ...offlineInput, url: "ldaps://directory.example.test", plan: await selectAuthPlan({ requested: "auto", url: "ldaps://directory.example.test", provider, platform: "linux" }) });
  assert.equal(tls.data.connection, "offline");
  assert.equal(tls.data.mechanism, "GSSAPI");
  assert.equal(tls.data.gssapi_service, "ldap@directory.example.test");
  assert.equal(tls.data.sasl_security_layer, "none");
  assert.equal(tls.data.channel_binding, "tls-server-end-point");
  assert.equal(tls.data.tls, "verified");
  assert.equal(tls.data.credentials, "ambient (unchecked)");
  assert.equal(tls.data.native_provider, "unchecked");
  assert.equal(typeof tls.data.native_provider_installation, "string");

  const plain = await authStatus({ ...offlineInput, url: "ldap://directory.example.test", plan: await selectAuthPlan({ requested: "auto", url: "ldap://directory.example.test", provider, platform: "linux" }) });
  assert.equal(plain.data.sasl_security_layer, "confidentiality");
  assert.equal(plain.data.channel_binding, "none");
  assert.equal(plain.data.tls, "none");

  const windows = await authStatus({ ...offlineInput, url: "ldaps://directory.example.test", plan: await selectAuthPlan({ requested: "auto", url: "ldaps://directory.example.test", provider, platform: "win32" }) });
  assert.equal(windows.data.mechanism, "GSS-SPNEGO");
});

test("auth status reports credential provenance for simple and anonymous plans", async () => {
  const simple = await authStatus({
    ...offlineInput,
    url: "ldaps://directory.example.test",
    authMode: "simple",
    authSource: "cli",
    credentialSource: "credentials-file",
    credentialsPermissions: "checked",
    caMode: "replacement",
    plan: await selectAuthPlan({ requested: "simple", url: "ldaps://directory.example.test", credentials: { dn: "CN=read,DC=example,DC=test", password: "synthetic-secret" }, credentialSource: "credentials-file" }),
  });
  assert.equal(simple.data.credentials, "resolved");
  assert.equal(simple.data.credential_source, "credentials-file");
  assert.equal(simple.data.credentials_file_permissions, "checked");
  assert.equal(simple.data.mechanism, "simple");
  assert.equal(simple.data.sasl_security_layer, "not applicable");
  assert.equal(simple.data.ca_trust, "replacement");
  assert.doesNotMatch(JSON.stringify(simple.data), /synthetic-secret/);

  const anonymous = await authStatus({ ...offlineInput, url: "ldaps://directory.example.test", plan: await selectAuthPlan({ requested: "auto", url: "ldaps://directory.example.test", anonymous: true }) });
  assert.equal(anonymous.data.credentials, "anonymous");
  assert.equal(anonymous.data.mechanism, "anonymous");
});

test("a live auth status resolves the identity through Who Am I only when the server advertises it", async () => {
  const advertised = new RecordedDirectory("ad", [], { supportedExtension: ["1.3.6.1.4.1.4203.1.11.3"] });
  advertised.whoami = async () => "dn:CN=read,DC=example,DC=test";
  const resolved = await authStatus({ ...offlineInput, url: "ldaps://directory.example.test" }, advertised);
  assert.equal(resolved.data.connection, "live");
  assert.equal(resolved.data.flavor, "ad");
  assert.equal(resolved.data.identity_method, "whoami");
  assert.equal(resolved.data.bound_as, "dn:CN=read,DC=example,DC=test");
  assert.deepEqual(resolved.help, []);

  const silent = new RecordedDirectory("ldapv3", [], { supportedExtension: [] });
  const configured = await authStatus({
    ...offlineInput,
    url: "ldaps://directory.example.test",
    authMode: "simple",
    plan: await selectAuthPlan({ requested: "simple", url: "ldaps://directory.example.test", credentials: { dn: "CN=read,DC=example,DC=test", password: "synthetic-secret" } }),
  }, silent);
  assert.equal(configured.data.identity_method, "configured-bind-dn");
  assert.equal(configured.data.bound_as, "CN=read,DC=example,DC=test");
  assert.match(configured.help[0], /Who Am I/);
});

test("native provider status is read from the recorded installation status file", async () => {
  const root = await mkdtemp(join(tmpdir(), "ldap-axi-native-status-"));
  try {
    const file = join(root, "native-status.json");
    await writeFile(file, JSON.stringify({ target: "linux-glibc-x64", mode: "auto", result: "installed", detail: "verified prebuild" }));
    assert.deepEqual(await readNativeStatus(file), { result: "installed", detail: "verified prebuild", target: "linux-glibc-x64", mode: "auto" });
    await writeFile(file, "{not json");
    assert.equal((await readNativeStatus(file))?.result, "unknown");
    assert.equal(await readNativeStatus(join(root, "absent.json")), undefined);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("auth status routes through the CLI, binds once when live, and never binds when offline", async () => {
  await withEnvironment(isolatedConfig(), async () => {
    const offline = await run(["auth", "status", "--offline", "--url", "ldaps://directory.example.test"], { openDirectory: async () => { throw new Error("offline auth status must not connect"); } });
    assert.equal(offline.exitCode, 0);
    assert.match(offline.stdout, /connection: offline/);
    assert.match(offline.stdout, process.platform === "win32" ? /mechanism: GSS-SPNEGO/ : /mechanism: GSSAPI/);
    assert.match(offline.stdout, /native_provider:/);

    const unconfigured = await run(["auth", "status"], { openDirectory: async () => { throw new Error("an unconfigured auth status must not connect"); } });
    assert.equal(unconfigured.exitCode, 0);
    assert.match(unconfigured.stdout, /mechanism: not selected/);
    assert.match(unconfigured.stdout, /LDAP_AXI_URL/);

    const directory = new RecordedDirectory("ad", [], { supportedExtension: [] });
    let closed = false;
    directory.close = async () => { closed = true; };
    const live = await run(["auth", "status", "--url", "ldaps://directory.example.test", "--anonymous"], { openDirectory: async () => directory });
    assert.equal(live.exitCode, 0);
    assert.match(live.stdout, /connection: live/);
    assert.match(live.stdout, /credentials: anonymous/);
    assert.equal(closed, true);
    assert.equal(directory.requests.length, 0);
  });
});

test("the home command renders the noun list through the CLI", async () => {
  await withEnvironment(isolatedConfig(), async () => {
    const home = await run([], { executable: "/durable/bin/ldap-axi" });
    assert.equal(home.exitCode, 0);
    assert.match(home.stdout, /bin: \/durable\/bin\/ldap-axi/);
    assert.match(home.stdout, /commands\[14\]:/);
    assert.match(home.stdout, /auth status/);
  });
});
test("the home command does not claim auto auth will use configured simple credentials", async () => {
  await withEnvironment({ ...isolatedConfig(), LDAP_AXI_URL: "ldaps://directory.example.test", LDAP_AXI_BIND_DN: "cn=synthetic", LDAP_AXI_BIND_PASSWORD: "synthetic" }, async () => {
    const home = await run([]);
    assert.match(home.stdout, /credentials: configured for simple auth/);
    assert.match(home.stdout, /auto.*ambient/);
  });
});
test("refusing unverified GSSAPI TLS does not warn that verification was disabled", async () => {
  await withEnvironment(isolatedConfig(), async () => {
    const result = await run(["auth", "status", "--url", "ldaps://directory.example.test", "--tls-no-verify"]);
    assert.equal(result.exitCode, 1);
    assert.match(result.stdout, /TLS_REQUIRED/);
    assert.equal(result.stderr, "");
  });
});

test("auth status rejects an unknown subcommand, positionals, and unknown flags before any connection", async () => {
  for (const argv of [["auth", "bogus"], ["auth", "status", "extra"], ["auth", "status", "--bogus"]]) {
    const result = await run(argv, { openDirectory: async () => { throw new Error("rejected input must not connect"); } });
    assert.equal(result.exitCode, 2);
    assert.match(result.stdout, /VALIDATION_ERROR/);
  }
  const help = await run(["auth", "status", "--help"]);
  assert.equal(help.exitCode, 0);
  assert.match(help.stdout, /Defaults:/);
  assert.match(help.stdout, /Examples:/);
});

test("the live smoke script refuses to run without the explicit live opt-in", () => {
  const result = spawnSync(process.execPath, ["scripts/live-smoke.mjs", "--url", "ldaps://directory.example.test"], { env: { ...process.env, LDAP_AXI_LIVE: "0" }, encoding: "utf8" });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /LDAP_AXI_LIVE=1/);
  const withoutUrl = spawnSync(process.execPath, ["scripts/live-smoke.mjs"], { env: { ...process.env, LDAP_AXI_LIVE: "1", LDAP_AXI_URL: "" }, encoding: "utf8" });
  assert.equal(withoutUrl.status, 2);
  assert.match(withoutUrl.stderr, /--url/);
});

test("the live smoke script writes redacted evidence for every step of its fixed sequence", async () => {
  const root = await mkdtemp(join(tmpdir(), "ldap-axi-live-smoke-"));
  const evidenceFile = join(root, "evidence.json");
  try {
    const result = spawnSync(process.execPath, ["scripts/live-smoke.mjs", "--out", evidenceFile, "--url", "ldap://127.0.0.1:1", "--anonymous", "--insecure-plaintext"], {
      env: { ...process.env, LDAP_AXI_LIVE: "1", LDAP_AXI_CONFIG: join(process.cwd(), "test", "nonexistent-config.json"), LDAP_AXI_CREDENTIALS_FILE: join(process.cwd(), "test", "nonexistent-credentials.env") },
      encoding: "utf8",
    });
    assert.equal(result.status, 1, result.stderr);
    const evidence = JSON.parse(await readFile(evidenceFile, "utf8"));
    assert.equal(evidence.url_scheme, "ldap");
    assert.deepEqual(evidence.steps.map((step: { step: string }) => step.step), ["home", "auth status (offline)", "auth status", "rootDSE read", "user list", "group list"]);
    assert.equal(evidence.steps[0].exit_code, 0);
    assert.ok(evidence.steps[0].keys.includes("commands[14]"));
    assert.equal(evidence.steps[1].exit_code, 0);
    // A filtered loopback port can time out instead of refusing the connection.
    for (const step of evidence.steps.slice(3)) assert.match(step.error_code, /^(SERVER_UNREACHABLE|OPERATION_TIMEOUT)$/);
    const serialized = await readFile(evidenceFile, "utf8");
    assert.doesNotMatch(serialized, /127\.0\.0\.1/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
