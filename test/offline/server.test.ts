import assert from "node:assert/strict";
import test from "node:test";
import { run } from "../../src/cli.js";
import { CliError, type ServerFlavor } from "../../src/core.js";
import { serverReport } from "../../src/server.js";
import { RecordedDirectory } from "../support/fixtures.js";

for (const flavor of ["ad", "adlds", "ldapv3"] as const) {
  test(`server reports ${flavor} rootDSE facts without searching entries`, async () => {
    const facts = {
      namingContexts: ["dc=example,dc=test", "cn=config"],
      supportedControl: ["1.2.840.113556.1.4.319"],
      supportedExtension: ["1.3.6.1.4.1.4203.1.11.3"],
      supportedCapabilities: ["1.2.840.113556.1.4.1791", "1.2.840.113556.1.4.1920"],
      supportedLDAPVersion: ["3"], supportedSASLMechanisms: ["GSSAPI"],
      vendorName: ["Synthetic vendor"], vendorVersion: ["1"],
      supportedLDAPPolicies: ["MaxPageSize"], maxPageSize: ["250"],
      domainFunctionality: ["7"], configurationNamingContext: ["cn=config"],
    };
    const directory = new RecordedDirectory(flavor, [], facts);
    const report = await serverReport(directory);
    assert.deepEqual(report.data, {
      flavor, detected_flavor: flavor, flavor_overridden: false, vendor: "Synthetic vendor",
      root_dse: facts, advertised_limits: { maxPageSize: ["250"] },
    });
    assert.deepEqual(directory.requests, []);
  });
}

test("server does not invent optional facts or limit values from policy names", async () => {
  const report = await serverReport(new RecordedDirectory("ldapv3", [], { supportedLDAPPolicies: ["MaxPageSize"], namingContexts: [] }));
  assert.equal(report.data.vendor, "unknown");
  assert.equal(report.data.advertised_limits, "not advertised");
  assert.deepEqual(report.data.root_dse, { supportedLDAPPolicies: ["MaxPageSize"] });
  const sparse = await serverReport(new RecordedDirectory("ldapv3", []));
  assert.deepEqual(sparse.data.root_dse, {});
});

for (const override of ["ad", "adlds", "ldapv3"] as const) {
  test(`server explicitly records the ${override} override even when it matches detection`, async () => {
    const report = await serverReport(new RecordedDirectory("ldapv3", []), override);
    assert.equal(report.data.flavor, override);
    assert.equal(report.data.detected_flavor, "ldapv3");
    assert.equal(report.data.flavor_overridden, true);
  });
}

test("server CLI uses configured override and closes a sparse directory without a search base", async () => {
  const result = await isolated(async () => {
    process.env.LDAP_AXI_FLAVOR = "adlds";
    const directory = new RecordedDirectory("ldapv3", []);
    let opened = 0; let closed = false;
    directory.close = async () => { closed = true; };
    const result = await run(["server", "--url", "ldaps://directory.example.test", "--anonymous"], { openDirectory: async () => { opened++; return directory; } });
    assert.equal(opened, 1);
    assert.equal(closed, true);
    assert.deepEqual(directory.requests, []);
    return result;
  });
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /flavor: adlds/);
  assert.match(result.stdout, /detected_flavor: ldapv3/);
  assert.match(result.stdout, /flavor_overridden: true/);
});

for (const { name, flags, verified } of [
  { name: "unverified LDAPS", flags: ["--url", "ldaps://directory.example.test", "--tls-no-verify"], verified: false },
  { name: "unverified StartTLS", flags: ["--url", "ldap://directory.example.test", "--start-tls", "--tls-no-verify"], verified: false },
  { name: "verified LDAPS", flags: ["--url", "ldaps://directory.example.test"], verified: true },
  { name: "verified StartTLS", flags: ["--url", "ldap://directory.example.test", "--start-tls"], verified: true },
  { name: "plaintext LDAP", flags: ["--url", "ldap://directory.example.test", "--insecure-plaintext"], verified: false },
]) {
  test(`server CLI reports transport trust for ${name}`, async () => {
    await isolated(async () => {
      const result = await run(["server", ...flags, "--anonymous"], { openDirectory: async () => new RecordedDirectory("ldapv3", []) });
      assert.equal(result.exitCode, 0);
      assert.match(result.stdout, new RegExp(`^tls_verified: ${verified}$`, "m"));
      assert.match(result.stdout, /^detected_flavor: ldapv3$/m);
    });
  });
}

test("server preserves authentication failures without retrying", async () => {
  await isolated(async () => {
    let attempts = 0;
    const result = await run(["server", "--url", "ldaps://directory.example.test", "--anonymous"], { openDirectory: async () => { attempts++; throw new CliError("AUTH_FAILED", "authentication failed"); } });
    assert.equal(attempts, 1);
    assert.equal(result.exitCode, 1);
    assert.match(result.stdout, /AUTH_FAILED/);
  });
});

test("server closes the directory when rootDSE fails", async () => {
  await isolated(async () => {
    const directory = new RecordedDirectory("ldapv3", []);
    let closed = false;
    directory.rootDSE = async () => { throw new CliError("INSUFFICIENT_ACCESS", "rootDSE denied"); };
    directory.close = async () => { closed = true; };
    const result = await run(["server", "--url", "ldaps://directory.example.test", "--anonymous"], { openDirectory: async () => directory });
    assert.equal(result.exitCode, 1);
    assert.match(result.stdout, /INSUFFICIENT_ACCESS/);
    assert.equal(closed, true);
  });
});

test("server rejects unknown flags and positionals before connecting and serves offline help", async () => {
  for (const argv of [["server", "--bogus"], ["server", "extra"]]) {
    const result = await run(argv, { openDirectory: async () => { throw new Error("invalid input must not connect"); } });
    assert.equal(result.exitCode, 2);
    assert.match(result.stdout, /VALIDATION_ERROR/);
  }
  const help = await run(["server", "--help"]);
  assert.equal(help.exitCode, 0);
  assert.match(help.stdout, /Defaults:/);
  assert.match(help.stdout, /Examples:/);
});

async function isolated<T>(body: () => Promise<T>): Promise<T> {
  const environment = {
    LDAP_AXI_CONFIG: "test/nonexistent-config.json", LDAP_AXI_CREDENTIALS_FILE: "test/nonexistent-credentials.env",
    LDAP_AXI_URL: undefined, LDAP_AXI_BIND_DN: undefined, LDAP_AXI_BIND_PASSWORD: undefined,
    LDAP_AXI_AUTH: undefined, LDAP_AXI_PROFILE: undefined, LDAP_AXI_FLAVOR: undefined as ServerFlavor | undefined,
  };
  const previous = Object.fromEntries(Object.keys(environment).map(name => [name, process.env[name]]));
  for (const [name, value] of Object.entries(environment)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; }
  try { return await body(); }
  finally { for (const [name, value] of Object.entries(previous)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; } }
}
