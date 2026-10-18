import assert from "node:assert/strict";
import test from "node:test";
import { run } from "../../src/cli.js";
import { CliError } from "../../src/core.js";
import { listComputers, showComputer } from "../../src/computer.js";
import { SecretRedactor } from "../../src/secrets.js";
import { BASE, DOMAIN_SID, byDn, byFilter, entry, guidBase64, sidBase64, RecordedDirectory } from "../support/fixtures.js";

const DN = "CN=Workstation,OU=Devices,DC=example,DC=test";
const COMPUTER = entry(DN, { cn: ["Workstation"], sAMAccountName: ["WORKSTATION$"], dNSHostName: ["workstation.example.test"], userAccountControl: ["4096"] });
const LIST = { base: BASE, flavor: "ad", pageSize: 1, all: true, scope: "sub" } as const;
const SHOW = { base: BASE, flavor: "ad", pageSize: 1, identifier: "WORKSTATION$" } as const;

for (const flavor of ["ad", "adlds"] as const) {
  test(`${flavor} computer list uses machine shape and minimal defaults`, async () => {
    const directory = new RecordedDirectory(flavor, [byFilter(["(objectCategory=computer)"], [COMPUTER])]);
    const result = await listComputers(directory, { ...LIST, flavor });
    assert.deepEqual(result.data.computers, [{ sam: "WORKSTATION$", name: "Workstation", dns_host_name: "workstation.example.test", enabled: true }]);
    assert.equal(result.data.count, "1 of 1 total");
    assert.deepEqual(directory.requests[0].attributes, ["sAMAccountName", "cn", "dNSHostName", "userAccountControl"]);
  });
}
test("generic list names the device fallback and uses generic fields", async () => {
  const directory = new RecordedDirectory("ldapv3", [byFilter(["(objectClass=device)"], [entry(DN, { cn: ["Workstation"] })])]);
  const result = await listComputers(directory, { ...LIST, flavor: "ldapv3" });
  assert.deepEqual(result.data.computers, [{ name: "Workstation", dn: DN }]);
  assert.equal(result.data.fallback_filter, "(objectClass=device)");
});
test("generic empty list explains the fallback and access-control uncertainty", async () => {
  const result = await listComputers(new RecordedDirectory("ldapv3", []), { ...LIST, flavor: "ldapv3" });
  assert.match(String(result.data.computers), /0 entries matched.*objectClass=device/);
  assert.match(String(result.data.note), /access control/);
  assert.match(result.help.join(" "), /machine accounts may not exist/);
});
test("AD empty list is definitive within the selected base", async () => {
  const result = await listComputers(new RecordedDirectory("ad", []), LIST);
  assert.equal(result.data.computers, `0 computers matched under ${BASE}`);
});
test("list filters escape literal metacharacters and preserve explicit wildcards", async () => {
  const directory = new RecordedDirectory("ad", []);
  await listComputers(directory, { ...LIST, name: "work*(x)\\", sam: "pc*", filter: "(description=synthetic)" });
  assert.equal(directory.requests[0].filter, "(&(objectCategory=computer)(cn=work*\\28x\\29\\5c)(sAMAccountName=pc*)(description=synthetic))");
});
for (const [options, expected] of [
  [{ all: false }, { count: "1 of unknown total", incomplete: "page_boundary" }],
  [{ all: true, maxRows: 1 }, { count: "1 of unknown total", partial: true, stop_reason: "max_rows" }],
  [{ all: false, limit: 2 }, { count: "2 of 2 total" }],
] as const) {
  test(`list reports bounded paging for ${JSON.stringify(options)}`, async () => {
    const directory = new RecordedDirectory("ad", [byFilter(["objectCategory=computer"], [{ entries: [COMPUTER] }, { entries: [entry("CN=Second,DC=example,DC=test", { cn: ["Second"] })] }])]);
    const result = await listComputers(directory, { ...LIST, ...options, fields: ["name"] });
    assert.equal(result.data.count, expected.count);
    assert.equal(result.data.incomplete, "incomplete" in expected ? expected.incomplete : undefined);
    assert.equal(result.data.partial, "partial" in expected ? expected.partial : undefined);
    assert.equal(result.data.stop_reason, "stop_reason" in expected ? expected.stop_reason : undefined);
    assert.equal(directory.requests[0].pageSize, 1);
  });
}
for (const stopReason of ["server_size_limit", "server_time_limit", "server_admin_limit"] as const) {
  test(`generic ${stopReason} cannot masquerade as an empty fallback`, async () => {
    const directory = new RecordedDirectory("ldapv3", [byFilter(["objectClass=device"], [{ entries: [], stopReason }])]);
    await assert.rejects(() => listComputers(directory, { ...LIST, flavor: "ldapv3" }), (error: unknown) => error instanceof CliError && error.code === "SERVER_LIMIT");
  });
}
test("referrals make an empty device search partial", async () => {
  const directory = new RecordedDirectory("ldapv3", [byFilter(["objectClass=device"], [{ entries: [], referrals: ["ldap://other.example.test/DC=example,DC=test"] }])]);
  const result = await listComputers(directory, { ...LIST, flavor: "ldapv3" });
  assert.deepEqual(result.data.computers, []);
  assert.equal(result.data.partial, true);
  assert.equal(result.data.stop_reason, "referral");
});
test("AD show decodes identity, timestamps and disabled state", async () => {
  const sid = `${DOMAIN_SID}-1200`;
  const guid = "04030201-0605-0807-090a-0b0c0d0e0f10";
  const computer = entry(DN, { ...COMPUTER.attributes, userAccountControl: ["4098"], objectSid: [sidBase64(sid)], objectGUID: [guidBase64(guid)], lastLogonTimestamp: ["132223104000000000"], operatingSystem: ["Synthetic OS"], whenCreated: ["20200101000000Z"] });
  const directory = new RecordedDirectory("ad", [byFilter(["objectCategory=computer", "sAMAccountName=WORKSTATION$", "cn=WORKSTATION$"], [computer])]);
  const result = await showComputer(directory, SHOW);
  assert.deepEqual(result.data.computer, { dn: DN, sam: "WORKSTATION$", name: "Workstation", dns_host_name: "workstation.example.test", enabled: false, operating_system: "Synthetic OS", last_logon: "2020-01-01T00:00:00.000Z", last_logon_precision: "approximate", object_sid: sid, object_sid_raw: sidBase64(sid), object_guid: guid, object_guid_raw: guidBase64(guid), when_created: "2020-01-01T00:00:00.000Z" });
});
test("generic show uses exact cn and generic operational attributes", async () => {
  const directory = new RecordedDirectory("ldapv3", [byFilter(["(&(objectClass=device)(cn=Workstation))"], [entry(DN, { cn: ["Workstation"], entryUUID: ["synthetic-uuid"], modifyTimestamp: ["20200101000000Z"] })])]);
  const result = await showComputer(directory, { ...SHOW, flavor: "ldapv3", identifier: "Workstation" });
  assert.deepEqual(result.data, { fallback_filter: "(objectClass=device)", computer: { name: "Workstation", dn: DN, entry_uuid: "synthetic-uuid", when_changed: "2020-01-01T00:00:00.000Z" } });
  assert.equal(directory.requests.length, 1);
});
for (const [flavor, shape] of [["ad", "(objectCategory=computer)"], ["ldapv3", "(objectClass=device)"]] as const) {
  test(`${flavor} show treats metacharacters as literal identifier values`, async () => {
    const directory = new RecordedDirectory(flavor, [byFilter([shape, "(cn=pc\\2a\\28x\\29\\5c\\00)"], [COMPUTER])]);
    await showComputer(directory, { ...SHOW, flavor, identifier: "pc*(x)\\\0", fields: ["dn"] });
    assert.equal(directory.requests.length, 1);
    assert.equal(directory.requests[0].scope, "sub");
  });
  test(`${flavor} escaped DN gets one shape-filtered base read`, async () => {
    const dn = "CN=Workstation\\, Lab,OU=Devices,DC=example,DC=test";
    const directory = new RecordedDirectory(flavor, [byDn(dn, entry(dn, {}))]);
    const result = await showComputer(directory, { ...SHOW, flavor, identifier: dn, fields: ["dn"] });
    assert.deepEqual(result.data.computer, { dn });
    assert.deepEqual(directory.requests, [{ base: dn, scope: "base", filter: shape, attributes: ["1.1"], pageSize: 1 }]);
  });
  test(`${flavor} wrong-shape DN is not retried as an identifier`, async () => {
    const directory = new RecordedDirectory(flavor, [byDn(DN, undefined), byFilter([shape], [COMPUTER])]);
    await assert.rejects(() => showComputer(directory, { ...SHOW, flavor, identifier: DN }), (error: unknown) => error instanceof CliError && error.code === "NOT_FOUND");
    assert.equal(directory.requests.length, 1);
  });
  test(`${flavor} identifier collision across pages requires a DN`, async () => {
    const directory = new RecordedDirectory(flavor, [byFilter([shape], [{ entries: [COMPUTER] }, { entries: [entry("CN=Other,DC=example,DC=test", {})] }])]);
    await assert.rejects(() => showComputer(directory, { ...SHOW, flavor }), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR" && /distinguished name/.test(error.help.join(" ")));
  });
  test(`${flavor} incomplete identity search refuses to claim uniqueness`, async () => {
    const directory = new RecordedDirectory(flavor, [byFilter([shape], [{ entries: [COMPUTER], stopReason: "server_size_limit" }])]);
    await assert.rejects(() => showComputer(directory, { ...SHOW, flavor }), (error: unknown) => error instanceof CliError && error.code === "SERVER_LIMIT");
  });
}
test("generic absent identifier names the device fallback", async () => {
  await assert.rejects(() => showComputer(new RecordedDirectory("ldapv3", []), { ...SHOW, flavor: "ldapv3" }), (error: unknown) => error instanceof CliError && error.code === "NOT_FOUND" && /objectClass=device/.test(error.message));
});
test("generic fields and flags reject AD assumptions before searching", async () => {
  const directory = new RecordedDirectory("ldapv3", []);
  await assert.rejects(() => listComputers(directory, { ...LIST, flavor: "ldapv3", sam: "pc" }), (error: unknown) => error instanceof CliError && error.code === "UNSUPPORTED_BY_SERVER");
  await assert.rejects(() => showComputer(directory, { ...SHOW, flavor: "ldapv3", fields: ["enabled"] }), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR");
  assert.equal(directory.requests.length, 0);
});
for (const attribute of ["userPassword", "unicodePwd", "2.5.4.35", "*"]) {
  test(`computer reads refuse ${attribute} before searching`, async () => {
    const directory = new RecordedDirectory("ad", []);
    await assert.rejects(() => listComputers(directory, { ...LIST, attributes: [attribute] }), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR");
    await assert.rejects(() => showComputer(directory, { ...SHOW, attributes: [attribute] }), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR");
    assert.equal(directory.requests.length, 0);
  });
}
test("selected and raw attributes redact before truncation and exclude unsolicited attributes", async () => {
  const redactor = new SecretRedactor();
  redactor.add("synthetic-secret");
  const computer = entry(DN, { cn: ["synthetic-secret"], description: ["synthetic-secret" + "x".repeat(900)], userPassword: ["hidden"], mail: ["hidden"] });
  const directory = new RecordedDirectory("ad", [byFilter(["objectCategory=computer"], [computer])]);
  const result = await listComputers(directory, { ...LIST, fields: ["name"], attributes: ["description"], redactor });
  const row = (result.data.computers as Record<string, unknown>[])[0];
  assert.equal(row.name, "[REDACTED]");
  assert.match(String(row.description), /^\[REDACTED\].*truncated/);
  assert.equal(row.mail, undefined);
  assert.equal(row.userPassword, undefined);
  assert.deepEqual(directory.requests[0].attributes, ["cn", "description"]);
});
for (const argv of [
  ["list", "extra"], ["show"], ["show", "a", "b"], ["list", "--all"], ["list", "--fields", "typo"],
  ["list", "--scope", "invalid"], ["list", "--filter", "(("], ["show", "pc", "--attributes", "unicodePwd"],
  ["list", "--cursor", "value"], ["list", "--max-rows", "0"],
]) {
  test(`computer ${argv.join(" ")} fails before connecting`, async () => {
    const result = await run(["computer", ...argv], { openDirectory: async () => assert.fail("invalid input must not connect") });
    assert.equal(result.exitCode, 2);
    assert.match(result.stdout, /VALIDATION_ERROR/);
  });
}
