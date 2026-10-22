import assert from "node:assert/strict";
import test from "node:test";
import { CliError } from "../../src/core.js";
import { listUsers, showUser, userGroups } from "../../src/user.js";
import { encodeSid } from "../../src/directory/sid.js";
import { encodeGuid } from "../../src/directory/guid.js";
import { byDn, byDnFn, byFilter, entry, RecordedDirectory, BASE, DOMAIN_SID, DOMAIN_USERS_RID } from "../support/fixtures.js";

const JANE_DN = "CN=Jane Doe,OU=Users,DC=example,DC=test";
const SVC_DN = "CN=Old Svc,OU=Users,DC=example,DC=test";
const JANE = entry(JANE_DN, { sAMAccountName: ["jdoe"], cn: ["Jane Doe"], userAccountControl: ["512"], lastLogonTimestamp: ["132223104000000000"] });
const SVC = entry(SVC_DN, { sAMAccountName: ["svc_old"], cn: ["Old Svc"], userAccountControl: ["514"], lastLogonTimestamp: ["0"] });

for (const [command, run, key, expected] of [
  ["list", listUsers, "users", [{ description: "Synthetic account", display_name: "Alice Example", memberOf: ["CN=Staff,DC=example,DC=test"] }]],
  ["show", showUser, "user", { description: "Synthetic account", display_name: "Alice Example", memberOf: ["CN=Staff,DC=example,DC=test"] }],
] as const) {
  for (const flavor of ["ad", "adlds"] as const) {
    test(`${flavor} user ${command} selects description, display_name and memberOf`, async () => {
      const alice = entry("CN=alice,DC=example,DC=test", { description: ["Synthetic account"], displayName: ["Alice Example"], memberOf: ["CN=Staff,DC=example,DC=test"] });
      const directory = new RecordedDirectory(flavor, [byFilter([], [alice])]);
      const result = await run(directory, { base: BASE, flavor, identifier: "alice", pageSize: 500, all: true, scope: "sub", fields: ["description", "display_name", "memberOf"] });
      assert.deepEqual(result.data[key], expected);
      assert.deepEqual(directory.requests[0].attributes, ["description", "displayName", "memberOf"]);
    });
  }
  for (const field of ["description", "display_name", "memberOf"]) {
    test(`LDAPv3 user ${command} rejects AD-only ${field}`, async () => {
      const directory = new RecordedDirectory("ldapv3", []);
      await assert.rejects(() => run(directory, { base: BASE, flavor: "ldapv3", identifier: "alice", pageSize: 500, all: true, scope: "sub", fields: [field] }),
        (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR");
      assert.equal(directory.requests.length, 0);
    });
  }
}
for (const [attribute, hint] of [["sAMAccountName", "--fields sam"], ["displayName", "--fields display_name"]] as const) {
  test(`user show rejects directory attribute ${attribute} with an actionable hint`, async () => {
    const directory = new RecordedDirectory("ad", []);
    await assert.rejects(
      () => showUser(directory, { base: BASE, flavor: "ad", identifier: "alice", pageSize: 500, fields: [attribute] }),
      (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR" && error.help.some(line => line.includes(hint)),
    );
    assert.equal(directory.requests.length, 0);
  });
}

for (const [command, run, fields] of [
  ["list", listUsers, ["description"]],
  ["show", showUser, ["description"]],
  ["show defaults", showUser, undefined],
] as const) {
  for (const flavor of ["ad", "adlds"] as const) {
    for (const attributes of [undefined, ["description"]]) {
      for (const [label, returnedAttributes, expected] of [
        ["absent", {}, undefined],
        ["empty string", { description: [""] }, ""],
        ["single value", { description: ["Operations"] }, "Operations"],
        ["multiple values", { description: ["Operations", "On-call"] }, ["Operations", "On-call"]],
      ] as const) {
        test(`${flavor} user ${command} preserves ${label} description with raw attributes ${String(attributes)}`, async () => {
          const alice = entry("CN=alice,DC=example,DC=test", returnedAttributes);
          const directory = new RecordedDirectory(flavor, [byFilter([], [alice])]);
          const result = await run(directory, { base: BASE, flavor, identifier: "alice", pageSize: 500, all: true, scope: "sub", fields, attributes });
          const rows = result.data.users as Record<string, unknown>[] | undefined;
          const user = (rows?.[0] ?? result.data.user) as Record<string, unknown>;
          assert.deepEqual(user.description, expected);
        });
      }
      test(`${flavor} user ${command} bounds multiple descriptions with raw attributes ${String(attributes)}`, async () => {
        const descriptions = ["x".repeat(1000), ...Array.from({ length: 50 }, (_, index) => `Description ${index}`)];
        const alice = entry("CN=alice,DC=example,DC=test", { description: descriptions });
        const directory = new RecordedDirectory(flavor, [byFilter([], [alice])]);
        const result = await run(directory, { base: BASE, flavor, identifier: "alice", pageSize: 500, all: true, scope: "sub", fields, attributes });
        const rows = result.data.users as Record<string, unknown>[] | undefined;
        const user = (rows?.[0] ?? result.data.user) as Record<string, unknown>;
        assert.deepEqual(user.description, [`${"x".repeat(800)}… (truncated, 1000 chars total)`, ...descriptions.slice(1, 50)]);
        assert.equal(user.description_value_count, 51);
        assert.equal(user.description_values_truncated, true);
      });
      for (const range of ["0-1499", "0-*"]) {
        test(`${flavor} user ${command} preserves bounded ranged descriptions ${range} with raw attributes ${String(attributes)}`, async () => {
          const descriptions = ["x".repeat(1000), ...Array.from({ length: 50 }, (_, index) => `Description ${index}`)];
          const key = `description;range=${range}`;
          const alice = entry("CN=alice,DC=example,DC=test", { description: [], [key]: descriptions });
          const directory = new RecordedDirectory(flavor, [byFilter([], [alice])]);
          const result = await run(directory, { base: BASE, flavor, identifier: "alice", pageSize: 500, all: true, scope: "sub", fields, attributes });
          const rows = result.data.users as Record<string, unknown>[] | undefined;
          const user = (rows?.[0] ?? result.data.user) as Record<string, unknown>;
          assert.deepEqual(user[key], [`${"x".repeat(800)}… (truncated, 1000 chars total)`, ...descriptions.slice(1, 50)]);
          assert.equal(user[`${key}_value_count`], 51);
          assert.equal(user[`${key}_values_truncated`], true);
          assert.deepEqual(user.description ?? [], []);
          assert.equal(directory.requests.length, 1);
        });
      }
    }
  }
}

for (const [command, run, fields] of [
  ["list", listUsers, ["description", "display_name", "memberOf"]],
  ["show", showUser, undefined],
] as const) {
  test(`AD user ${command} bounds new text fields and membership values`, async () => {
    const text = "x".repeat(1000);
    const groups = Array.from({ length: 51 }, (_, index) => `CN=Group ${index},DC=example,DC=test`);
    const alice = entry("CN=alice,DC=example,DC=test", { description: [text], displayName: [text], memberOf: groups });
    const directory = new RecordedDirectory("ad", [byFilter([], [alice])]);
    const result = await run(directory, { base: BASE, flavor: "ad", identifier: "alice", pageSize: 500, all: true, scope: "sub", fields });
    const rows = result.data.users as Record<string, unknown>[] | undefined;
    const user = (rows?.[0] ?? result.data.user) as Record<string, unknown>;
    assert.equal(user.description, `${"x".repeat(800)}… (truncated, 1000 chars total)`);
    assert.equal(user.display_name, `${"x".repeat(800)}… (truncated, 1000 chars total)`);
    assert.deepEqual(user.memberOf, groups.slice(0, 50));
    assert.equal(user.memberOf_value_count, 51);
    assert.equal(user.memberOf_values_truncated, true);
  });
  test(`AD user ${command} preserves ranged membership and truncates its text`, async () => {
    const dn = `CN=${"x".repeat(900)},DC=example,DC=test`;
    const alice = entry("CN=alice,DC=example,DC=test", { memberOf: [], "memberOf;range=0-*": [dn] });
    const directory = new RecordedDirectory("ad", [byFilter([], [alice])]);
    const result = await run(directory, { base: BASE, flavor: "ad", identifier: "alice", pageSize: 500, all: true, scope: "sub", fields });
    const rows = result.data.users as Record<string, unknown>[] | undefined;
    const user = (rows?.[0] ?? result.data.user) as Record<string, unknown>;
    assert.equal(user.memberOf, undefined);
    assert.deepEqual(user["memberOf;range=0-*"], [`${dn.slice(0, 800)}… (truncated, ${dn.length} chars total)`]);
    assert.equal(directory.requests.length, 1);
  });
}

test("AD user list decodes enabled from userAccountControl and renders FILETIME sentinels honestly", async () => {
  const directory = new RecordedDirectory("ad", [byFilter(["objectCategory=person"], [JANE, SVC])]);
  const result = await listUsers(directory, { base: BASE, flavor: "ad", pageSize: 500, all: true, scope: "sub" });
  assert.equal(result.data.count, "2 of 2 total");
  assert.equal(directory.requests[0].attributes.includes("msDS-User-Account-Control-Computed"), false);
  assert.deepEqual(result.data.users, [
    { sam: "jdoe", name: "Jane Doe", enabled: true, last_logon: "2020-01-01T00:00:00.000Z" },
    { sam: "svc_old", name: "Old Svc", enabled: false, last_logon: "unset" },
  ]);
});
test("AD user list without --all is explicitly incomplete, not a fabricated total", async () => {
  const directory = new RecordedDirectory("ad", [byFilter(["objectCategory=person"], [{ entries: [JANE] }, { entries: [SVC] }])]);
  const result = await listUsers(directory, { base: BASE, flavor: "ad", pageSize: 500, all: false, scope: "sub" });
  assert.equal(result.data.count, "1 of unknown total");
  assert.equal(result.data.incomplete, "page_boundary");
});
test("generic user list defaults to uid, name, and mail", async () => {
  const alice = entry("uid=alice,ou=people,dc=example,dc=test", { uid: ["alice"], cn: ["Alice"], mail: ["alice@example.test"] });
  const directory = new RecordedDirectory("ldapv3", [byFilter(["inetOrgPerson"], [alice])]);
  const result = await listUsers(directory, { base: BASE, flavor: "ldapv3", pageSize: 500, all: true, scope: "sub" });
  assert.deepEqual(result.data.users, [{ uid: "alice", name: "Alice", mail: "alice@example.test" }]);
});
test("unsupported generic user list filters fail explicitly", async () => {
  const directory = new RecordedDirectory("ldapv3", []);
  for (const options of [{ disabled: true }, { enabled: true }, { locked: true }, { sam: "jdoe" }, { upn: "jdoe@example.test" }]) {
    await assert.rejects(
      () => listUsers(directory, { base: BASE, flavor: "ldapv3", pageSize: 500, all: true, scope: "sub", ...options }),
      (error: unknown) => error instanceof CliError && error.code === "UNSUPPORTED_BY_SERVER",
    );
  }
});
test("--uid is generic-only and UNSUPPORTED_BY_SERVER on Active Directory", async () => {
  const directory = new RecordedDirectory("ad", []);
  await assert.rejects(() => listUsers(directory, { base: BASE, flavor: "ad", pageSize: 500, all: true, scope: "sub", uid: "alice" }), (error: unknown) => error instanceof CliError && error.code === "UNSUPPORTED_BY_SERVER");
});
test("--locked verifies current computed state after finding historical lockout candidates", async () => {
  const stale = entry(SVC_DN, { sAMAccountName: ["svc_old"], cn: ["Old Svc"], userAccountControl: ["512"], "msDS-User-Account-Control-Computed": ["0"] });
  const locked = entry(JANE_DN, { sAMAccountName: ["jdoe"], cn: ["Jane Doe"], userAccountControl: ["512"], "msDS-User-Account-Control-Computed": ["16"] });
  const directory = new RecordedDirectory("ad", [byFilter(["lockoutTime>=1"], [{ entries: [stale] }, { entries: [locked] }])]);
  const result = await listUsers(directory, { base: BASE, flavor: "ad", pageSize: 1, all: true, scope: "sub", locked: true });
  assert.match(directory.requests[0].filter, /lockoutTime>=1/);
  assert.ok(directory.requests[0].attributes.includes("msDS-User-Account-Control-Computed"));
  assert.deepEqual(result.data.users, [{ sam: "jdoe", name: "Jane Doe", enabled: true }]);
  assert.equal(result.data.count, "1 of 1 total");
});
test("requested raw attributes are emitted by user list", async () => {
  const described = entry(JANE_DN, { sAMAccountName: ["jdoe"], cn: ["Jane Doe"], userAccountControl: ["512"], description: ["Synthetic account"] });
  const directory = new RecordedDirectory("ad", [byFilter(["objectCategory=person"], [described])]);
  const result = await listUsers(directory, { base: BASE, flavor: "ad", pageSize: 500, all: true, scope: "sub", attributes: ["description"] });
  assert.equal((result.data.users as Array<Record<string, unknown>>)[0].description, "Synthetic account");
});

test("AD user show returns full detail with object_sid/object_guid decoded and last_logon marked approximate", async () => {
  const sid = `${DOMAIN_SID}-1104`;
  const guid = "04030201-0605-0807-090a-0b0c0d0e0f10";
  const full = entry(JANE_DN, {
    sAMAccountName: ["jdoe"], userPrincipalName: ["jdoe@example.test"], cn: ["Jane Doe"], userAccountControl: ["512"],
    lastLogonTimestamp: ["132223104000000000"], objectSid: [encodeSid(sid).toString("base64")], objectGUID: [encodeGuid(guid).toString("base64")],
  });
  const directory = new RecordedDirectory("ad", [byDn(JANE_DN, full)]);
  const result = await showUser(directory, { base: BASE, flavor: "ad", identifier: JANE_DN, pageSize: 500 });
  const user = result.data.user as Record<string, unknown>;
  assert.equal(user.object_sid, sid);
  assert.equal(user.object_guid, guid);
  assert.equal(user.object_sid_raw, encodeSid(sid).toString("base64"));
  assert.equal(user.object_guid_raw, encodeGuid(guid).toString("base64"));
  assert.equal(user.last_logon, "2020-01-01T00:00:00.000Z");
  assert.equal(user.last_logon_precision, "approximate");
});
test("generic user show includes the RFC 2307 gecos field", async () => {
  const aliceDn = "uid=alice,ou=people,dc=example,dc=test";
  const directory = new RecordedDirectory("ldapv3", [byDn(aliceDn, entry(aliceDn, { uid: ["alice"], gecos: ["Alice Example"] }))]);
  const result = await showUser(directory, { base: BASE, flavor: "ldapv3", identifier: aliceDn, pageSize: 500, fields: ["gecos"] });
  assert.deepEqual(result.data.user, { gecos: "Alice Example" });
});
for (const time of ["000001010000Z", "00000101000000Z", "00000101000000.000Z", "00000101010000+0100"]) {
  test(`generic permanent ppolicy lock ${time} reports disabled and locked state`, async () => {
    const dn = "uid=judy,ou=people,dc=example,dc=test";
    const directory = new RecordedDirectory("ldapv3", [byDn(dn, entry(dn, { pwdAccountLockedTime: [time] }))]);
    const result = await showUser(directory, { base: BASE, flavor: "ldapv3", identifier: dn, pageSize: 500, fields: ["enabled", "locked", "account_state"] });
    assert.deepEqual(result.data.user, { enabled: false, locked: true, account_state: { enabled: false, locked_out: true, pwd_account_locked_time: time } });
  });
}
test("generic timed lock records the timestamp without claiming it is still locked", async () => {
  const dn = "uid=judy,ou=people,dc=example,dc=test";
  const directory = new RecordedDirectory("ldapv3", [byDn(dn, entry(dn, { pwdAccountLockedTime: ["20260101000000Z"] }))]);
  const result = await showUser(directory, { base: BASE, flavor: "ldapv3", identifier: dn, pageSize: 500, fields: ["enabled", "locked", "account_state"] });
  assert.deepEqual(result.data.user, { account_state: { pwd_account_locked_time: "20260101000000Z", locked_out: "unknown" } });
});
test("generic absent or ACL-hidden lock state is omitted", async () => {
  const dn = "uid=alice,ou=people,dc=example,dc=test";
  const directory = new RecordedDirectory("ldapv3", [byDn(dn, entry(dn, { uid: ["alice"] }))]);
  const result = await showUser(directory, { base: BASE, flavor: "ldapv3", identifier: dn, pageSize: 500, fields: ["uid", "enabled", "locked", "account_state"] });
  assert.deepEqual(result.data.user, { uid: "alice" });
});
for (const [flag, filter, attributes, expected] of [
  ["disabled", "(pwdAccountLockedTime=000001010000Z)", { uid: ["judy"], pwdAccountLockedTime: ["000001010000Z"] }, { uid: "judy", enabled: false, locked: true }],
  ["enabled", "(!(pwdAccountLockedTime=000001010000Z))", { uid: ["alice"] }, { uid: "alice" }],
  ["locked", "(pwdAccountLockedTime=*)", { uid: ["judy"], pwdAccountLockedTime: ["000001010000Z"] }, { uid: "judy", enabled: false, locked: true }],
  ["disabled", "(pwdAccountLockedTime=000001010000Z)", { uid: ["judy"], pwdAccountLockedTime: ["00000101000000Z"] }, { uid: "judy", enabled: false, locked: true }],
  ["locked", "(pwdAccountLockedTime=*)", { uid: ["judy"], pwdAccountLockedTime: ["00000101000000Z"] }, { uid: "judy", enabled: false, locked: true }],
] as const) {
  test(`generic --${flag} uses the advertised ppolicy schema for ${"pwdAccountLockedTime" in attributes ? attributes.pwdAccountLockedTime[0] : "absent lock"}`, async () => {
    const dn = "uid=judy,ou=people,dc=example,dc=test";
    const directory = new RecordedDirectory("ldapv3", [
      byDn("cn=Subschema", entry("cn=Subschema", { attributeTypes: ["( 1.3.6.1.4.1.42.2.27.8.1.17 NAME 'pwdAccountLockedTime' EQUALITY generalizedTimeMatch )"] })),
      byFilter([filter], [entry(dn, attributes)]),
    ], { subschemaSubentry: ["cn=Subschema"] });
    const result = await listUsers(directory, { base: BASE, flavor: "ldapv3", pageSize: 500, all: true, scope: "sub", fields: ["uid", "enabled", "locked"], [flag]: true });
    assert.deepEqual(result.data.users, [expected]);
    assert.equal(result.data.partial, undefined);
    assert.equal(result.data.account_state_incomplete, undefined);
    assert.ok(directory.requests.at(-1)!.attributes.includes("pwdAccountLockedTime"));
  });
}
test("generic --locked reports uncertainty for timed lock candidates", async () => {
  const directory = new RecordedDirectory("ldapv3", [
    byDn("cn=Subschema", entry("cn=Subschema", { attributeTypes: ["( 1.3.6.1.4.1.42.2.27.8.1.17 NAME 'pwdAccountLockedTime' )"] })),
    byFilter(["(pwdAccountLockedTime=*)"], [entry("uid=judy,dc=example,dc=test", { uid: ["judy"], pwdAccountLockedTime: ["20260101000000Z"] })]),
  ], { subschemaSubentry: ["cn=Subschema"] });
  const result = await listUsers(directory, { base: BASE, flavor: "ldapv3", pageSize: 500, all: true, scope: "sub", locked: true });
  assert.equal(result.data.partial, true);
  assert.equal(result.data.account_state_incomplete, "lockout_policy_unavailable");
  assert.match(result.help.join(" "), /pwdLockoutDuration/);
});
test("account_state reads locked_out and password_expired from msDS-User-Account-Control-Computed, never the raw bitfield", async () => {
  const full = entry(JANE_DN, { userAccountControl: ["512"], "msDS-User-Account-Control-Computed": [String(0x10 | 0x800000)] });
  const directory = new RecordedDirectory("ad", [byDn(JANE_DN, full)]);
  const result = await showUser(directory, { base: BASE, flavor: "ad", identifier: JANE_DN, pageSize: 500, fields: ["account_state"] });
  const user = result.data.user as Record<string, unknown>;
  assert.deepEqual(user.account_state, { enabled: true, locked_out: true, password_expired: true, user_account_control_raw: 512, user_account_control_flags: ["NORMAL_ACCOUNT"] });
});

test("AD user groups resolves tokenGroups SIDs to names and reports transitive:true", async () => {
  const groupSid = `${DOMAIN_SID}-1108`;
  const group = entry("CN=IT Staff,OU=Groups,DC=example,DC=test", { cn: ["IT Staff"], sAMAccountName: ["IT Staff"], objectClass: ["group"], objectSid: [encodeSid(groupSid).toString("base64")] });
  const user = entry(JANE_DN, { tokenGroups: [encodeSid(groupSid).toString("base64")] });
  const directory = new RecordedDirectory("ad", [byDn(JANE_DN, user), byFilter(["objectSid="], [group])]);
  const result = await userGroups(directory, { base: BASE, flavor: "ad", identifier: JANE_DN, pageSize: 500 });
  assert.equal(result.data.transitive, true);
  assert.equal(result.data.method, "tokenGroups");
  assert.deepEqual(result.data.groups, [{ name: "IT Staff", dn: group.dn, type: "group" }]);
});
test("AD user groups by name requests tokenGroups only on the resolved user's base read", async () => {
  const dn = `CN=alice,${BASE}`;
  const group = entry(`CN=engineering,${BASE}`, { cn: ["engineering"], objectClass: ["group"], objectSid: [encodeSid(`${DOMAIN_SID}-1108`).toString("base64")] });
  const user = entry(dn, { tokenGroups: [encodeSid(`${DOMAIN_SID}-1108`).toString("base64")] });
  const directory = new RecordedDirectory("ad", [request => {
    if (request.scope !== "base" && request.attributes.includes("tokenGroups")) throw Object.assign(new Error("operations error"), { code: 1 });
    return undefined;
  }, byDn(dn, user), byFilter(["sAMAccountName=alice"], [entry(dn, {})]), byFilter(["objectSid="], [group])]);
  const result = await userGroups(directory, { base: BASE, flavor: "ad", identifier: "alice", pageSize: 500 });
  assert.deepEqual(result.data.groups, [{ name: "engineering", dn: group.dn, type: "group" }]);
  assert.deepEqual(directory.requests.filter(request => request.attributes.includes("tokenGroups")).map(request => ({ base: request.base, scope: request.scope })), [{ base: dn, scope: "base" }]);
  assert.ok(["objectSid", "primaryGroupID", "memberOf"].every(attribute => directory.requests[1].attributes.includes(attribute)));
});
test("AD user groups falls back to memberOf plus primaryGroupID when tokenGroups is absent, and is not transitive", async () => {
  const domainUsersSid = `${DOMAIN_SID}-${DOMAIN_USERS_RID}`;
  const domainUsers = entry("CN=Domain Users,CN=Users,DC=example,DC=test", { cn: ["Domain Users"], objectClass: ["group"], objectSid: [encodeSid(domainUsersSid).toString("base64")] });
  const itStaffDn = "CN=IT Staff,OU=Groups,DC=example,DC=test";
  const itStaff = entry(itStaffDn, { cn: ["IT Staff"], objectClass: ["group"] });
  const user = entry(JANE_DN, { memberOf: [itStaffDn], objectSid: [encodeSid(`${DOMAIN_SID}-1104`).toString("base64")], primaryGroupID: [String(DOMAIN_USERS_RID)] });
  const directory = new RecordedDirectory("ad", [byDn(JANE_DN, user), byDn(itStaffDn, itStaff), byFilter(["objectSid="], [domainUsers])]);
  const result = await userGroups(directory, { base: BASE, flavor: "ad", identifier: JANE_DN, pageSize: 500 });
  assert.equal(result.data.transitive, false);
  assert.equal(result.data.method, "memberOf+primaryGroupID");
  const groups = (result.data.groups as Array<{ name: string }>).map(row => row.name);
  assert.ok(groups.includes("IT Staff"));
  assert.ok(groups.includes("Domain Users"), "primaryGroupID resolution must surface the omitted primary group");
});
test("AD memberOf fallback follows ranged values instead of trusting the synthetic empty bare key", async () => {
  const domainUsersSid = `${DOMAIN_SID}-${DOMAIN_USERS_RID}`;
  const domainUsers = entry("CN=Domain Users,CN=Users,DC=example,DC=test", { cn: ["Domain Users"], objectClass: ["group"], objectSid: [encodeSid(domainUsersSid).toString("base64")] });
  const itDn = "CN=IT Staff,OU=Groups,DC=example,DC=test";
  const opsDn = "CN=Ops,OU=Groups,DC=example,DC=test";
  const user = entry(JANE_DN, { memberOf: [], "memberOf;range=0-0": [itDn], objectSid: [encodeSid(`${DOMAIN_SID}-1104`).toString("base64")], primaryGroupID: [String(DOMAIN_USERS_RID)] });
  const directory = new RecordedDirectory("ad", [
    byDnFn(JANE_DN, request => request.attributes.some(attribute => attribute.includes("memberOf;range=1")) ? entry(JANE_DN, { "memberOf;range=1-*": [opsDn] }) : user),
    byFilter(["objectSid="], [domainUsers]),
    byDn(itDn, entry(itDn, { cn: ["IT Staff"], objectClass: ["group"] })),
    byDn(opsDn, entry(opsDn, { cn: ["Ops"], objectClass: ["group"] })),
  ]);
  const result = await userGroups(directory, { base: BASE, flavor: "ad", identifier: JANE_DN, pageSize: 500 });
  assert.deepEqual((result.data.groups as Array<{ name: string }>).map(group => group.name), ["Domain Users", "IT Staff", "Ops"]);
  assert.equal(result.data.partial, undefined);
});
test("AD fallback reserves the membership budget for the primary group", async () => {
  const domainUsersSid = `${DOMAIN_SID}-${DOMAIN_USERS_RID}`;
  const domainUsers = entry("CN=Domain Users,CN=Users,DC=example,DC=test", { cn: ["Domain Users"], objectClass: ["group"], objectSid: [encodeSid(domainUsersSid).toString("base64")] });
  const user = entry(JANE_DN, { memberOf: ["CN=IT Staff,OU=Groups,DC=example,DC=test"], objectSid: [encodeSid(`${DOMAIN_SID}-1104`).toString("base64")], primaryGroupID: [String(DOMAIN_USERS_RID)] });
  const directory = new RecordedDirectory("ad", [byDn(JANE_DN, user), byFilter(["objectSid="], [domainUsers])]);
  const result = await userGroups(directory, { base: BASE, flavor: "ad", identifier: JANE_DN, pageSize: 500, maxRows: 1 });
  assert.deepEqual(result.data.groups, [{ name: "Domain Users", dn: domainUsers.dn, type: "group" }]);
  assert.equal(result.data.partial, true);
});
test("AD fallback reports an unavailable primary group as incomplete", async () => {
  const user = entry(JANE_DN, { memberOf: [] });
  const directory = new RecordedDirectory("ad", [byDn(JANE_DN, user)]);
  const result = await userGroups(directory, { base: BASE, flavor: "ad", identifier: JANE_DN, pageSize: 500 });
  assert.equal(result.data.method, "memberOf+primaryGroupID");
  assert.equal(result.data.partial, true);
  assert.equal(result.data.stop_reason, "primary_group_unavailable");
  assert.equal(result.data.count, "0 of unknown total");
  assert.match(result.help[0], /objectSid and primaryGroupID/);
  assert.doesNotMatch(result.help[0], /max-rows/);
});
test("AD --nested expands both user and primary-group chains without duplicate groups", async () => {
  const domainUsersSid = `${DOMAIN_SID}-${DOMAIN_USERS_RID}`;
  const domainUsers = entry("CN=Domain Users,CN=Users,DC=example,DC=test", { cn: ["Domain Users"], objectClass: ["group"], objectSid: [encodeSid(domainUsersSid).toString("base64")] });
  const admins = entry("CN=Admins,OU=Groups,DC=example,DC=test", { cn: ["Admins"], objectClass: ["group"] });
  const user = entry(JANE_DN, { objectSid: [encodeSid(`${DOMAIN_SID}-1104`).toString("base64")], primaryGroupID: [String(DOMAIN_USERS_RID)] });
  const directory = new RecordedDirectory("ad", [byDn(JANE_DN, user), byFilter(["objectSid="], [domainUsers]), byFilter(["member:1.2.840.113556.1.4.1941", JANE_DN, domainUsers.dn], [domainUsers, admins])]);
  const result = await userGroups(directory, { base: BASE, flavor: "ad", identifier: JANE_DN, pageSize: 37, nested: true });
  assert.equal(result.data.transitive, true);
  assert.equal(result.data.method, "matching-rule-in-chain+primaryGroupID");
  assert.deepEqual((result.data.groups as Array<{ name: string }>).map(group => group.name), ["Domain Users", "Admins"]);
  assert.match(directory.requests.at(-1)?.filter ?? "", /\(objectCategory=group\)/);
  assert.equal(directory.requests.at(-1)?.pageSize, 37);
});
test("AD nested fallback is incomplete when the primary group DN cannot be resolved", async () => {
  const user = entry(JANE_DN, { objectSid: [encodeSid(`${DOMAIN_SID}-1104`).toString("base64")], primaryGroupID: [String(DOMAIN_USERS_RID)] });
  const directory = new RecordedDirectory("ad", [byDn(JANE_DN, user), byFilter(["objectSid="], []), byFilter(["member:1.2.840.113556.1.4.1941", JANE_DN], [])]);
  const result = await userGroups(directory, { base: BASE, flavor: "ad", identifier: JANE_DN, pageSize: 500, nested: true });
  assert.equal(result.data.transitive, true);
  assert.equal(result.data.partial, true);
  assert.equal(result.data.stop_reason, "primary_group_unavailable");
});
test("generic user groups merges memberOf with reverse-search memberships without duplicates", async () => {
  const groupDn = "CN=Staff,OU=Groups,DC=example,DC=test";
  const withMemberOf = entry(JANE_DN, { memberOf: [groupDn], uid: ["jdoe"] });
  const group = entry(groupDn, { cn: ["Staff"] });
  const posix = entry("cn=unix,ou=groups,dc=example,dc=test", { cn: ["unix"], objectClass: ["posixGroup"] });
  const directoryWithMemberOf = new RecordedDirectory("ldapv3", [byDn(JANE_DN, withMemberOf), byDn(groupDn, group), byFilter(["objectClass=posixGroup", "memberUid=jdoe", "uniqueMember="], [group, posix])]);
  const viaMemberOf = await userGroups(directoryWithMemberOf, { base: BASE, flavor: "ldapv3", identifier: JANE_DN, pageSize: 500 });
  assert.equal(viaMemberOf.data.method, "memberOf+reverse-search");
  assert.equal(viaMemberOf.data.transitive, false);
  assert.deepEqual((viaMemberOf.data.groups as Array<{ dn: string }>).map(row => row.dn), [groupDn, posix.dn]);
  const bounded = await userGroups(directoryWithMemberOf, { base: BASE, flavor: "ldapv3", identifier: JANE_DN, pageSize: 500, maxRows: 1 });
  assert.equal((bounded.data.groups as unknown[]).length, 1);
  assert.equal(bounded.data.stop_reason, "max_rows");

  const withoutMemberOf = entry(JANE_DN, { uid: ["jdoe"] });
  const directoryReverse = new RecordedDirectory("ldapv3", [byDn(JANE_DN, withoutMemberOf), byFilter(["groupOfNames"], [group])]);
  const viaReverse = await userGroups(directoryReverse, { base: BASE, flavor: "ldapv3", identifier: JANE_DN, pageSize: 500 });
  assert.equal(viaReverse.data.method, "reverse-search");
  assert.equal(viaReverse.data.transitive, false);

  const posixDirectory = new RecordedDirectory("ldapv3", [byDn(JANE_DN, withoutMemberOf), byFilter(["objectClass=posixGroup", "memberUid=jdoe"], [posix])]);
  const viaMemberUid = await userGroups(posixDirectory, { base: BASE, flavor: "ldapv3", identifier: JANE_DN, pageSize: 23 });
  assert.deepEqual(viaMemberUid.data.groups, [{ name: "unix", dn: posix.dn, type: "group" }]);
  assert.equal(posixDirectory.requests.at(-1)?.pageSize, 23);
});
test("generic reverse search cannot claim completeness for uniqueMember UID suffixes", async () => {
  const directory = new RecordedDirectory("ldapv3", [byDn(JANE_DN, entry(JANE_DN, { uid: ["jdoe"] })), byFilter(["uniqueMember="], [])]);
  const result = await userGroups(directory, { base: BASE, flavor: "ldapv3", identifier: JANE_DN, pageSize: 500 });
  assert.equal(result.data.count, "0 of unknown total");
  assert.equal(result.data.partial, true);
  assert.equal(result.data.stop_reason, "unique_member_uid_not_checked");
  assert.match(result.help[0], /uniqueMember.*UID suffix/);
});
test("generic user groups rejects the AD-only sam field", async () => {
  const directory = new RecordedDirectory("ldapv3", []);
  await assert.rejects(
    () => userGroups(directory, { base: BASE, flavor: "ldapv3", identifier: JANE_DN, pageSize: 500, fields: ["sam"] }),
    (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR" && /unknown field/.test(error.message),
  );
  assert.equal(directory.requests.length, 0);
});
test("--nested on user groups is UNSUPPORTED_BY_SERVER off Active Directory, not silently ignored", async () => {
  const directory = new RecordedDirectory("ldapv3", [byDn(JANE_DN, entry(JANE_DN, {}))]);
  await assert.rejects(
    () => userGroups(directory, { base: BASE, flavor: "ldapv3", identifier: JANE_DN, pageSize: 500, nested: true }),
    (error: unknown) => error instanceof CliError && error.code === "UNSUPPORTED_BY_SERVER",
  );
});
