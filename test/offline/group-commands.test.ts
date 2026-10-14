import assert from "node:assert/strict";
import test from "node:test";
import { CliError } from "../../src/core.js";
import { listGroups, showGroup, groupMembers } from "../../src/group.js";
import { encodeGuid } from "../../src/directory/guid.js";
import { encodeSid } from "../../src/directory/sid.js";
import { byDn, byDnFn, byFilter, entry, RecordedDirectory, BASE } from "../support/fixtures.js";

const GROUP_DN = "CN=IT Staff,OU=Groups,DC=example,DC=test";

test("AD group list decodes group_scope and security_enabled from groupType", async () => {
  const group = entry(GROUP_DN, { sAMAccountName: ["IT Staff"], cn: ["IT Staff"], groupType: [String(-2147483646)] });
  const directory = new RecordedDirectory("ad", [byFilter(["objectCategory=group"], [group])]);
  const result = await listGroups(directory, { base: BASE, flavor: "ad", pageSize: 500, all: true, scope: "sub" });
  assert.deepEqual(result.data.groups, [{ sam: "IT Staff", name: "IT Staff", group_scope: "global", security_enabled: true }]);
});
test("generic group list reports the object class instead of an AD-only scope", async () => {
  const group = entry(GROUP_DN, { cn: ["IT Staff"], objectClass: ["top", "groupOfNames"] });
  const directory = new RecordedDirectory("ldapv3", [byFilter(["groupOfNames"], [group])]);
  const result = await listGroups(directory, { base: BASE, flavor: "ldapv3", pageSize: 500, all: true, scope: "sub" });
  assert.deepEqual(result.data.groups, [{ name: "IT Staff", object_class: ["top", "groupOfNames"] }]);
});
test("--sam on group list is UNSUPPORTED_BY_SERVER off Active Directory", async () => {
  const directory = new RecordedDirectory("ldapv3", []);
  await assert.rejects(() => listGroups(directory, { base: BASE, flavor: "ldapv3", pageSize: 500, all: true, scope: "sub", sam: "x" }), (error: unknown) => error instanceof CliError && error.code === "UNSUPPORTED_BY_SERVER");
});
test("requested raw attributes are emitted by group list", async () => {
  const group = entry(GROUP_DN, { cn: ["IT Staff"], objectClass: ["groupOfNames"], description: ["Synthetic group"] });
  const directory = new RecordedDirectory("ldapv3", [byFilter(["groupOfNames"], [group])]);
  const result = await listGroups(directory, { base: BASE, flavor: "ldapv3", pageSize: 500, all: true, scope: "sub", attributes: ["description"] });
  assert.equal((result.data.groups as Array<Record<string, unknown>>)[0].description, "Synthetic group");
});
test("a bare requested attribute emits its optioned values while an optioned request remains exact", async () => {
  const group = entry(GROUP_DN, { cn: ["IT Staff"], objectClass: ["groupOfNames"], "description;lang-en": ["English"], "description;lang-fr": ["French"] });
  const bareResult = await listGroups(new RecordedDirectory("ldapv3", [byFilter(["groupOfNames"], [group])]), { base: BASE, flavor: "ldapv3", pageSize: 500, all: true, scope: "sub", attributes: ["description"] });
  assert.deepEqual((bareResult.data.groups as Array<Record<string, unknown>>)[0], { name: "IT Staff", object_class: ["groupOfNames"], "description;lang-en": "English", "description;lang-fr": "French" });
  const optionedResult = await listGroups(new RecordedDirectory("ldapv3", [byFilter(["groupOfNames"], [group])]), { base: BASE, flavor: "ldapv3", pageSize: 500, all: true, scope: "sub", attributes: ["description;lang-en"] });
  assert.deepEqual((optionedResult.data.groups as Array<Record<string, unknown>>)[0], { name: "IT Staff", object_class: ["groupOfNames"], "description;lang-en": "English" });
});

test("AD group show performs the full lossless groupType decode for a valid security group", async () => {
  const group = entry(GROUP_DN, { sAMAccountName: ["IT Staff"], cn: ["IT Staff"], groupType: [String(-2147483646)], member: ["CN=A,DC=x", "CN=B,DC=x"] });
  const directory = new RecordedDirectory("ad", [byDn(GROUP_DN, group)]);
  const result = await showGroup(directory, { base: BASE, flavor: "ad", identifier: GROUP_DN, pageSize: 500 });
  const data = result.data.group as Record<string, unknown>;
  assert.equal(data.group_scope, "global");
  assert.equal(data.security_enabled, true);
  assert.equal(data.group_type_valid, true);
  assert.equal(data.group_type_unknown_bits, undefined);
  assert.equal(data.member_count, 2);
  assert.equal(data.member_count_complete, false);
  assert.equal(data.member_count_stop_reason, "primary_group_members_not_included");
  assert.deepEqual(data.member_count_limitations, ["primary_group_members_not_included"]);
});
test("AD group show emits raw companions for decoded binary fields", async () => {
  const sid = "S-1-5-21-1111111111-2222222222-3333333333-1108";
  const guid = "04030201-0605-0807-090a-0b0c0d0e0f10";
  const sidRaw = encodeSid(sid).toString("base64");
  const guidRaw = encodeGuid(guid).toString("base64");
  const group = entry(GROUP_DN, { objectSid: [sidRaw], objectSid_raw: [sidRaw], objectGUID: [guidRaw], objectGUID_raw: [guidRaw] });
  const directory = new RecordedDirectory("ad", [byDn(GROUP_DN, group)]);
  const result = await showGroup(directory, { base: BASE, flavor: "ad", identifier: GROUP_DN, pageSize: 500, fields: ["object_sid", "object_guid"] });
  assert.deepEqual(result.data.group, { object_sid: sid, object_guid: guid, object_sid_raw: sidRaw, object_guid_raw: guidRaw });
});
test("AD group show preserves an unknown groupType bit and malformed combinations as observable data, not a failure", async () => {
  const malformed = String((0x2 | 0x4 | 0x40) >>> 0); // GLOBAL + DOMAIN_LOCAL (mutually exclusive) + an unknown bit
  const group = entry(GROUP_DN, { cn: ["IT Staff"], groupType: [malformed] });
  const directory = new RecordedDirectory("ad", [byDn(GROUP_DN, group)]);
  const result = await showGroup(directory, { base: BASE, flavor: "ad", identifier: GROUP_DN, pageSize: 500 });
  const data = result.data.group as Record<string, unknown>;
  assert.equal(data.group_type_valid, false);
  assert.equal(data.group_type_unknown_bits, "0x00000040");
  assert.match((data.group_type_anomalies as string[])[0], /multiple scope bits/);
});
test("AD group show counts the complete member attribute without claiming complete membership", async () => {
  const group = entry(GROUP_DN, { cn: ["IT Staff"], "member;range=0-1": ["CN=A,DC=x", "CN=B,DC=x"] });
  const directory = new RecordedDirectory("ad", [
    byDnFn(GROUP_DN, request => request.attributes[0]?.includes("range=2") ? entry(GROUP_DN, { "member;range=2-*": ["CN=C,DC=x"] }) : group),
  ]);
  const result = await showGroup(directory, { base: BASE, flavor: "ad", identifier: GROUP_DN, pageSize: 500 });
  const data = result.data.group as Record<string, unknown>;
  assert.equal(data.member_count, 3);
  assert.equal(data.member_count_complete, false);
  assert.equal(data.member_count_stop_reason, "primary_group_members_not_included");
});
test("group show surfaces referrals that make ranged member counts incomplete", async () => {
  const uri = "ldap://child.example.test/DC=child,DC=example,DC=test";
  const group = entry(GROUP_DN, { "member;range=0-0": ["CN=A,DC=x"] });
  const directory = new RecordedDirectory("ad", [request => request.scope === "base" && request.base === GROUP_DN
    ? request.attributes[0]?.includes("range=1") ? [{ entries: [], referrals: [uri] }] : [{ entries: [group] }]
    : undefined]);
  const result = await showGroup(directory, { base: BASE, flavor: "ad", identifier: GROUP_DN, pageSize: 500 });
  const data = result.data.group as Record<string, unknown>;
  assert.equal(data.member_count_complete, false);
  assert.deepEqual(data.referrals, [{ uri }]);
});
test("generic group show reports member_form:uid for a posixGroup without fabricating DNs", async () => {
  const group = entry(GROUP_DN, { cn: ["admins"], objectClass: ["posixGroup"], memberUid: ["alice", "bob"] });
  const directory = new RecordedDirectory("ldapv3", [byDn(GROUP_DN, group)]);
  const result = await showGroup(directory, { base: BASE, flavor: "ldapv3", identifier: GROUP_DN, pageSize: 500 });
  const data = result.data.group as Record<string, unknown>;
  assert.equal(data.member_form, "uid");
  assert.equal(data.member_count, 2);
});

test("AD group members resolves direct member DNs and reports an unresolved dangling reference", async () => {
  const aliceDn = "CN=Alice,OU=Users,DC=example,DC=test";
  const alice = entry(aliceDn, { cn: ["Alice"], sAMAccountName: ["alice"], objectClass: ["user"] });
  const group = entry(GROUP_DN, { objectClass: ["group"], member: [aliceDn, "CN=Ghost,DC=example,DC=test"] });
  const directory = new RecordedDirectory("ad", [byDn(GROUP_DN, group), byDn(aliceDn, alice), byDn("CN=Ghost,DC=example,DC=test", undefined)]);
  const result = await groupMembers(directory, { base: BASE, flavor: "ad", identifier: GROUP_DN, pageSize: 500 });
  assert.equal(result.data.transitive, false);
  assert.equal(result.data.method, "member");
  assert.deepEqual(result.data.members, [{ sam: "alice", name: "Alice", type: "user" }]);
  assert.equal(directory.requests[1].attributes.includes("uid"), false);
  assert.equal((result.data.unresolved as unknown[]).length, 1);
  assert.equal(result.data.partial, true);
  assert.equal(result.data.stop_reason, "primary_group_members_not_included");
  assert.match(result.help[0], /primaryGroupID/);
});
test("AD group members --nested walks the matching-rule-in-chain and reports transitive:true", async () => {
  const group = entry(GROUP_DN, { objectClass: ["group"] });
  const nestedUser = entry("CN=Alice,OU=Users,DC=example,DC=test", { cn: ["Alice"], sAMAccountName: ["alice"], objectClass: ["user"] });
  const directory = new RecordedDirectory("ad", [byDn(GROUP_DN, group), byFilter(["1.2.840.113556.1.4.1941"], [nestedUser])]);
  const result = await groupMembers(directory, { base: BASE, flavor: "ad", identifier: GROUP_DN, pageSize: 500, nested: true });
  assert.equal(result.data.transitive, true);
  assert.equal(result.data.method, "matching-rule-in-chain");
  assert.match(directory.requests[1].filter, /^\(memberOf:1\.2\.840\.113556\.1\.4\.1941:=/);
  assert.deepEqual(result.data.members, [{ sam: "alice", name: "Alice", type: "user" }]);
  assert.equal(result.data.partial, true);
  assert.equal(result.data.stop_reason, "primary_group_members_not_included");
  assert.doesNotMatch(result.help.join("\n"), /--all/);
});
test("group member fields are validated against the detected flavor", async () => {
  const ad = new RecordedDirectory("ad", []);
  await assert.rejects(
    () => groupMembers(ad, { base: BASE, flavor: "ad", identifier: GROUP_DN, pageSize: 500, fields: ["uid"] }),
    (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR" && /unknown field/.test(error.message),
  );
  const generic = new RecordedDirectory("ldapv3", []);
  await assert.rejects(
    () => groupMembers(generic, { base: BASE, flavor: "ldapv3", identifier: GROUP_DN, pageSize: 500, fields: ["sam"] }),
    (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR" && /unknown field/.test(error.message),
  );
  assert.equal(ad.requests.length + generic.requests.length, 0);
});
test("--nested on group members is UNSUPPORTED_BY_SERVER off Active Directory, not silently ignored", async () => {
  const group = entry(GROUP_DN, { objectClass: ["groupOfNames"] });
  const directory = new RecordedDirectory("ldapv3", [byDn(GROUP_DN, group)]);
  await assert.rejects(
    () => groupMembers(directory, { base: BASE, flavor: "ldapv3", identifier: GROUP_DN, pageSize: 500, nested: true }),
    (error: unknown) => error instanceof CliError && error.code === "UNSUPPORTED_BY_SERVER",
  );
});
test("generic group members does not classify unresolved memberUid values as users", async () => {
  const group = entry(GROUP_DN, { objectClass: ["posixGroup"], memberUid: ["alice", "ghost"] });
  const directory = new RecordedDirectory("ldapv3", [byDn(GROUP_DN, group)]);
  const result = await groupMembers(directory, { base: BASE, flavor: "ldapv3", identifier: GROUP_DN, pageSize: 500 });
  assert.equal(result.data.method, "memberUid");
  assert.equal(result.data.member_form, "uid");
  assert.deepEqual(result.data.members, [{ uid: "alice", type: "unresolved" }, { uid: "ghost", type: "unresolved" }]);
  assert.equal(directory.requests.length, 1, "a posixGroup's bare usernames must not trigger per-name resolution reads");
});
test("generic memberUid membership respects the shared row budget", async () => {
  const group = entry(GROUP_DN, { objectClass: ["posixGroup"], memberUid: ["alice", "bob", "carol"] });
  const directory = new RecordedDirectory("ldapv3", [byDn(GROUP_DN, group)]);
  const result = await groupMembers(directory, { base: BASE, flavor: "ldapv3", identifier: GROUP_DN, pageSize: 500, maxRows: 2 });
  assert.deepEqual(result.data.members, [{ uid: "alice", type: "unresolved" }, { uid: "bob", type: "unresolved" }]);
  assert.equal(result.data.count, "2 of unknown total");
  assert.equal(result.data.partial, true);
});
test("generic group members strips a uniqueMember optional UID suffix before resolving", async () => {
  const aliceDn = "CN=Alice,OU=Users,DC=example,DC=test";
  const alice = entry(aliceDn, { cn: ["Alice"], objectClass: ["person"] });
  const group = entry(GROUP_DN, { objectClass: ["groupOfUniqueNames"], uniqueMember: [`${aliceDn}#'0101'B`] });
  const directory = new RecordedDirectory("ldapv3", [byDn(GROUP_DN, group), byDn(aliceDn, alice)]);
  const result = await groupMembers(directory, { base: BASE, flavor: "ldapv3", identifier: GROUP_DN, pageSize: 500 });
  assert.equal(result.data.method, "uniqueMember");
  assert.deepEqual(result.data.members, [{ name: "Alice", type: "user" }]);
});
