import assert from "node:assert/strict";
import test from "node:test";
import { membershipSummary, readMultivaluedAttribute, resolveDnMembers, resolveSidMembers } from "../../src/directory/membership.js";
import { encodeSid } from "../../src/directory/sid.js";
import { byDn, byDnFn, byFilter, entry, RecordedDirectory, BASE } from "../support/fixtures.js";

const GROUP_DN = "CN=Big Group,OU=Groups,DC=example,DC=test";

test("an attribute the server never ranged is read as-is, with no extra request", async () => {
  const group = entry(GROUP_DN, { member: ["CN=A,DC=example,DC=test", "CN=B,DC=example,DC=test"] });
  const directory = new RecordedDirectory("ad", []);
  const result = await readMultivaluedAttribute(directory, GROUP_DN, "member", group, 1000);
  assert.deepEqual(result.values, ["CN=A,DC=example,DC=test", "CN=B,DC=example,DC=test"]);
  assert.equal(result.complete, true);
  assert.equal(directory.requests.length, 0);
});

test("a ranged attribute is followed to completion across chunk boundaries", async () => {
  const group = entry(GROUP_DN, { "member;range=0-1": ["CN=A,DC=example,DC=test", "CN=B,DC=example,DC=test"] });
  const directory = new RecordedDirectory("ad", [
    byDnFn(GROUP_DN, request => request.attributes[0]?.includes("range=2") ? entry(GROUP_DN, { "member;range=2-*": ["CN=C,DC=example,DC=test"] }) : group),
  ]);
  const result = await readMultivaluedAttribute(directory, GROUP_DN, "member", group, 1000);
  assert.deepEqual(result.values, ["CN=A,DC=example,DC=test", "CN=B,DC=example,DC=test", "CN=C,DC=example,DC=test"]);
  assert.equal(result.complete, true);
});

test("a ranged attribute walk stops once the row cap is reached and reports incompleteness", async () => {
  const group = entry(GROUP_DN, { "member;range=0-1": ["CN=A,DC=example,DC=test", "CN=B,DC=example,DC=test"] });
  const directory = new RecordedDirectory("ad", [
    byDnFn(GROUP_DN, () => entry(GROUP_DN, { "member;range=2-3": ["CN=C,DC=example,DC=test", "CN=D,DC=example,DC=test"] })),
  ]);
  const result = await readMultivaluedAttribute(directory, GROUP_DN, "member", group, 3);
  assert.equal(result.values.length, 3);
  assert.equal(result.complete, false);
  assert.equal(directory.requests.length, 1);
});
test("a ranged attribute already at or past the cap issues no further request", async () => {
  const group = entry(GROUP_DN, { "member;range=0-1": ["CN=A,DC=example,DC=test", "CN=B,DC=example,DC=test"] });
  const directory = new RecordedDirectory("ad", []);
  const result = await readMultivaluedAttribute(directory, GROUP_DN, "member", group, 2);
  assert.equal(result.values.length, 2);
  assert.equal(result.complete, false);
  assert.equal(directory.requests.length, 0);
});

test("resolveDnMembers resolves each DN via one base-scope read and reports an unresolved dangling reference", async () => {
  const aliceDn = "CN=Alice,OU=Users,DC=example,DC=test";
  const alice = entry(aliceDn, { cn: ["Alice"], sAMAccountName: ["alice"], objectClass: ["top", "person", "user"] });
  const directory = new RecordedDirectory("ad", [byDn(aliceDn, alice), byDn("CN=Ghost,DC=example,DC=test", undefined)]);
  const walk = await resolveDnMembers(directory, [aliceDn, "CN=Ghost,DC=example,DC=test"], 10);
  assert.equal(walk.rows.length, 1);
  assert.equal(walk.rows[0].sam, "alice");
  assert.equal(walk.rows[0].type, "user");
  assert.equal(walk.unresolved.length, 1);
  assert.equal(walk.unresolved[0].raw, "CN=Ghost,DC=example,DC=test");
});

test("resolveDnMembers preserves referral URIs as partial membership data", async () => {
  const referredDn = "CN=Remote,DC=child,DC=example,DC=test";
  const uri = "ldap://child.example.test/DC=child,DC=example,DC=test";
  const directory = new RecordedDirectory("ad", [byDn(referredDn, [{ entries: [], referrals: [uri] }])]);
  const walk = await resolveDnMembers(directory, [referredDn], 10);
  assert.deepEqual(walk.referrals, [uri]);
  assert.equal(walk.partial, true);
  assert.equal(walk.unresolved.length, 1);
});

test("resolveDnMembers preserves server-limit state instead of treating omissions as visibility gaps", async () => {
  const limitedDn = "CN=Limited,DC=example,DC=test";
  const directory = new RecordedDirectory("ad", [byDn(limitedDn, [{ entries: [], stopReason: "server_admin_limit" }])]);
  const walk = await resolveDnMembers(directory, [limitedDn], 10);
  assert.equal(walk.partial, true);
  assert.equal(walk.stopReason, "server_admin_limit");
  assert.match(walk.unresolved[0].reason, /resolution incomplete/);
  assert.equal(membershipSummary(walk, 1).stop_reason, "server_admin_limit");
});

test("resolveDnMembers strips a uniqueMember optional UID suffix before reading", async () => {
  const aliceDn = "CN=Alice,OU=Users,DC=example,DC=test";
  const alice = entry(aliceDn, { cn: ["Alice"], objectClass: ["groupOfUniqueNames"] });
  const directory = new RecordedDirectory("ldapv3", [byDn(aliceDn, alice)]);
  const walk = await resolveDnMembers(directory, [`${aliceDn}#'0101'B`], 10);
  assert.equal(walk.rows.length, 1);
  assert.equal(walk.rows[0].raw, `${aliceDn}#'0101'B`);
  assert.equal(walk.rows[0].dn, aliceDn);
});

test("resolveDnMembers respects the cap and marks the walk partial", async () => {
  const dns = ["CN=A,DC=x", "CN=B,DC=x", "CN=C,DC=x"];
  const directory = new RecordedDirectory("ad", dns.map(dn => byDn(dn, entry(dn, { cn: ["x"] }))));
  const walk = await resolveDnMembers(directory, dns, 2);
  assert.equal(walk.rows.length, 2);
  assert.equal(walk.partial, true);
});

test("resolveSidMembers carries a server limit into its partial summary", async () => {
  const sid = "S-1-5-21-1111111111-2222222222-3333333333-1104";
  const directory = new RecordedDirectory("ad", [byFilter(["objectSid="], [{ entries: [], stopReason: "server_time_limit" }])]);
  const walk = await resolveSidMembers(directory, BASE, [sid], 10, 500);
  assert.equal(walk.stopReason, "server_time_limit");
  assert.equal(walk.partial, true);
  assert.match(walk.unresolved[0].reason, /resolution incomplete/);
});

test("resolveSidMembers batches an objectSid OR-filter and reports a foreign SID as unresolved", async () => {
  const domainSid = "S-1-5-21-1111111111-2222222222-3333333333";
  const localSid = `${domainSid}-1104`;
  const foreignSid = "S-1-5-21-9999999999-8888888888-7777777777-500";
  const bob = entry("CN=Bob,OU=Users,DC=example,DC=test", { cn: ["Bob"], sAMAccountName: ["bob"], objectClass: ["group"], objectSid: [encodeSid(localSid).toString("base64")] });
  const directory = new RecordedDirectory("ad", [byFilter(["objectSid="], [bob])]);
  const walk = await resolveSidMembers(directory, BASE, [localSid, foreignSid], 10, 1);
  assert.equal(directory.requests[0].pageSize, 1);
  assert.equal(walk.rows.length, 1);
  assert.equal(walk.rows[0].name, "Bob");
  assert.equal(walk.unresolved.length, 1);
  assert.equal(walk.unresolved[0].raw, foreignSid);
});
