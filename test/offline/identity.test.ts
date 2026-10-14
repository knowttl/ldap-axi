import assert from "node:assert/strict";
import test from "node:test";
import { CliError } from "../../src/core.js";
import { resolveIdentity, type IdentityQuery } from "../../src/directory/identity.js";
import { byDn, byFilter, entry, RecordedDirectory, BASE } from "../support/fixtures.js";

const USER_QUERY: IdentityQuery = {
  noun: "user",
  shapeFilter: "(objectCategory=person)",
  searchFilter: "(&(objectCategory=person)(|(sAMAccountName=jdoe)(userPrincipalName=jdoe)))",
};
const JANE_DN = "CN=Jane Doe,OU=Users,DC=example,DC=test";
const JANE = entry(JANE_DN, { cn: ["Jane Doe"], sAMAccountName: ["jdoe"] });
// The three continuation references an AD domain-root subtree search always returns (§5.5, §9.6).
const CONFIG_REF = "ldap://example.test/CN=Configuration,DC=example,DC=test";
const DOMAIN_DNS_REF = "ldap://example.test/DC=DomainDnsZones,DC=example,DC=test";
const FOREST_DNS_REF = "ldap://example.test/DC=ForestDnsZones,DC=example,DC=test";

test("a valid DN gets one base-scope read with required object-shape validation", async () => {
  const directory = new RecordedDirectory("ad", [byDn(JANE_DN, JANE)]);
  const found = await resolveIdentity(directory, JANE_DN, BASE, USER_QUERY, ["cn"], 500);
  assert.equal(found.dn, JANE_DN);
  assert.equal(directory.requests.length, 1);
  assert.equal(directory.requests[0].scope, "base");
});
test("a DN that exists but fails the object-shape filter is NOT_FOUND, never a fallback search", async () => {
  const directory = new RecordedDirectory("ad", [byDn(JANE_DN, undefined)]);
  await assert.rejects(() => resolveIdentity(directory, JANE_DN, BASE, USER_QUERY, ["cn"], 500), (error: unknown) => error instanceof CliError && error.code === "NOT_FOUND");
  assert.equal(directory.requests.length, 1);
});
test("a non-DN identifier with zero matches is NOT_FOUND", async () => {
  const directory = new RecordedDirectory("ad", [byFilter(["sAMAccountName=jdoe"], [])]);
  await assert.rejects(() => resolveIdentity(directory, "jdoe", BASE, USER_QUERY, ["cn"], 500), (error: unknown) => error instanceof CliError && error.code === "NOT_FOUND");
});
test("a non-DN identifier with exactly one match is returned, via one subtree search", async () => {
  const directory = new RecordedDirectory("ad", [byFilter(["sAMAccountName=jdoe"], [JANE])]);
  const found = await resolveIdentity(directory, "jdoe", BASE, USER_QUERY, ["cn"], 500);
  assert.equal(found.dn, JANE_DN);
  assert.equal(directory.requests.length, 1);
  assert.equal(directory.requests[0].scope, "sub");
});
test("a non-DN identifier with more than one match is VALIDATION_ERROR requiring a DN, never a preferred match", async () => {
  const other = entry("CN=Jane Other,OU=Users,DC=example,DC=test", { cn: ["Jane Other"], sAMAccountName: ["jdoe"] });
  const directory = new RecordedDirectory("ad", [byFilter(["sAMAccountName=jdoe"], [JANE, other])]);
  await assert.rejects(() => resolveIdentity(directory, "jdoe", BASE, USER_QUERY, ["cn"], 500), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR" && /distinguished name/.test(error.help.join(" ")));
});
test("an incomplete identity search never claims uniqueness or absence", async () => {
  const limited = new RecordedDirectory("ad", [byDn(JANE_DN, [{ entries: [], stopReason: "server_size_limit" }])]);
  await assert.rejects(() => resolveIdentity(limited, JANE_DN, BASE, USER_QUERY, ["cn"], 500), (error: unknown) => error instanceof CliError && error.code === "SERVER_LIMIT");

  // A terminal result code 10 searched nothing at all, unlike a continuation reference.
  const refused = new RecordedDirectory("ad", [byFilter(["sAMAccountName=jdoe"], [{ entries: [], referrals: [CONFIG_REF], stopReason: "referral" }])]);
  await assert.rejects(() => resolveIdentity(refused, "jdoe", BASE, USER_QUERY, ["cn"], 500), (error: unknown) => error instanceof CliError && error.code === "SERVER_LIMIT" && /incomplete/.test(error.message));
});
test("AD domain-root continuation references do not spoil a unique identifier match", async () => {
  const directory = new RecordedDirectory("ad", [byFilter(["sAMAccountName=jdoe"], [
    { entries: [], referrals: [CONFIG_REF, DOMAIN_DNS_REF] },
    { entries: [JANE], referrals: [FOREST_DNS_REF] },
  ])]);
  const found = await resolveIdentity(directory, "jdoe", BASE, USER_QUERY, ["cn"], 500);
  assert.equal(found.dn, JANE_DN);
  assert.equal(directory.requests.length, 1);
});
test("continuation references still make ambiguity ambiguous and absence explicit about what was not searched", async () => {
  const other = entry("CN=Jane Other,OU=Users,DC=example,DC=test", { cn: ["Jane Other"], sAMAccountName: ["jdoe"] });
  const ambiguous = new RecordedDirectory("ad", [byFilter(["sAMAccountName=jdoe"], [{ entries: [JANE, other], referrals: [CONFIG_REF] }])]);
  await assert.rejects(() => resolveIdentity(ambiguous, "jdoe", BASE, USER_QUERY, ["cn"], 500), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR");

  const absent = new RecordedDirectory("ad", [byFilter(["sAMAccountName=jdoe"], [{ entries: [], referrals: [CONFIG_REF, CONFIG_REF] }])]);
  await assert.rejects(() => resolveIdentity(absent, "jdoe", BASE, USER_QUERY, ["cn"], 500), (error: unknown) =>
    error instanceof CliError && error.code === "NOT_FOUND" && error.help.join(" ").includes(CONFIG_REF) && !/CN=Configuration.*CN=Configuration/.test(error.help.join(" ")));
});
test("a subordinate OpenLDAP referral is reported, never chased into a second search", async () => {
  const uri = "ldap://child.example.test/DC=child,DC=example,DC=test";
  const directory = new RecordedDirectory("ldapv3", [byFilter(["sAMAccountName=jdoe"], [{ entries: [], referrals: [uri] }])]);
  await assert.rejects(() => resolveIdentity(directory, "jdoe", BASE, USER_QUERY, ["cn"], 500), (error: unknown) => error instanceof CliError && error.code === "NOT_FOUND" && error.help.join(" ").includes(uri));
  assert.equal(directory.requests.length, 1);
});
test("no retry across identifier forms: exactly one search is issued regardless of outcome", async () => {
  const directory = new RecordedDirectory("ad", [byFilter(["sAMAccountName=jdoe"], [JANE])]);
  await resolveIdentity(directory, "jdoe", BASE, USER_QUERY, ["cn"], 500);
  assert.equal(directory.requests.length, 1);
});
