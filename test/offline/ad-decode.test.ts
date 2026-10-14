import assert from "node:assert/strict";
import test from "node:test";
import { decodeSid, encodeSid, domainSid, sidWithRid } from "../../src/directory/sid.js";
import { decodeGuid, encodeGuid } from "../../src/directory/guid.js";
import { decodeFiletime, decodeGeneralizedTime } from "../../src/directory/time.js";
import { decodeUserAccountControl } from "../../src/directory/uac.js";
import { decodeGroupType } from "../../src/directory/grouptype.js";

// SID vector authored from MS-DTYP 2.4.2.2 for the well-known BUILTIN\Administrators group,
// S-1-5-32-544: revision 1, 2 sub-authorities, NT authority (5), sub-authorities 32 and 544.
const ADMINISTRATORS_SID_BYTES = Buffer.from("0102000000000005200000002002 0000".replace(/ /g, ""), "hex");
test("objectSid decodes a spec-authored byte vector to its canonical SDDL string", () => {
  assert.equal(decodeSid(ADMINISTRATORS_SID_BYTES), "S-1-5-32-544");
});
test("objectSid encoder round-trips the same vector", () => {
  assert.deepEqual(encodeSid("S-1-5-32-544"), ADMINISTRATORS_SID_BYTES);
});
test("domain SID strips the trailing RID, and a RID can be substituted back in", () => {
  assert.equal(domainSid("S-1-5-21-1111111111-2222222222-3333333333-1104"), "S-1-5-21-1111111111-2222222222-3333333333");
  assert.equal(domainSid("S-1-5"), undefined);
  assert.equal(sidWithRid("S-1-5-21-1111111111-2222222222-3333333333", 513), "S-1-5-21-1111111111-2222222222-3333333333-513");
});

// GUID mixed-endian vector: sequential bytes 01..10, the standard illustrative example for
// AD's mixed-endian objectGUID layout (MS-DTYP 2.3.4.1).
const SEQUENTIAL_GUID_BYTES = Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex");
test("objectGUID decodes mixed-endian bytes to the canonical 8-4-4-4-12 string", () => {
  assert.equal(decodeGuid(SEQUENTIAL_GUID_BYTES), "04030201-0605-0807-090a-0b0c0d0e0f10");
});
test("objectGUID encoder round-trips the same vector", () => {
  assert.deepEqual(encodeGuid("04030201-0605-0807-090a-0b0c0d0e0f10"), SEQUENTIAL_GUID_BYTES);
});

test("FILETIME sentinels render as unset and never, never as a date", () => {
  assert.equal(decodeFiletime("0"), "unset");
  assert.equal(decodeFiletime("9223372036854775807"), "never");
});
test("an ordinary FILETIME value, derived from the documented tick formula, renders ISO 8601", () => {
  // ticks = (unix_ms + 11644473600000) * 10000, for 2020-01-01T00:00:00.000Z (unix_ms 1577836800000).
  assert.equal(decodeFiletime("132223104000000000"), "2020-01-01T00:00:00.000Z");
});
test("GeneralizedTime renders as ISO 8601", () => {
  assert.equal(decodeGeneralizedTime("20240315093000Z"), "2024-03-15T09:30:00.000Z");
  assert.equal(decodeGeneralizedTime("20240315093000.5Z"), "2024-03-15T09:30:00.500Z");
  assert.equal(decodeGeneralizedTime("20240315093000.9999Z"), "2024-03-15T09:30:00.999Z");
  assert.equal(decodeGeneralizedTime("2024031509Z"), "2024-03-15T09:00:00.000Z");
  assert.equal(decodeGeneralizedTime("2024031509.5Z"), "2024-03-15T09:30:00.000Z");
  assert.equal(decodeGeneralizedTime("202403150930,5+0130"), "2024-03-15T08:00:30.000Z");
});

test("userAccountControl decodes a disabled normal account", () => {
  assert.deepEqual(decodeUserAccountControl("514"), { raw: 514, flags: ["ACCOUNTDISABLE", "NORMAL_ACCOUNT"] });
});

test("groupType decodes a valid single-scope security group", () => {
  const decoded = decodeGroupType("-2147483646");
  assert.equal(decoded.unsigned, 2147483650);
  assert.equal(decoded.scope, "global");
  assert.equal(decoded.securityEnabled, true);
  assert.deepEqual(decoded.flags, ["GLOBAL", "SECURITY_ENABLED"]);
  assert.equal(decoded.valid, true);
  assert.equal(decoded.unknownBits, 0);
});
test("groupType treats builtin as orthogonal to a domain-local security scope", () => {
  const decoded = decodeGroupType(String(0x80000005 | 0));
  assert.equal(decoded.scope, "domain_local");
  assert.equal(decoded.builtinLocal, true);
  assert.equal(decoded.securityEnabled, true);
  assert.deepEqual(decoded.flags, ["BUILTIN_LOCAL", "DOMAIN_LOCAL", "SECURITY_ENABLED"]);
  assert.equal(decoded.valid, true);
  assert.deepEqual(decoded.anomalies, []);
});
test("groupType rejects security-enabled application combinations", () => {
  const decoded = decodeGroupType(String(0x80000010 | 0));
  assert.equal(decoded.scope, "application_basic");
  assert.equal(decoded.securityEnabled, true);
  assert.equal(decoded.valid, false);
  assert.match(decoded.anomalies[0], /security-enabled application group/);
});
test("groupType preserves an unknown bit and marks the value invalid rather than discarding it", () => {
  const decoded = decodeGroupType(String(0x2 | 0x40));
  assert.equal(decoded.unknownBits, 0x40);
  assert.equal(decoded.valid, false);
  assert.equal(decoded.scope, "global");
});
test("groupType reports an anomaly for multiple mutually-exclusive scope bits, and still returns data", () => {
  const decoded = decodeGroupType(String(0x2 | 0x4));
  assert.equal(decoded.scope, "unknown");
  assert.equal(decoded.valid, false);
  assert.match(decoded.anomalies[0], /multiple scope bits: GLOBAL,DOMAIN_LOCAL/);
});
test("groupType reports an anomaly when no scope bit is set", () => {
  const decoded = decodeGroupType(String(0x80000000));
  assert.equal(decoded.scope, "unknown");
  assert.deepEqual(decoded.flags, ["SECURITY_ENABLED"]);
  assert.match(decoded.anomalies[0], /no scope or application bit/);
});
