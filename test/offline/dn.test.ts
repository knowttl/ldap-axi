import assert from "node:assert/strict";
import test from "node:test";
import { isDn, parseDn } from "../../src/directory/dn.js";

test("parses a simple multi-RDN DN", () => {
  const dn = parseDn("CN=Jane Doe,OU=Users,DC=example,DC=test");
  assert.ok(dn);
  assert.equal(dn.rdns.length, 4);
  assert.deepEqual(dn.rdns[0].attributes, [{ type: "CN", value: "Jane Doe", hex: false }]);
});
test("parses a multi-valued RDN joined with +", () => {
  const dn = parseDn("CN=Jane Doe+UID=jdoe,DC=example,DC=test");
  assert.ok(dn);
  assert.equal(dn.rdns[0].attributes.length, 2);
  assert.equal(dn.rdns[0].attributes[1].type, "UID");
});
test("parses a numeric OID attribute type and rejects leading-zero arcs", () => {
  assert.ok(parseDn("1.2.840.113556.1.4.1=x,DC=example,DC=test"));
  assert.equal(parseDn("01.2=x,DC=example,DC=test"), undefined);
  assert.equal(parseDn("1.02=x,DC=example,DC=test"), undefined);
});
test("unescapes comma, plus, hex byte, and leading/trailing space", () => {
  const dn = parseDn("CN=Smith\\, Bob,DC=example,DC=test");
  assert.ok(dn);
  assert.equal(dn.rdns[0].attributes[0].value, "Smith, Bob");
  const withHex = parseDn("CN=\\23sales,DC=example,DC=test");
  assert.ok(withHex);
  assert.equal(withHex.rdns[0].attributes[0].value, "#sales");
  const withSpaces = parseDn("CN=\\ padded\\ ,DC=example,DC=test");
  assert.ok(withSpaces);
  assert.equal(withSpaces.rdns[0].attributes[0].value, " padded ");
});
test("rejects malformed UTF-8 in escaped attribute-value bytes", () => {
  assert.equal(parseDn("CN=\\ff,DC=example,DC=test"), undefined);
  assert.equal(parseDn("CN=\\c3\\28,DC=example,DC=test"), undefined);
});
test("parses a hex attribute value form", () => {
  const dn = parseDn("CN=#04024869,DC=example,DC=test");
  assert.ok(dn);
  assert.equal(dn.rdns[0].attributes[0].hex, true);
  assert.equal(dn.rdns[0].attributes[0].value, "04024869");
});
test("empty string is a valid DN with zero RDNs, but isDn requires at least one", () => {
  assert.deepEqual(parseDn(""), { rdns: [] });
  assert.equal(isDn(""), false);
});
test("rejects a raw leading '#', raw leading space, and raw trailing space", () => {
  assert.equal(parseDn("CN=#nothex,DC=x"), undefined);
  assert.equal(parseDn("CN= leading,DC=x"), undefined);
  assert.equal(parseDn("CN=trailing ,DC=x"), undefined);
});
test("rejects an unescaped special character and structurally invalid input", () => {
  assert.equal(parseDn("CN=a>b,DC=x"), undefined);
  assert.equal(parseDn("CN=a,,DC=x"), undefined);
  assert.equal(parseDn("CN=a,"), undefined);
  assert.equal(parseDn("not a dn at all"), undefined);
  assert.equal(isDn("jdoe"), false);
  assert.equal(isDn("alice@example.test"), false);
});
