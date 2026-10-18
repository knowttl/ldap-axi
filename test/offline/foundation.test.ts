import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import test from "node:test";
import { parse } from "../../src/cli.js";
import { attributeBaseName, CliError, type Directory, type RootDse, type SearchPage, type SearchRequest } from "../../src/core.js";
import { validatePageSize } from "../../src/config.js";
import { AdminLimitExceededError, Attribute, NoSuchObjectError, SearchEntry, SizeLimitExceededError, TimeLimitExceededError, UnknownStatusCodeError } from "ldapts";
import { CONTROL_OIDS, EXTENDED_OIDS, OPERATIONS } from "../../src/directory/policy.js";
import { limitStopReason, mapAttributes, openDirectory, searchFailurePage } from "../../src/directory/client.js";
import { translateLdapError } from "../../src/directory/errors.js";
import { filterValue, searchEntries, showEntry } from "../../src/entry.js";
import { selectFields, userListSchema } from "../../src/schema.js";

// A minimal BER encoder for the one served rootDSE entry below; the offline suite has no LDAP server.
function der(tag: number, value: Uint8Array): Buffer {
  const bytes = Buffer.from(value);
  if (bytes.length < 0x80) return Buffer.concat([Buffer.from([tag, bytes.length]), bytes]);
  const length: number[] = [];
  for (let remaining = bytes.length; remaining; remaining = Math.floor(remaining / 0x100)) length.unshift(remaining & 0xff);
  return Buffer.concat([Buffer.from([tag, 0x80 | length.length, ...length]), bytes]);
}
function readTlv(buffer: Buffer, offset: number): { tag: number; value: Buffer; end: number } {
  const first = buffer[offset + 1]!;
  const lengthBytes = first < 0x80 ? 0 : first & 0x7f;
  const header = lengthBytes ? 2 + lengthBytes : 2;
  let length = lengthBytes ? 0 : first;
  for (let index = 0; index < lengthBytes; index += 1) length = length * 0x100 + buffer[offset + 2 + index]!;
  return { tag: buffer[offset]!, value: buffer.subarray(offset + header, offset + header + length), end: offset + header + length };
}
function ldapMessage(messageId: number, operation: Buffer, controls?: Buffer): Buffer {
  return der(0x30, Buffer.concat([der(0x02, Buffer.from([messageId])), operation, ...(controls ? [controls] : [])]));
}
function searchResultEntry(messageId: number, attributes: Readonly<Record<string, readonly string[]>>): Buffer {
  const encoded = Object.entries(attributes).map(([type, values]) => der(0x30, Buffer.concat([
    der(0x04, Buffer.from(type)),
    der(0x31, Buffer.concat(values.map(value => der(0x04, Buffer.from(value))))),
  ])));
  return ldapMessage(messageId, der(0x64, Buffer.concat([der(0x04, Buffer.alloc(0)), der(0x30, Buffer.concat(encoded))])));
}
function searchResultDone(messageId: number): Buffer {
  const emptyCookie = der(0x30, Buffer.concat([der(0x02, Buffer.from([0])), der(0x04, Buffer.alloc(0))]));
  const controls = der(0xa0, der(0x30, Buffer.concat([der(0x04, Buffer.from("1.2.840.113556.1.4.319")), der(0x04, emptyCookie)])));
  return ldapMessage(messageId, der(0x65, Buffer.concat([der(0x0a, Buffer.from([0])), der(0x04, Buffer.alloc(0)), der(0x04, Buffer.alloc(0))])), controls);
}
function listening(server: Server): Promise<number> {
  return new Promise(resolve => server.listen(0, "127.0.0.1", () => {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    resolve(address.port);
  }));
}

class RecordedDirectory implements Directory {
  readonly flavor = "ldapv3" as const;
  requests: SearchRequest[] = [];
  async rootDSE(): Promise<RootDse> { return { flavor: this.flavor, attributes: { namingContexts: ["dc=example,dc=test"] } }; }
  async *searchPages(request: SearchRequest) { this.requests.push(request); yield { entries: [{ dn: "cn=synthetic,dc=example,dc=test", attributes: { cn: ["synthetic"], description: ["safe"] } }], referrals: [] }; }
  async whoami(): Promise<string | undefined> { return undefined; }
  async close(): Promise<void> {}
}
test("registry is frozen and has only read-safe operations", () => { assert.deepEqual(Object.keys(OPERATIONS), ["rootDSE", "searchPaged", "bind", "unbind", "startTLS", "whoami"]); assert.deepEqual([...EXTENDED_OIDS], ["1.3.6.1.4.1.1466.20037", "1.3.6.1.4.1.4203.1.11.3"]); assert.deepEqual([...CONTROL_OIDS], ["1.2.840.113556.1.4.319"]); assert.throws(() => { (OPERATIONS as any).bind = {}; }); });
test("parser rejects unsupported input before any directory can open", () => {
  assert.throws(() => parse(["entry", "search", "--disable"]), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR");
  assert.throws(() => parse(["entry", "search", "--cursor", "opaque"]), (error: unknown) => error instanceof CliError && /out of scope/.test(error.message));
  assert.throws(() => parse(["entry", "search", "--all"]), (error: unknown) => error instanceof CliError && /max-rows/.test(error.message));
});
test("request-shaped validation runs during parse, before any connection", () => {
  const rejected = (argv: string[]) => assert.throws(() => parse(argv), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR");
  rejected(["entry", "search", "--scope", "garbage"]);
  rejected(["entry", "search", "--filter", "(("]);
  rejected(["entry", "search", "--attributes", "userPassword"]);
  rejected(["entry", "search", "--attributes", "userPassword;binary"]);
  rejected(["entry", "search", "--attributes", "2.5.4.35"]);
  rejected(["entry", "search", "--attributes", "1.2.840.113556.1.4.90;binary"]);
  rejected(["entry", "search", "--attributes", "*"]);
  rejected(["entry", "search", "--attributes", "+"]);
  rejected(["user", "show", "alice", "--attributes", "unicodePwd;lang-x"]);
  rejected(["entry", "search", "--max-rows", "abc"]);
  rejected(["entry", "search", "--page-size", "1001"]);
  rejected(["entry", "show", "cn=x,dc=example,dc=test", "--attributes", "unicodePwd"]);
});
test("an explicit empty entry-search base remains distinct and reaches the request", async () => {
  assert.equal(parse(["entry", "search", "--scope", "base"]).flags.base, undefined);
  assert.equal(parse(["entry", "search", "--base", "", "--scope", "base"]).flags.base, "");
  assert.equal(parse(["entry", "search", "--base=", "--scope=base"]).flags.base, "");
  assert.throws(() => parse(["entry", "search", "--base", ""]), (error: unknown) => error instanceof CliError && /requires --scope base/.test(error.message));
  const directory = new RecordedDirectory();
  await searchEntries(directory, { base: "", filter: "(objectClass=*)", scope: "base", attributes: ["cn"], pageSize: 500, all: true });
  assert.equal(directory.requests[0]?.base, "");
});
test("filter literal escaping uses RFC 4515 escapes", () => { assert.equal(filterValue("a*(b)\\\0"), "a\\2a\\28b\\29\\5c\\00"); });
test("recorded directory provides an offline entry search seam", async () => { const directory = new RecordedDirectory(); const result = await searchEntries(directory, { base: "dc=example,dc=test", filter: "(objectClass=*)", scope: "sub", attributes: ["cn"], pageSize: 500, all: true }); assert.equal((result.data.entries as unknown[]).length, 1); assert.equal(directory.requests.length, 1); });
test("LDAP URL userinfo is rejected before a connection is opened", async () => {
  await assert.rejects(() => openDirectory({ url: "ldap://bind-dn:password@127.0.0.1:1", startTls: false, caOnly: false, tlsNoVerify: false, insecurePlaintext: true, anonymous: true }), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR" && /must not contain credentials/.test(error.message));
});
test("a served rootDSE entry maps into attributes and flavor detection", async () => {
  // RecordedDirectory replaces LdapDirectory.rootDSE, so only a served BER entry proves that the
  // real client reads the plain `{ dn, ...attributes }` entry shape ldapts yields.
  const server = createServer(socket => socket.on("data", data => {
    const message = readTlv(data, 0);
    const id = readTlv(message.value, 0);
    const operation = readTlv(message.value, id.end);
    if (operation.tag !== 0x63) return;
    const messageId = id.value.readUIntBE(0, id.value.length);
    socket.write(Buffer.concat([
      searchResultEntry(messageId, { supportedCapabilities: ["1.2.840.113556.1.4.800"], defaultNamingContext: ["DC=example,DC=test"], supportedLDAPPolicies: ["MaxPageSize"], maxPageSize: ["250"], configurationNamingContext: ["CN=Configuration,DC=example,DC=test"] }),
      searchResultDone(messageId),
    ]));
  }));
  const port = await listening(server);
  try {
    const directory = await openDirectory({ url: `ldap://127.0.0.1:${port}`, startTls: false, caOnly: false, tlsNoVerify: false, insecurePlaintext: true, anonymous: true });
    assert.equal(directory.flavor, "ad");
    const root = await directory.rootDSE();
    assert.deepEqual(root.attributes.defaultNamingContext, ["DC=example,DC=test"]);
    assert.deepEqual(root.attributes.supportedLDAPPolicies, ["MaxPageSize"]);
    assert.deepEqual(root.attributes.maxPageSize, ["250"]);
    assert.deepEqual(root.attributes.configurationNamingContext, ["CN=Configuration,DC=example,DC=test"]);
    const result = await searchEntries(directory, { base: "", filter: "(objectClass=*)", scope: "base", attributes: ["supportedCapabilities"], pageSize: 500, all: false });
    assert.equal(result.data.count, "1 of 1 total");
    assert.equal(result.data.incomplete, undefined);
    await directory.close();
  } finally {
    server.close();
  }
});
test("bounded multivalue output reports truncation and the original count", async () => {
  const values = Array.from({ length: 51 }, (_, index) => `value-${index}`);
  const directory = new LimitDirectory({ entries: [{ dn: "cn=synthetic,dc=example,dc=test", attributes: { description: values } }] });
  const result = await searchEntries(directory, { base: "dc=example,dc=test", filter: "(objectClass=*)", scope: "sub", attributes: ["description"], pageSize: 500, all: true });
  const entry = (result.data.entries as Record<string, unknown>[])[0];
  assert.equal((entry.description as string[]).length, 50);
  assert.equal(entry.description_value_count, 51);
  assert.equal(entry.description_values_truncated, true);
});
test("a default read distinguishes an exhausted page from a continuation and a definitive empty result", async () => {
  const entry = { dn: "cn=a,dc=example,dc=test", attributes: { cn: ["a"] } };
  const request = { base: "dc=example,dc=test", filter: "(objectClass=*)", scope: "sub" as const, attributes: ["cn"], pageSize: 500, all: false };
  const complete = await searchEntries(new PagedDirectory([{ entries: [entry] }]), request);
  assert.equal(complete.data.count, "1 of 1 total");
  assert.equal(complete.data.incomplete, undefined);
  const empty = await searchEntries(new PagedDirectory([{ entries: [] }]), request);
  assert.equal(empty.data.entries, "0 entries matched under dc=example,dc=test");
  const incomplete = await searchEntries(new PagedDirectory([{ entries: [entry] }, { entries: [entry] }]), request);
  assert.equal(incomplete.data.incomplete, "page_boundary");
  assert.equal((incomplete.data.entries as unknown[]).length, 1);
  assert.match(incomplete.help[0], /--all --max-rows/);
});
test("search references make entry searches partial and preserve their URIs", async () => {
  const uri = "ldap://child.example.test/DC=child,DC=example,DC=test";
  const result = await searchEntries(new LimitDirectory({ entries: [], referrals: [uri] }), { base: "dc=example,dc=test", filter: "(objectClass=*)", scope: "sub", attributes: ["cn"], pageSize: 500, all: true });
  assert.equal(result.data.count, "0 of unknown total");
  assert.equal(result.data.partial, true);
  assert.equal(result.data.stop_reason, "referral");
  assert.deepEqual(result.data.referrals, [{ uri }]);
  assert.match(result.help[0], /not chased/);
  assert.doesNotMatch(result.help[0], /--all/);
});
class LimitDirectory implements Directory {
  readonly flavor = "ldapv3" as const;
  constructor(private readonly page: SearchPage) {}
  async rootDSE(): Promise<RootDse> { return { flavor: this.flavor, attributes: {} }; }
  async *searchPages(): AsyncIterable<SearchPage> { yield this.page; }
  async whoami(): Promise<string | undefined> { return undefined; }
  async close(): Promise<void> {}
}
test("DN-only field selections request no LDAP attributes", () => {
  const selected = selectFields(userListSchema("ad"), ["dn"]);
  assert.deepEqual(selected.attributes, ["1.1"]);
  assert.deepEqual(selected.fieldAttributes, ["1.1"]);
});
test("known binary attributes remain buffers before attribute mapping", () => {
  const bytes = Buffer.from([0xff, 0x00, 0xfe, 0x80]);
  for (const type of ["OBJECTSID", "tokenGroups;range=0-*"]) {
    const attribute = new Attribute({ type, values: [bytes.toString("utf8")] });
    Object.assign(attribute, { buffers: [bytes] });
    const converted = new SearchEntry({ messageId: 1, name: "cn=synthetic", attributes: [attribute] }).toObject([attributeBaseName(type)], [attributeBaseName(type)]);
    assert.ok(Buffer.isBuffer(converted[type]));
    assert.deepEqual(converted[type], bytes);
  }
});
test("known binary attributes stay base64 across server casing, options, and ldapts string decoding", () => {
  const bytes = Buffer.from([1, 0, 2, 0]);
  const mapped = mapAttributes({ OBJECTSID: bytes.toString("utf8"), "TOKENGROUPS;range=0-*": bytes, DESCRIPTION: Buffer.from("safe"), SAMACCOUNTNAME: "alice", whenCreated: "20260101000000Z", SUPPORTEDCAPABILITIES: "1.2.840.113556.1.4.800", NAMINGCONTEXTS: "dc=example,dc=test" }, ["description", "sAMAccountName"]);
  assert.deepEqual(mapped.objectSid, [bytes.toString("base64")]);
  assert.deepEqual(mapped.objectSid_raw, [bytes.toString("base64")]);
  assert.deepEqual(mapped["tokenGroups;range=0-*"], [bytes.toString("base64")]);
  assert.deepEqual(mapped["tokenGroups;range=0-*_raw"], [bytes.toString("base64")]);
  assert.deepEqual(mapped.description, ["safe"]);
  assert.deepEqual(mapped.sAMAccountName, ["alice"]);
  assert.deepEqual(mapped.whenCreated, ["20260101000000Z"]);
  assert.deepEqual(mapped.supportedCapabilities, ["1.2.840.113556.1.4.800"]);
  assert.deepEqual(mapped.namingContexts, ["dc=example,dc=test"]);
});
test("ranged attributes suppress ldapts synthetic empty bare values", () => {
  const mapped = mapAttributes({ member: [], "member;range=0-1": ["cn=a,dc=example,dc=test", "cn=b,dc=example,dc=test"] }, ["member"]);
  assert.equal(mapped.member, undefined);
  assert.deepEqual(mapped["member;range=0-1"], ["cn=a,dc=example,dc=test", "cn=b,dc=example,dc=test"]);
});
test("absent requested attributes from ldapts are omitted while empty strings are retained", () => {
  const converted = new SearchEntry({ messageId: 1, name: "dc=example,dc=test", attributes: [new Attribute({ type: "description", values: [""] })] }).toObject(["cn", "uid", "description"], []);
  assert.deepEqual(mapAttributes(converted, ["cn", "uid", "description"]), { dn: ["dc=example,dc=test"], description: [""] });
});
test("LDAPS refuses StartTLS before opening a connection", async () => {
  await assert.rejects(() => openDirectory({ url: "ldaps://127.0.0.1:1", startTls: true, caOnly: false, tlsNoVerify: false, insecurePlaintext: false, anonymous: true, timeoutMs: 100 }), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR" && /start-tls/.test(error.message));
});
test("unreadable CA files produce an actionable validation error", async () => {
  for (const caFile of ["test/nonexistent-ca.pem", "test"]) {
    await assert.rejects(() => openDirectory({ url: "ldaps://127.0.0.1:1", startTls: false, caFile, caOnly: false, tlsNoVerify: false, insecurePlaintext: false, anonymous: true }), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR" && /--ca-file could not be read/.test(error.message));
  }
});
test("a result-code referral becomes an incomplete search page without being chased", () => {
  const uri = "ldap://child.example.test/DC=child,DC=example,DC=test";
  assert.deepEqual(searchFailurePage({ code: 10, referrals: [uri] }), { entries: [], referrals: [uri], stopReason: "referral" });
  assert.deepEqual(searchFailurePage(new UnknownStatusCodeError(10)), { entries: [], referrals: [], stopReason: "referral" });
});
test("configured page sizes use the same bounded range as CLI page sizes", () => {
  assert.equal(validatePageSize(1000), 1000);
  assert.throws(() => validatePageSize(1001), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR");
});
test("real ldapts result-code errors translate to the design taxonomy", () => {
  assert.equal(limitStopReason(new SizeLimitExceededError()), "server_size_limit");
  assert.equal(limitStopReason(new TimeLimitExceededError()), "server_time_limit");
  assert.equal(limitStopReason(new AdminLimitExceededError()), "server_admin_limit");
  assert.equal(limitStopReason(new NoSuchObjectError()), undefined);
  const translated = translateLdapError(new NoSuchObjectError());
  assert.ok(translated instanceof CliError && translated.code === "NOT_FOUND");
  assert.match(translated.help[0], /hidden by access control.*--anonymous.*authenticated bind/);
  const passthrough = new Error("boom");
  const unknown = translateLdapError(passthrough);
  assert.ok(unknown instanceof CliError && unknown.code === "UNKNOWN");
});
class PagedDirectory implements Directory {
  readonly flavor = "ldapv3" as const;
  constructor(private readonly pages: readonly SearchPage[]) {}
  async rootDSE(): Promise<RootDse> { return { flavor: this.flavor, attributes: {} }; }
  async *searchPages(): AsyncIterable<SearchPage> { for (const page of this.pages) yield page; }
  async whoami(): Promise<string | undefined> { return undefined; }
  async close(): Promise<void> {}
}
test("an exact max-rows boundary checks whether another page exists", async () => {
  const first = { dn: "cn=a,dc=example,dc=test", attributes: { cn: ["a"] } };
  const second = { dn: "cn=b,dc=example,dc=test", attributes: { cn: ["b"] } };
  const request = { base: "dc=example,dc=test", filter: "(objectClass=*)", scope: "sub" as const, attributes: ["cn"], pageSize: 1, maxRows: 1, all: true };
  const complete = await searchEntries(new PagedDirectory([{ entries: [first] }]), request);
  assert.equal(complete.data.count, "1 of 1 total");
  const partial = await searchEntries(new PagedDirectory([{ entries: [first] }, { entries: [second] }]), request);
  assert.equal(partial.data.count, "1 of unknown total");
  assert.equal(partial.data.stop_reason, "max_rows");
  assert.match(partial.help[0], /higher --max-rows/);
  assert.doesNotMatch(partial.help[0], /--all/);
});
test("a server limit with no entries retained is a SERVER_LIMIT error", async () => {
  await assert.rejects(() => searchEntries(new LimitDirectory({ entries: [], stopReason: "server_size_limit" }), { base: "dc=example,dc=test", filter: "(objectClass=*)", scope: "sub", attributes: ["cn"], pageSize: 500, all: true }), (error: unknown) => error instanceof CliError && error.code === "SERVER_LIMIT");
});
test("a server limit with entries retained is a bounded partial result", async () => {
  const result = await searchEntries(new LimitDirectory({ entries: [{ dn: "cn=a,dc=example,dc=test", attributes: { cn: ["a"] } }], stopReason: "server_size_limit" }), { base: "dc=example,dc=test", filter: "(objectClass=*)", scope: "sub", attributes: ["cn"], pageSize: 500, all: true });
  assert.equal(result.data.partial, true);
  assert.equal(result.data.stop_reason, "server_size_limit");
  assert.match(result.help[0], /server limit/);
  assert.doesNotMatch(result.help[0], /--all/);
});
test("entry show on a zero-match base is NOT_FOUND, not a stringified sentinel", async () => {
  await assert.rejects(() => showEntry(new LimitDirectory({ entries: [], referrals: [] }), "cn=missing,dc=example,dc=test", 500), (error: unknown) => error instanceof CliError && error.code === "NOT_FOUND");
});
test("entry show rejects referral-incomplete base reads", async () => {
  const uri = "ldap://child.example.test/DC=child,DC=example,DC=test";
  const entry = { dn: "cn=synthetic,dc=example,dc=test", attributes: { cn: ["synthetic"] } };
  for (const entries of [[], [entry]]) {
    await assert.rejects(() => showEntry(new LimitDirectory({ entries, referrals: [uri] }), entry.dn, 500), (error: unknown) => error instanceof CliError && error.code === "SERVER_LIMIT" && /referral/.test(error.message));
  }
});
test("denylisted password attributes are rejected before a search", async () => { const directory = new RecordedDirectory(); await assert.rejects(() => searchEntries(directory, { base: "dc=example,dc=test", filter: "(objectClass=*)", scope: "sub", attributes: ["userPassword;binary"], pageSize: 500, all: true }), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR"); assert.equal(directory.requests.length, 0); });
test("password attributes returned unexpectedly are never emitted", async () => {
  const entry = { dn: "cn=synthetic,dc=example,dc=test", attributes: { cn: ["synthetic"], userPassword: ["synthetic-hash"], "2.5.4.35;binary": ["synthetic-hash"] } };
  const result = await searchEntries(new LimitDirectory({ entries: [entry] }), { base: "dc=example,dc=test", filter: "(objectClass=*)", scope: "sub", attributes: ["cn"], pageSize: 500, all: true });
  assert.deepEqual((result.data.entries as unknown[])[0], { dn: entry.dn, cn: "synthetic" });
});
test("entry show requests only explicit safe attributes", async () => {
  const directory = new RecordedDirectory();
  await showEntry(directory, "cn=synthetic,dc=example,dc=test", 500, ["description"]);
  assert.deepEqual(directory.requests[0].attributes, ["description"]);
});
