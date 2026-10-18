import assert from "node:assert/strict";
import test from "node:test";
import { parse, run } from "../../src/cli.js";
import { pageSizeForFlavor, resolveSettings } from "../../src/config.js";
import { CliError } from "../../src/core.js";

const rejects = (argv: string[], match: (error: CliError) => boolean = () => true) =>
  assert.throws(() => parse(argv), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR" && match(error));

test("an unknown top-level command exits 2 without connecting", async () => {
  const result = await run(["bogus"], { openDirectory: async () => assert.fail("invalid input must not connect") });
  assert.equal(result.exitCode, 2);
  assert.match(result.stdout, /unknown command bogus/);
});

for (const [group, subcommands] of [
  ["entry", ["search", "show"]], ["user", ["list", "show", "groups"]],
  ["group", ["list", "show", "members"]], ["auth", ["status"]],
  ["profile", ["list"]], ["config", ["path"]],
] as const) {
  test(`${group} help lists its subcommands without connecting`, async () => {
    const result = await run([group, "--help"], { openDirectory: async () => assert.fail("help must not connect") });
    assert.equal(result.exitCode, 0);
    assert.equal(result.stderr, "");
    for (const subcommand of subcommands) assert.ok(result.stdout.includes(`ldap-axi ${group} ${subcommand} --help`));
  });
  test(`${group} rejects unknown subcommands without connecting`, async () => {
    const result = await run([group, "bogus"], { openDirectory: async () => assert.fail("invalid input must not connect") });
    assert.equal(result.exitCode, 2);
    assert.match(result.stdout, /VALIDATION_ERROR/);
  });
  test(`${group} help still rejects unknown flags without connecting`, async () => {
    const result = await run([group, "--help", "--bogus"], { openDirectory: async () => assert.fail("invalid input must not connect") });
    assert.equal(result.exitCode, 2);
    assert.match(result.stdout, /unknown flag --bogus/);
  });
  for (const subcommand of subcommands) {
    test(`${group} ${subcommand} help succeeds without arguments or a connection`, async () => {
      const result = await run([group, subcommand, "--help"], { openDirectory: async () => assert.fail("help must not connect") });
      assert.equal(result.exitCode, 0);
      assert.ok(result.stdout.includes(`${group} ${subcommand}`));
    });
    test(`${group} ${subcommand} rejects unknown flags before connecting`, async () => {
      const result = await run([group, subcommand, "--bogus"], { openDirectory: async () => assert.fail("invalid input must not connect") });
      assert.equal(result.exitCode, 2);
      assert.match(result.stdout, /unknown flag --bogus/);
      assert.match(result.stdout, /valid flags/);
    });
  }
}

for (const [command, localFlags] of [
  ["entry search", ["filter", "scope", "attributes", "page-size", "max-rows", "all"]],
  ["auth status", ["offline"]],
] as const) {
  test(`${command} help lists every accepted flag exactly once`, async () => {
    const result = await run([...command.split(" "), "--help"]);
    const invalid = await run([...command.split(" "), "--bogus"]);
    const advertised = [...result.stdout.matchAll(/^  --([\w-]+)  \S.+$/gm)].map(match => match[1]);
    const accepted = [...invalid.stdout.matchAll(/--([\w-]+)/g)].map(match => match[1]).filter(name => name !== "bogus");
    assert.deepEqual(advertised.toSorted(), [...new Set(accepted)].toSorted());
    assert.equal(advertised.length, new Set(advertised).size);
    for (const flag of localFlags) assert.ok(advertised.includes(flag));
    assert.match(result.stdout, /default: auto/);
    assert.match(result.stdout, /Examples:\n  ldap-axi /);
  });
}

test("entry search help explains search and paging defaults", async () => {
  const result = await run(["entry", "search", "--help"]);
  assert.match(result.stdout, /default: \(objectClass=\*\)/);
  assert.match(result.stdout, /default: sub/);
  assert.match(result.stdout, /default: objectClass,cn/);
  assert.match(result.stdout, /AD 1000, LDAPv3 500/);
  assert.match(result.stdout, /default: one page/);
});

for (const command of ["user list", "user show", "user groups", "group list", "group show", "group members"]) {
  test(`${command} help provides two useful parseable examples`, async () => {
    const result = await run([...command.split(" "), "--help"]);
    const examples = result.stdout.split("Examples:\n")[1].trim().split("\n");
    assert.equal(examples.length, 2);
    for (const example of examples) {
      assert.doesNotMatch(example, /\s(?:--help|example)(?:\s|$)/);
      assert.doesNotThrow(() => parse(example.trim().split(" ").slice(1)));
    }
  });
}

test("user and group subcommands route to their command and consume the identifier positional", () => {
  assert.equal(parse(["user", "list", "--disabled"]).command, "user list");
  assert.equal(parse(["user", "show", "jdoe"]).positionals[0], "jdoe");
  assert.equal(parse(["user", "groups", "jdoe", "--nested"]).flags.nested, true);
  assert.equal(parse(["group", "list"]).command, "group list");
  assert.equal(parse(["group", "show", "CN=x,DC=y"]).command, "group show");
  assert.equal(parse(["group", "members", "CN=x,DC=y", "--nested"]).flags.nested, true);
});
test("an unknown user or group subcommand is rejected before any flag is parsed", () => {
  rejects(["user", "bogus"]);
  rejects(["group", "bogus"]);
});
test("identifier commands require exactly one positional", () => {
  rejects(["user", "show"]);
  rejects(["user", "show", "a", "b"]);
  rejects(["group", "members"]);
});
test("list commands accept no positional arguments", () => {
  rejects(["user", "list", "jdoe"]);
  rejects(["group", "list", "x"]);
});
test("an unrecognized flag is rejected by name, with the subcommand's valid flags inlined", () => {
  assert.throws(() => parse(["user", "list", "--bogus"]), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR" && /unknown flag --bogus for `user list`/.test(error.message) && /valid flags for `user list`/.test(error.help.join(" ")));
});
test("value flags accept both --name value and --name=value forms", () => {
  const spaced = parse(["user", "list", "--sam", "jdoe"]);
  assert.equal(spaced.flags.sam, "jdoe");
  const inline = parse(["user", "list", "--sam=jdoe", "--fields=sam,name"]);
  assert.equal(inline.flags.sam, "jdoe");
  assert.equal(inline.flags.fields, "sam,name");
});
test("--all requires --max-rows or --limit on every list-shaped command", () => {
  rejects(["user", "list", "--all"]);
  rejects(["group", "list", "--all"]);
  assert.equal(parse(["user", "list", "--all", "--max-rows", "5"]).flags.all, true);
  assert.equal(parse(["group", "list", "--all", "--limit", "5"]).flags.all, true);
});
test("--scope, --filter, and --fields validate before command execution", () => {
  rejects(["user", "list", "--scope", "everywhere"]);
  rejects(["group", "list", "--filter", "(("]);
  rejects(["user", "list", "--fields", "typo"], error => /unknown field/.test(error.message));
  assert.equal(parse(["user", "list", "--fields", "object_sid"]).flags.fields, "object_sid");
});
test("a denylisted attribute in --attributes is rejected for the new commands too", () => {
  rejects(["user", "show", "jdoe", "--attributes", "unicodePwd"]);
  rejects(["group", "show", "CN=x,DC=y", "--attributes", "userPassword"]);
});
test("TLS maximum version accepts only the explicit TLS 1.2 cap before connection", () => {
  assert.equal(parse(["entry", "search", "--tls-max-version", "1.2"]).flags["tls-max-version"], "1.2");
  rejects(["entry", "search", "--tls-max-version", "1.3"]);
  rejects(["entry", "search", "--tls-max-version", "TLSv1.2"]);
});
test("TLS maximum version resolves from config-shaped settings", async () => {
  const previousConfig = process.env.LDAP_AXI_CONFIG;
  const previousCredentials = process.env.LDAP_AXI_CREDENTIALS_FILE;
  const previousTlsMaxVersion = process.env.LDAP_AXI_TLS_MAX_VERSION;
  process.env.LDAP_AXI_CONFIG = `${process.cwd()}/test/nonexistent-config.json`;
  process.env.LDAP_AXI_CREDENTIALS_FILE = `${process.cwd()}/test/nonexistent-credentials.env`;
  delete process.env.LDAP_AXI_TLS_MAX_VERSION;
  try {
    assert.equal((await resolveSettings({ url: "ldaps://directory.example.test", tlsMaxVersion: "1.2" })).tlsMaxVersion, "1.2");
  } finally {
    if (previousConfig === undefined) delete process.env.LDAP_AXI_CONFIG; else process.env.LDAP_AXI_CONFIG = previousConfig;
    if (previousCredentials === undefined) delete process.env.LDAP_AXI_CREDENTIALS_FILE; else process.env.LDAP_AXI_CREDENTIALS_FILE = previousCredentials;
    if (previousTlsMaxVersion === undefined) delete process.env.LDAP_AXI_TLS_MAX_VERSION; else process.env.LDAP_AXI_TLS_MAX_VERSION = previousTlsMaxVersion;
  }
});
test("auth flags parse as global settings and invalid modes fail before connection", () => {
  assert.equal(parse(["entry", "search", "--auth", "simple"]).flags.auth, "simple");
  assert.equal(parse(["entry", "search", "--gssapi-service=ldap/directory.example.test"]).flags["gssapi-service"], "ldap/directory.example.test");
  assert.equal(parse(["entry", "search", "--gssapi-protection", "confidentiality"]).flags["gssapi-protection"], "confidentiality");
  assert.equal(parse(["entry", "search", "--gssapi-protection", "none"]).flags["gssapi-protection"], "none");
  rejects(["entry", "search", "--auth", "kerberos"]);
  rejects(["entry", "search", "--gssapi-protection", "integrity"]);
  rejects(["entry", "search", "--anonymous", "--auth", "simple"]);
  rejects(["entry", "search", "--anonymous", "--gssapi-service", "ldap/directory.example.test"]);
  rejects(["entry", "search", "--anonymous", "--gssapi-protection", "confidentiality"]);
});
test("--nested and other boolean flags never require a value", () => {
  assert.equal(parse(["user", "groups", "jdoe", "--nested"]).flags.nested, true);
  assert.equal(parse(["group", "list", "--all", "--limit", "1"]).positionals.length, 0);
});
test("contradictory account-state filters are rejected before connection", () => {
  rejects(["user", "list", "--disabled", "--enabled"]);
});
test("paging defaults by detected flavor unless configured", () => {
  assert.equal(pageSizeForFlavor(undefined, "ad"), 1000);
  assert.equal(pageSizeForFlavor(undefined, "adlds"), 1000);
  assert.equal(pageSizeForFlavor(undefined, "ldapv3"), 500);
  assert.equal(pageSizeForFlavor(25, "ad"), 25);
});
test("command help describes flags, flavor fields, and flavor defaults without duplicates", async () => {
  const result = await run(["user", "list", "--help"]);
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /--page-size  <1\.\.1000> LDAP page size/);
  assert.match(result.stdout, /--tls-max-version  <1\.2> cap verified TLS to TLS 1\.2/);
  assert.match(result.stdout, /--all  read all pages up to --max-rows or --limit/);
  assert.match(result.stdout, /Active Directory fields:.*object_sid/);
  assert.match(result.stdout, /LDAPv3 fields:.*entry_uuid/);
  assert.match(result.stdout, /Active Directory defaults: sam, name, enabled, last_logon/);
  assert.match(result.stdout, /LDAPv3 defaults: uid, name, mail/);
  assert.equal(result.stdout.match(/^  --all  /gm)?.length, 1);
});
test("a blocked plaintext request does not claim traffic was sent", async () => {
  const result = await run(["entry", "search", "--url", "ldap://127.0.0.1:1", "--base", "dc=example,dc=test", "--anonymous"]);
  assert.notEqual(result.exitCode, 0);
  assert.equal(result.stderr, "");
});
test("URL userinfo is rejected before transport warnings are emitted", async () => {
  const result = await run(["entry", "search", "--url", "ldap://bind-dn:password@127.0.0.1:1", "--base", "dc=example,dc=test", "--anonymous", "--insecure-plaintext"]);
  assert.notEqual(result.exitCode, 0);
  assert.equal(result.stderr, "");
  assert.doesNotMatch(result.stdout, /bind-dn|password/);
});
test("a plaintext warning survives connection failure", async () => {
  const previousConfig = process.env.LDAP_AXI_CONFIG;
  const previousCredentials = process.env.LDAP_AXI_CREDENTIALS_FILE;
  const previousDn = process.env.LDAP_AXI_BIND_DN;
  const previousPassword = process.env.LDAP_AXI_BIND_PASSWORD;
  process.env.LDAP_AXI_CONFIG = `${process.cwd()}/test/nonexistent-config.json`;
  process.env.LDAP_AXI_CREDENTIALS_FILE = `${process.cwd()}/test/nonexistent-credentials.env`;
  delete process.env.LDAP_AXI_BIND_DN;
  delete process.env.LDAP_AXI_BIND_PASSWORD;
  try {
    const result = await run(["entry", "search", "--url", "ldap://127.0.0.1:1", "--base", "dc=example,dc=test", "--anonymous", "--insecure-plaintext"]);
    assert.notEqual(result.exitCode, 0);
    assert.equal(result.stderr, "warning: bind credentials and queries are sent in cleartext over plaintext LDAP\n");
  } finally {
    if (previousConfig === undefined) delete process.env.LDAP_AXI_CONFIG; else process.env.LDAP_AXI_CONFIG = previousConfig;
    if (previousCredentials === undefined) delete process.env.LDAP_AXI_CREDENTIALS_FILE; else process.env.LDAP_AXI_CREDENTIALS_FILE = previousCredentials;
    if (previousDn === undefined) delete process.env.LDAP_AXI_BIND_DN; else process.env.LDAP_AXI_BIND_DN = previousDn;
    if (previousPassword === undefined) delete process.env.LDAP_AXI_BIND_PASSWORD; else process.env.LDAP_AXI_BIND_PASSWORD = previousPassword;
  }
});
test("the URL scheme selects the GSSAPI transport rather than refusing plaintext", async () => {
  const sealed = await run(["entry", "search", "--url", "ldap://127.0.0.1:1", "--base", "dc=example,dc=test", "--auth", "gssapi", "--gssapi-service", "ldap@directory.example.test", "--gssapi-protection", "confidentiality"]);
  assert.notEqual(sealed.exitCode, 0);
  assert.doesNotMatch(sealed.stdout, /TLS_REQUIRED/);
  const mismatch = await run(["entry", "search", "--url", "ldap://127.0.0.1:1", "--base", "dc=example,dc=test", "--auth", "gssapi", "--gssapi-service", "ldap@directory.example.test", "--gssapi-protection", "none"]);
  assert.equal(mismatch.exitCode, 2);
  assert.match(mismatch.stdout, /VALIDATION_ERROR/);
});
test("the home command rejects configured URL credentials without rendering them", async () => {
  const previousUrl = process.env.LDAP_AXI_URL;
  const previousConfig = process.env.LDAP_AXI_CONFIG;
  const previousCredentials = process.env.LDAP_AXI_CREDENTIALS_FILE;
  process.env.LDAP_AXI_URL = "ldaps://bind-dn:password@example.test";
  process.env.LDAP_AXI_CONFIG = `${process.cwd()}/test/nonexistent-config.json`;
  process.env.LDAP_AXI_CREDENTIALS_FILE = `${process.cwd()}/test/nonexistent-credentials.env`;
  try {
    const result = await run([]);
    assert.notEqual(result.exitCode, 0);
    assert.equal(result.stderr, "");
    assert.doesNotMatch(result.stdout, /bind-dn|password/);
  } finally {
    if (previousUrl === undefined) delete process.env.LDAP_AXI_URL; else process.env.LDAP_AXI_URL = previousUrl;
    if (previousConfig === undefined) delete process.env.LDAP_AXI_CONFIG; else process.env.LDAP_AXI_CONFIG = previousConfig;
    if (previousCredentials === undefined) delete process.env.LDAP_AXI_CREDENTIALS_FILE; else process.env.LDAP_AXI_CREDENTIALS_FILE = previousCredentials;
  }
});
test("the home command and existing entry commands are unaffected", () => {
  assert.equal(parse([]).command, "home");
  assert.equal(parse(["entry", "search", "--filter", "(objectClass=*)"]).command, "entry search");
});
