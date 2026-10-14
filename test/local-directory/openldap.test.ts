import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const skip = process.env.LDAP_AXI_LOCAL_OPENLDAP === "1" ? false : "requires the opt-in OpenLDAP/MIT KDC mock";
const cli = fileURLToPath(new URL("../../src/cli.js", import.meta.url));
const base = "dc=ldapaxi,dc=test";
const ca = "/data/tls/ca.crt";
const transports = [
  { name: "LDAPS", args: ["--url", "ldaps://localhost:636", "--ca-file", ca], layer: "none", binding: "tls-server-end-point" },
  { name: "StartTLS", args: ["--url", "ldap://localhost:389", "--start-tls", "--ca-file", ca], layer: "none", binding: "tls-server-end-point" },
  { name: "plain", args: ["--url", "ldap://localhost:389"], layer: "confidentiality", binding: "none" },
] as const;

function run(args: readonly string[], transport: typeof transports[number], auth: "simple" | "ambient" = "simple") {
  const env: NodeJS.ProcessEnv = { ...process.env, LDAP_AXI_GSSAPI_TRACE: "1" };
  if (auth === "ambient") {
    delete env.LDAP_AXI_BIND_DN;
    delete env.LDAP_AXI_BIND_PASSWORD;
  }
  const flags = auth === "simple" ? ["--auth", "simple", ...(transport.name === "plain" ? ["--insecure-plaintext"] : [])] : [];
  const result = spawnSync(process.execPath, [cli, ...args, "--base", base, ...transport.args, ...flags], { encoding: "utf8", env, timeout: 30_000 });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}${result.error ?? ""}`);
  return result;
}

for (const transport of transports) {
  test(`OpenLDAP simple bind merges all generic group shapes over ${transport.name}`, { skip }, () => {
    const result = run(["user", "groups", "alice", "--fields", "name"], transport);
    assert.match(result.stdout, /method: memberOf\+reverse-search/);
    assert.match(result.stdout, /engineering/);
    assert.match(result.stdout, /developers/);
    assert.match(result.stdout, /auditors/);
    assert.match(result.stdout, /O'Brien, Pat team/);
    assert.match(result.stdout, /stop_reason: unique_member_uid_not_checked/);
  });

  test(`OpenLDAP ambient Kerberos binds and reads over ${transport.name}`, { skip }, () => {
    const status = run(["auth", "status"], transport, "ambient");
    assert.match(status.stdout, /connection: live/);
    assert.match(status.stdout, /mechanism: GSSAPI/);
    assert.match(status.stdout, /credentials: ambient/);
    assert.match(status.stdout, /flavor: ldapv3/);
    const boundAs = /^bound_as: (.+)$/m.exec(status.stdout);
    assert.ok(boundAs, status.stdout);
    assert.equal(JSON.parse(boundAs[1]), "dn:uid=alice,ou=people,dc=ldapaxi,dc=test");
    assert.match(status.stdout, new RegExp(`sasl_security_layer: ${transport.layer}`));
    assert.match(status.stdout, new RegExp(`channel_binding: ${transport.binding}`));
    // Multiple post-bind search requests must interoperate with the negotiated
    // layer. On plain LDAP the server cannot decode an unwrapped search PDU.
    const groups = run(["user", "groups", "alice", "--fields", "name"], transport, "ambient");
    assert.match(groups.stdout, /developers/);
    assert.match(groups.stdout, /engineering/);
    assert.match(groups.stdout, /auditors/);
    assert.doesNotMatch(groups.stderr, /cleartext/);
  });
}

test("OpenLDAP explicitly requested ppolicy attributes report the permanent lock", { skip }, () => {
  const result = run(["user", "show", "judy"], transports[0]);
  assert.match(result.stdout, /enabled: false/);
  assert.match(result.stdout, /locked: true/);
  assert.match(result.stdout, /pwd_account_locked_time: 000001010000Z/);
});

for (const [flag, expected, excluded] of [
  ["disabled", "judy", "alice"], ["enabled", "alice", "judy"], ["locked", "judy", "alice"],
] as const) {
  test(`OpenLDAP --${flag} filters through the real subschema`, { skip }, () => {
    const result = run(["user", "list", `--${flag}`, "--all", "--max-rows", "50", "--fields", "uid"], transports[0]);
    assert.match(result.stdout, new RegExp(`\\b${expected}\\b`));
    assert.doesNotMatch(result.stdout, new RegExp(`\\b${excluded}\\b`));
  });
}

test("OpenLDAP paging returns all users across real cookies", { skip }, () => {
  const result = run(["user", "list", "--all", "--max-rows", "50", "--page-size", "2", "--fields", "uid"], transports[0]);
  assert.match(result.stdout, /count: 4 of 4 total/);
  assert.doesNotMatch(result.stdout, /incomplete:/);
});

test("OpenLDAP preserves optional uniqueMember UIDs and unresolved POSIX references", { skip }, () => {
  const auditors = run(["group", "members", "auditors"], transports[0]);
  assert.match(auditors.stdout, /ivan/);
  const developers = run(["group", "members", "developers"], transports[0]);
  assert.match(developers.stdout, /ghost/);
  assert.match(developers.stdout, /unresolved/);
});
