import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

// The drift check for everything the synthetic fixtures assert about Active Directory
// (docs/design/v1.md §18.4). It runs only against the ephemeral Samba AD DC that
// scripts/local-directory.sh provisions, never against a real directory (§19.1), and stays outside
// npm run verify: every case is skipped unless that script set LDAP_AXI_LOCAL_DIRECTORY.
const enabled = process.env.LDAP_AXI_LOCAL_DIRECTORY === "1";
const skip = enabled ? false : "requires the containerized directory: npm run test:local-directory";
const cli = fileURLToPath(new URL("../../src/cli.js", import.meta.url));
const caFile = process.env.LDAP_AXI_LOCAL_DIRECTORY_CA ?? "";
const base = process.env.LDAP_AXI_LOCAL_DIRECTORY_BASE ?? "";
const users = `CN=Users,${base}`;

function run(args: readonly string[]): { stdout: string; stderr: string; status: number | null } {
  // --auth simple is explicit: the container holds a Kerberos ticket, so `auto` would select
  // GSSAPI for every one of these reads.
  const result = spawnSync(process.execPath, [cli, ...args, "--auth", "simple", "--ca-file", caFile], { encoding: "utf8" });
  return { stdout: result.stdout, stderr: result.stderr, status: result.status };
}

test("a real Active Directory server is detected and paged reads decode", { skip }, () => {
  const result = run(["user", "list", "--base", users, "--limit", "5"]);
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stdout, /sam: Administrator/);
  assert.match(result.stdout, /enabled: true/);
  assert.match(result.stdout, /tls_verified: true/);
});

test("real Active Directory binary and timestamp attributes decode to their canonical forms", { skip }, () => {
  const result = run(["user", "show", "Administrator", "--base", users]);
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  // The domain administrator is always RID 500, its objectGUID must render mixed-endian as a
  // canonical GUID, and an unset accountExpires must be the sentinel, never a year-30828 date.
  assert.match(result.stdout, /object_sid: S-1-5-21-\d+-\d+-\d+-500/);
  assert.match(result.stdout, /object_guid: [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/);
  assert.match(result.stdout, /account_expires: never/);
  assert.match(result.stdout, /user_account_control_flags\[1\]: NORMAL_ACCOUNT/);
});

test("tokenGroups membership resolves against a real directory", { skip }, () => {
  const result = run(["user", "groups", `CN=Administrator,${users}`, "--base", base]);
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stdout, /method: tokenGroups/);
  assert.match(result.stdout, /Administrators,"CN=Administrators,CN=Builtin,/);
});

test("subordinate referrals from a real naming context are reported, never chased", { skip }, () => {
  // Active Directory answers a domain-root search with subordinate references for the
  // configuration and DNS partitions. §9.6 reports them and marks the result partial.
  const result = run(["user", "list", "--base", base, "--limit", "5"]);
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stdout, /stop_reason: referral/);
  assert.match(result.stdout, /CN=Configuration,/);
});

test("an identifier resolves at the domain root despite those references", { skip }, () => {
  // The same domain-root search that reports stop_reason: referral above is what `user show`
  // issues for a bare identifier. §5.5 rule 4 counts only the entries this server returned, so
  // the reference must not turn a unique match into SERVER_LIMIT.
  const result = run(["user", "show", "Administrator", "--base", base]);
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stdout, /object_sid: S-1-5-21-\d+-\d+-\d+-500/);
});

test("GSSAPI completes its RFC 4752 exchange and selects no security layer under TLS", { skip }, () => {
  // Under D1 option C (§10.7) a verified-TLS GSSAPI bind negotiates *no* SASL security layer:
  // the client establishes a real Kerberos context, the server offers all three RFC 4752 layers,
  // and the client wraps the no-layer selection (integrity false). A production Active Directory
  // DC answers that round-3 BindRequest with success (the project's private operations record),
  // but Samba 4.19.5 answers strongerAuthRequired (result 8) and does not authenticate. The
  // assertion pins that Samba-specific boundary: the exchange runs to round 3, no layer is
  // selected, and the client surfaces STRONGER_AUTH_REQUIRED. Whether Samba should accept the
  // no-layer bind is a directory behavior, not a test-infrastructure one.
  const environment: NodeJS.ProcessEnv = { ...process.env, LDAP_AXI_GSSAPI_TRACE: "1" };
  delete environment.LDAP_AXI_BIND_DN;
  delete environment.LDAP_AXI_BIND_PASSWORD;
  const result = spawnSync(process.execPath, [cli, "entry", "search", "--scope", "base", "--base", "", "--auth", "gssapi", "--ca-file", caFile], { encoding: "utf8", env: environment });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /"layerMask":7/);
  assert.match(result.stderr, /"event":"gssapi-rfc4752-selection-wrap-result"/);
  assert.match(result.stderr, /"integrityRequired":false/);
  assert.match(result.stderr, /"resultCode":8/);
  assert.match(result.stdout, /STRONGER_AUTH_REQUIRED/);
});
