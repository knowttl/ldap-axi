import assert from "node:assert/strict";
import test from "node:test";
import { CliError } from "../../src/core.js";
import { translateLdapError, adBindSubCode } from "../../src/directory/errors.js";
import { resolveIdentity } from "../../src/directory/identity.js";
import { showEntry } from "../../src/entry.js";
import { BASE, RecordedDirectory } from "../support/fixtures.js";

function bindFailure(dataCode: string): Error {
  const error = new Error(`80090308: LdapErr: DSID-0C09030B, comment: AcceptSecurityContext error, data ${dataCode}, v1db1`);
  (error as unknown as { code: number }).code = 49;
  return error;
}
function resultCodeError(code: number, message = ""): Error {
  const error = new Error(message);
  (error as unknown as { code: number }).code = code;
  return error;
}

test("zero-visible entry and identity lookups include ACL and anonymous-bind guidance", async () => {
  const directory = new RecordedDirectory("ldapv3", []);
  const dn = `cn=missing,${BASE}`;
  for (const noun of ["user", "group"]) {
    for (const identifier of [dn, "missing"]) {
      await assert.rejects(() => resolveIdentity(directory, identifier, BASE, { noun, shapeFilter: "(objectClass=*)", searchFilter: "(cn=missing)" }, ["cn"], 500), (error: unknown) => {
        assert.ok(error instanceof CliError);
        assert.equal(error.code, "NOT_FOUND");
        assert.match(error.help.join(" "), /hidden by access control.*--anonymous.*authenticated bind/);
        assert.match(error.help[0], /shape|distinguished name/);
        return true;
      });
    }
  }
  await assert.rejects(() => showEntry(directory, dn, 500), (error: unknown) => {
    assert.ok(error instanceof CliError);
    assert.equal(error.code, "NOT_FOUND");
    assert.match(error.help.join(" "), /hidden by access control.*--anonymous.*authenticated bind/);
    return true;
  });
  const serverError = translateLdapError(resultCodeError(32)) as CliError;
  assert.match(serverError.help.join(" "), /hidden by access control.*--anonymous.*authenticated bind/);
  assert.equal(serverError.help.length, 1);
});

test("AD bind sub-codes translate to their distinct, non-retryable codes", () => {
  const cases: ReadonlyArray<readonly [string, string]> = [["52e", "AUTH_FAILED"], ["532", "PASSWORD_EXPIRED"], ["533", "ACCOUNT_DISABLED"], ["701", "ACCOUNT_EXPIRED"], ["773", "PASSWORD_EXPIRED"], ["775", "ACCOUNT_LOCKED"]];
  for (const [dataCode, code] of cases) {
    const translated = translateLdapError(bindFailure(dataCode));
    assert.ok(translated instanceof CliError && translated.code === code, `${dataCode} -> ${code}`);
  }
});
test("an unrecognized AD sub-code degrades to AUTH_FAILED and reports the raw token", () => {
  const translated = translateLdapError(bindFailure("9ff"));
  assert.ok(translated instanceof CliError && translated.code === "AUTH_FAILED");
  assert.match(translated.message, /9ff/);
});
test("a bind failure with no AD sub-code is still AUTH_FAILED, never a retry suggestion", () => {
  const error = new Error("invalid credentials");
  (error as unknown as { code: number }).code = 49;
  const translated = translateLdapError(error);
  assert.ok(translated instanceof CliError && translated.code === "AUTH_FAILED");
  assert.equal(translated.help.some(line => /retry/i.test(line)), false);
});
test("adBindSubCode extracts the hex data token case-insensitively", () => {
  assert.equal(adBindSubCode("data 52E, v1db1"), "52e");
  assert.equal(adBindSubCode("no data token here"), undefined);
});
test("server-limit result codes translate to SERVER_LIMIT outside a page walk", () => {
  for (const code of [3, 4, 11]) assert.ok((translateLdapError(resultCodeError(code)) as CliError).code === "SERVER_LIMIT");
});
test("stronger-auth, unsupported, not-found, invalid-dn, insufficient-access, and busy codes translate distinctly", () => {
  for (const [code, expected] of [[1, "OPERATIONS_ERROR"], [2, "PROTOCOL_ERROR"]] as const) assert.equal(translateLdapError(resultCodeError(code)).code, expected);
  assert.equal((translateLdapError(resultCodeError(8)) as CliError).code, "STRONGER_AUTH_REQUIRED");
  assert.equal((translateLdapError(resultCodeError(13)) as CliError).code, "STRONGER_AUTH_REQUIRED");
  assert.equal((translateLdapError(resultCodeError(12)) as CliError).code, "UNSUPPORTED_BY_SERVER");
  assert.equal((translateLdapError(resultCodeError(32)) as CliError).code, "NOT_FOUND");
  assert.equal((translateLdapError(resultCodeError(34)) as CliError).code, "INVALID_DN");
  assert.equal((translateLdapError(resultCodeError(50)) as CliError).code, "INSUFFICIENT_ACCESS");
  assert.equal((translateLdapError(resultCodeError(51)) as CliError).code, "SERVER_BUSY");
  assert.equal((translateLdapError(resultCodeError(52)) as CliError).code, "SERVER_BUSY");
});
test("operations errors retain the numeric code and explain scope remedies", () => {
  const translated = translateLdapError(resultCodeError(1));
  assert.match(translated.message, /LDAP result code 1/);
  assert.doesNotMatch(translated.message, /unrecognized/);
  assert.match(translated.help.join(" "), /naming context.*base-scope read.*entry's DN/);
});
test("an unmapped result code is UNKNOWN and reports the number, never a raw library error", () => {
  const translated = translateLdapError(resultCodeError(999, "some obscure diagnostic")) as CliError;
  assert.equal(translated.code, "UNKNOWN");
  assert.match(translated.message, /999/);
  assert.doesNotMatch(translated.message, /obscure diagnostic/);
});
test("a connection-level failure classifies TLS, timeout, and unreachable distinctly", () => {
  assert.equal((translateLdapError(new Error("self signed certificate in certificate chain")) as CliError).code, "TLS_UNTRUSTED");
  assert.equal((translateLdapError(new Error("connect ETIMEDOUT 10.0.0.1:636")) as CliError).code, "OPERATION_TIMEOUT");
  assert.equal((translateLdapError(new Error("Connection timeout")) as CliError).code, "OPERATION_TIMEOUT");
  assert.equal((translateLdapError(new Error("connect ECONNREFUSED 10.0.0.1:636")) as CliError).code, "SERVER_UNREACHABLE");
});
test("a CliError passed in is returned unchanged, never re-wrapped", () => {
  const original = new CliError("VALIDATION_ERROR", "already translated");
  assert.equal(translateLdapError(original), original);
});
