import assert from "node:assert/strict";
import test from "node:test";
import { InvalidCredentialsError, ProtocolError, UnknownStatusCodeError } from "ldapts";
import { translateLdapError } from "../../src/directory/errors.js";
import { renderError } from "../../src/render.js";
import { listUsers, showUser, userGroups } from "../../src/user.js";
import { showGroup } from "../../src/group.js";
import { showComputer } from "../../src/computer.js";
import { BASE, byDn, byFilter, DOMAIN_SID, entry, RecordedDirectory, sidBase64 } from "../support/fixtures.js";

const PRIVATE_VALUE = "synthetic-private-value";
for (const [error, code, number, name] of [
  [new ProtocolError(PRIVATE_VALUE), "PROTOCOL_ERROR", 2, "ProtocolError"],
  [new InvalidCredentialsError(`data 775, ${PRIVATE_VALUE}`), "ACCOUNT_LOCKED", 49, "InvalidCredentialsError"],
  [new UnknownStatusCodeError(999, PRIVATE_VALUE), "UNKNOWN", 999, "UnknownStatusCodeError"],
] as const) {
  test(`rendered ${name} retains result metadata without server prose`, () => {
    error.name = PRIVATE_VALUE;
    const result = renderError(translateLdapError(error));
    assert.match(result.stdout, new RegExp(`code: ${code}`));
    assert.match(result.stdout, new RegExp(`LDAP result code ${number}`));
    assert.ok(result.stdout.includes(name));
    assert.ok(!result.stdout.includes(PRIVATE_VALUE));
    assert.equal(result.exitCode, 1);
    assert.equal(result.stderr, "");
  });
}

for (const [noun, show] of [["user", showUser], ["group", showGroup], ["computer", showComputer]] as const) {
  for (const [field, attribute] of [["object_sid", "objectSid"], ["object_guid", "objectGUID"], ["when_created", "whenCreated"], ["when_changed", "whenChanged"]]) {
    for (const [verb, command] of [["show", show]] as const) {
      test(`${noun} ${verb} identifies malformed ${attribute} without its value`, async () => {
        const record = entry(`cn=Synthetic,${BASE}`, { [attribute]: [PRIVATE_VALUE] });
        const directory = new RecordedDirectory("ad", [byFilter([], [record])]);
        await assert.rejects(() => command(directory, { base: BASE, flavor: "ad", identifier: "Synthetic", pageSize: 500, fields: [field] }), error => {
          const result = renderError(error);
          assert.match(result.stdout, /code: PROTOCOL_ERROR/);
          assert.ok(result.stdout.includes(attribute));
          assert.ok(!result.stdout.includes(PRIVATE_VALUE));
          assert.ok(!result.stdout.includes(record.dn));
          return true;
        });
      });
    }
  }
}

for (const [field, attribute, flavor] of [["last_logon", "lastLogonTimestamp", "ad"], ["password_last_set", "pwdLastSet", "ad"], ["account_expires", "accountExpires", "ad"], ["when_created", "createTimestamp", "ldapv3"], ["when_changed", "modifyTimestamp", "ldapv3"], ["account_state", "pwdAccountLockedTime", "ldapv3"]] as const) {
  test(`user show identifies malformed ${attribute}`, async () => {
    const directory = new RecordedDirectory(flavor, [byFilter([], [entry(`cn=Synthetic,${BASE}`, { [attribute]: [PRIVATE_VALUE] })])]);
    await assert.rejects(() => showUser(directory, { base: BASE, flavor, identifier: "Synthetic", pageSize: 500, fields: [field] }), error => {
      const result = renderError(error);
      assert.match(result.stdout, /code: PROTOCOL_ERROR/);
      assert.ok(result.stdout.includes(attribute));
      assert.ok(!result.stdout.includes(PRIVATE_VALUE));
      return true;
    });
  });
}

test("user list identifies a malformed default lastLogonTimestamp", async () => {
  const directory = new RecordedDirectory("ad", [byFilter([], [entry(`cn=Synthetic,${BASE}`, { lastLogonTimestamp: [PRIVATE_VALUE] })])]);
  await assert.rejects(() => listUsers(directory, { base: BASE, flavor: "ad", pageSize: 500, all: true, scope: "sub" }), error => {
    const result = renderError(error);
    assert.match(result.stdout, /code: PROTOCOL_ERROR/);
    assert.ok(result.stdout.includes("lastLogonTimestamp"));
    assert.ok(!result.stdout.includes(PRIVATE_VALUE));
    return true;
  });
});

for (const attribute of ["tokenGroups", "objectSid"]) {
  test(`user groups identifies malformed ${attribute}`, async () => {
    const record = entry(`cn=Synthetic,${BASE}`, { [attribute]: [PRIVATE_VALUE], primaryGroupID: ["513"] });
    const directory = new RecordedDirectory("ad", [byFilter([], [record])]);
    await assert.rejects(() => userGroups(directory, { base: BASE, flavor: "ad", identifier: "Synthetic", pageSize: 500 }), error => {
      const result = renderError(error);
      assert.match(result.stdout, /code: PROTOCOL_ERROR/);
      assert.ok(result.stdout.includes(attribute));
      assert.ok(!result.stdout.includes(PRIVATE_VALUE));
      return true;
    });
  });
}

for (const [method, attributes] of [
  ["tokenGroups", { tokenGroups: [sidBase64(`${DOMAIN_SID}-513`)] }],
  ["primaryGroupID", { objectSid: [sidBase64(`${DOMAIN_SID}-1104`)], primaryGroupID: ["513"] }],
] as const) {
  for (const [syntax, value] of [["malformed", PRIVATE_VALUE], ["empty", ""]]) {
    test(`user groups rejects ${syntax} resolved group objectSid through ${method}`, async () => {
      const user = entry(`cn=Synthetic,${BASE}`, attributes);
      const group = entry(`cn=SyntheticGroup,${BASE}`, { objectSid: [value] });
      const directory = new RecordedDirectory("ad", [byDn(user.dn, user), byFilter(["(objectSid="], [group])]);
      await assert.rejects(() => userGroups(directory, { base: BASE, flavor: "ad", identifier: user.dn, pageSize: 500 }), error => {
        const result = renderError(error);
        assert.match(result.stdout, /code: PROTOCOL_ERROR/);
        assert.ok(result.stdout.includes("objectSid"));
        assert.ok(!result.stdout.includes(PRIVATE_VALUE));
        assert.ok(!result.stdout.includes(user.dn));
        assert.ok(!result.stdout.includes(group.dn));
        assert.equal(result.exitCode, 1);
        assert.equal(result.stderr, "");
        return true;
      });
    });
  }
}
