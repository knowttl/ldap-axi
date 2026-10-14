import assert from "node:assert/strict";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { run } from "../../src/cli.js";
import { CliError } from "../../src/core.js";
import { RecordedDirectory, byDn, byFilter, entry } from "../support/fixtures.js";

const endpoint = "ldaps://directory.example.test";
const ambient = { url: endpoint };
const simple = { url: endpoint, auth: "simple", bindDn: "uid=synthetic", bindPassword: { env: "ARTIUM_SECRET_0" } };

async function withHome(body: (home: {
  root: string; config: string; env: NodeJS.ProcessEnv;
  save: (profiles: Record<string, unknown>, defaultProfile?: string) => Promise<void>;
  cli: (args?: string[], env?: NodeJS.ProcessEnv) => SpawnSyncReturns<string>;
}) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "ldap-axi-credentials-"));
  const directory = join(root, "config", "ldap-axi");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const config = join(directory, "config.json");
  const env: NodeJS.ProcessEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("LDAP_AXI_") && !["ARTIUM_SECRET_0", "NODE_EXTRA_CA_CERTS", "KRB5_CONFIG", "KRB5CCNAME"].includes(key)));
  Object.assign(env, { HOME: root, USERPROFILE: root, APPDATA: join(root, "config"), LOCALAPPDATA: join(root, "state"), XDG_CONFIG_HOME: join(root, "config"), XDG_STATE_HOME: join(root, "state"), TMPDIR: root });
  try {
    await body({ root, config, env,
      save: async (profiles, defaultProfile) => { await writeFile(config, JSON.stringify({ version: 1, defaultProfile, profiles }), { mode: 0o600 }); },
      cli: (args = ["auth", "status", "--offline"], extra = {}) => spawnSync(process.execPath, ["dist/src/cli.js", ...args], { env: { ...env, ...extra }, encoding: "utf8", timeout: 10_000 }),
    });
  } finally { await rm(root, { recursive: true, force: true }); }
}

test("artium's single profile and injected env SecretRef work with an isolated HOME", async () => {
  await withHome(async home => {
    await home.save({ artium: simple }, "artium");
    const result = home.cli(undefined, { ARTIUM_SECRET_0: "synthetic-artium-password" });
    assert.equal(result.status, 0, result.stdout);
    assert.match(result.stdout, /profile: artium/);
    assert.match(result.stdout, /bind_password_source: "env:ARTIUM_SECRET_0"/);
    assert.match(result.stdout, /mechanism: simple/);
    assert.match(result.stdout, /configured_bind_dn: uid=synthetic/);
    assert.doesNotMatch(result.stdout + result.stderr, /synthetic-artium-password/);
  });
});

for (const password of ["password", "source", '"', "line\nbreak"]) test(`offline auth preserves TOON structure with password ${JSON.stringify(password)}`, async () => {
  await withHome(async home => {
    await home.save({ artium: simple });
    const result = home.cli(undefined, { ARTIUM_SECRET_0: password });
    assert.equal(result.status, 0, result.stdout);
    assert.match(result.stdout, /^bind_password_source: "env:ARTIUM_SECRET_0"$/m);
    assert.match(result.stdout, /^mechanism: simple$/m);
  });
});

for (const password of ['synthetic/"\nsecret', "keep?sig=hide&tail"]) test(`error messages and help redact the complete secret ${JSON.stringify(password)}`, async () => {
  await withHome(async home => {
    const passwordFile = join(home.root, "password");
    await writeFile(passwordFile, password, { mode: 0o600 });
    await home.save({ work: { ...simple, bindPassword: { file: passwordFile } } });
    const result = await run(["entry", "search", "--config", home.config, "--base", "dc=example,dc=test"], {
      openDirectory: async () => { throw new CliError("SERVER_UNREACHABLE", `Missing ${password}`, [`Inspect ${password}`]); },
    });
    assert.equal(result.exitCode, 1);
    assert.equal(result.stdout, 'error: "Missing [REDACTED]"\ncode: SERVER_UNREACHABLE\nhelp[1]: "Inspect [REDACTED]"\n');
  });
});

for (const [pattern, password] of [
  ["SAS", `keep?sig=${"synthetic".repeat(120)}&tail`],
  ["AccountKey", `keep;AccountKey=${"synthetic".repeat(120)};tail`],
  ["JWT", `keep eyJhbGciOiJIUzI1NiJ9.${"B".repeat(1200)}.signature tail`],
  ["PEM", `keep -----BEGIN PRIVATE KEY-----\n${"A".repeat(1200)}\n-----END PRIVATE KEY----- tail`],
] as const) test(`registered passwords containing ${pattern} are fully redacted before truncation`, async () => {
  await withHome(async home => {
    const passwordFile = join(home.root, "password");
    await writeFile(passwordFile, password, { mode: 0o600 });
    await home.save({ work: { ...simple, bindPassword: { file: passwordFile } } });
    const result = await run(["entry", "search", "--config", home.config, "--base", "dc=example,dc=test", "--attributes", "description,info"], {
      openDirectory: async () => new RecordedDirectory("ldapv3", [byFilter([], [entry("uid=synthetic", {
        description: [password, JSON.stringify(password).slice(1, -1), encodeURIComponent(password)],
        info: [password],
      })])]),
    });
    assert.equal(result.exitCode, 0, result.stdout);
    assert.match(result.stdout, /description\[3\]: "\[REDACTED\]","\[REDACTED\]","\[REDACTED\]"/);
    assert.match(result.stdout, /info: "\[REDACTED\]"/);
    assert.doesNotMatch(result.stdout + result.stderr, /keep|tail|truncated/);
  });
});

for (const [pattern, password, payload, protectedValue] of [
  ["SAS", "sig", "https://example.test/?sig=protected-token&x=1", "protected-token"],
  ["AccountKey", "AccountKey", "AccountKey=protected-token;next=ordinary", "protected-token"],
  ["JWT", "eyJ", `eyJhbGciOiJIUzI1NiJ9.${"B".repeat(1200)}.signature`, "B".repeat(64)],
  ["PEM", "PRIVATE KEY", `-----BEGIN PRIVATE KEY-----\n${"A".repeat(1200)}\n-----END PRIVATE KEY-----`, "A".repeat(64)],
] as const) test(`registered pattern labels do not defeat ${pattern} redaction before truncation`, async () => {
  await withHome(async home => {
    const passwordFile = join(home.root, "password");
    await writeFile(passwordFile, password, { mode: 0o600 });
    await home.save({ work: { ...simple, bindPassword: { file: passwordFile } } });
    const result = await run(["entry", "search", "--config", home.config, "--base", "dc=example,dc=test", "--attributes", "description"], {
      openDirectory: async () => new RecordedDirectory("ldapv3", [byFilter([], [entry("uid=synthetic", { description: [payload] })])]),
    });
    assert.equal(result.exitCode, 0, result.stdout);
    assert.ok(!result.stdout.includes(protectedValue), result.stdout);
    assert.match(result.stdout, /\[REDACTED\]/);
    assert.doesNotMatch(result.stdout, /truncated/);
  });
});

for (const [command, collection] of [
  [["entry", "search"], "entries"],
  [["entry", "show", "cn=synthetic,dc=example,dc=test"], "entry"],
  [["user", "list"], "users"],
  [["user", "show", "cn=synthetic,dc=example,dc=test"], "user"],
  [["group", "list"], "groups"],
  [["group", "show", "cn=synthetic,dc=example,dc=test"], "group"],
] as const) test(`${command.join(" ")} redacts complete attributes before truncation`, async () => {
  await withHome(async home => {
    const password = "synthetic-long-password".repeat(60);
    const passwordFile = join(home.root, "password");
    await writeFile(passwordFile, password, { mode: 0o600 });
    await home.save({ work: { ...simple, bindPassword: { file: passwordFile } } });
    const dn = "cn=synthetic,dc=example,dc=test";
    const row = entry(dn, {
      objectClass: ["inetOrgPerson", "groupOfNames"], cn: ["synthetic"],
      description: [`-----BEGIN PRIVATE KEY-----\n${"A".repeat(1200)}\n-----END PRIVATE KEY-----`, `eyJhbGciOiJIUzI1NiJ9.${"B".repeat(1200)}.signature`, password],
      info: [password], title: ["ordinary".repeat(150)],
    });
    const result = await run([...command, "--config", home.config, "--base", "dc=example,dc=test", "--attributes", "description,info,title"], {
      openDirectory: async () => new RecordedDirectory("ldapv3", [byDn(dn, row), byFilter([], [row])]),
    });
    assert.equal(result.exitCode, 0, result.stdout);
    assert.match(result.stdout, new RegExp(`^${collection}(?:\\[1\\])?:`, "m"));
    assert.match(result.stdout, /description\[3\]: "\[REDACTED\]","\[REDACTED\]","\[REDACTED\]"/);
    assert.match(result.stdout, /info: "\[REDACTED\]"/);
    assert.ok(result.stdout.includes(`${"ordinary".repeat(100)}… (truncated, 1200 chars total)`));
    assert.doesNotMatch(result.stdout, /BEGIN PRIVATE KEY|eyJhbGci|synthetic-long-password/);
  });
});

for (const [title, flags, env, expected] of [
  ["flag profile precedes environment selection", ["--profile", "flag"], { LDAP_AXI_PROFILE: "selected", LDAP_AXI_URL: "ldaps://env.example.test" }, "flag"],
  ["environment profile selector precedes env fields", [], { LDAP_AXI_PROFILE: "selected", LDAP_AXI_URL: "ldaps://env.example.test" }, "selected"],
  ["env profile precedes the default profile", [], { LDAP_AXI_URL: "ldaps://env.example.test" }, "env"],
  ["default profile selects one of several profiles", [], {}, "selected"],
] as const) test(title, async () => {
  await withHome(async home => {
    await home.save({ flag: ambient, selected: ambient }, "selected");
    const result = home.cli(["auth", "status", "--offline", ...flags], env);
    assert.equal(result.status, 0, result.stdout);
    assert.match(result.stdout, new RegExp(`profile: ${expected}\\n`));
  });
});

test("a file-selected profile ignores partial env credentials and endpoint settings", async () => {
  await withHome(async home => {
    await home.save({ selected: ambient });
    const result = home.cli(["auth", "status", "--offline", "--profile", "selected"], { LDAP_AXI_URL: "invalid", LDAP_AXI_BIND_DN: "uid=wrong", LDAP_AXI_AUTH: "simple", LDAP_AXI_START_TLS: "wrong" });
    assert.equal(result.status, 0, result.stdout);
    assert.match(result.stdout, /url: "ldaps:\/\/directory.example.test"/);
    assert.match(result.stdout, /credentials: ambient \(unchecked\)/);
  });
});

test("non-secret flags override the selected file profile", async () => {
  await withHome(async home => {
    await home.save({ selected: ambient });
    const result = home.cli(["auth", "status", "--offline", "--url", "ldap://override.example.test"]);
    assert.equal(result.status, 0, result.stdout);
    assert.match(result.stdout, /url: "ldap:\/\/override.example.test"/);
    assert.match(result.stdout, /sasl_security_layer: confidentiality/);
  });
});

for (const [profiles, defaultProfile, expected] of [
  [{}, undefined, "PROFILE_REQUIRED"],
  [{ one: ambient, two: ambient }, undefined, "PROFILE_AMBIGUOUS"],
  [{ one: ambient }, "missing", "PROFILE_NOT_FOUND"],
] as const) test(`profile selection reports ${expected}`, async () => {
  await withHome(async home => {
    await home.save(profiles, defaultProfile);
    const result = home.cli();
    assert.notEqual(result.status, 0);
    assert.match(result.stdout, new RegExp(`code: ${expected}`));
  });
});

test("an omitted password reference defaults to LDAP_AXI_BIND_PASSWORD", async () => {
  await withHome(async home => {
    await home.save({ work: { url: endpoint, auth: "simple", bindDn: "uid=synthetic" } });
    const result = home.cli(["auth", "status", "--offline", "--profile", "work"], { LDAP_AXI_BIND_PASSWORD: "synthetic-default-password" });
    assert.equal(result.status, 0, result.stdout);
    assert.match(result.stdout, /bind_password_source: "env:LDAP_AXI_BIND_PASSWORD"/);
  });
});

test("a half environment credential pair never falls back to a file profile", async () => {
  await withHome(async home => {
    await home.save({ work: ambient });
    const result = home.cli(undefined, { LDAP_AXI_BIND_DN: "uid=synthetic" });
    assert.equal(result.status, 2, result.stdout);
    assert.match(result.stdout, /CREDENTIAL_INCOMPLETE/);
  });
});

test("a missing selected password reference is CREDENTIAL_INCOMPLETE", async () => {
  await withHome(async home => {
    await home.save({ work: simple });
    const result = home.cli();
    assert.equal(result.status, 2, result.stdout);
    assert.match(result.stdout, /CREDENTIAL_INCOMPLETE/);
  });
});

for (const [title, profile] of [
  ["inline password", { ...simple, bindPassword: "synthetic-inline-password" }],
  ["unknown field", { ...ambient, unexpected: true }],
  ["invalid environment reference", { ...simple, bindPassword: { env: "BAD=NAME" } }],
  ["ambiguous reference", { ...simple, bindPassword: { env: "ARTIUM_SECRET_0", file: "/tmp/password" } }],
  ["relative file reference", { ...simple, bindPassword: { file: "password" } }],
  ["stored secret", { ...simple, bindPassword: { stored: true } }],
  ["wrong boolean type", { ...ambient, startTls: "false" }],
  ["invalid page size", { ...ambient, pageSize: 1001 }],
] as const) test(`profile validation rejects ${title} before secret resolution`, async () => {
  await withHome(async home => {
    await home.save({ work: profile });
    const result = home.cli(["profile", "list"]);
    assert.notEqual(result.status, 0);
    assert.match(result.stdout, /CONFIG_INVALID/);
    assert.doesNotMatch(result.stdout + result.stderr, /synthetic-inline-password/);
  });
});

test("password files remove a BOM and trailing whitespace and redact directory output", async () => {
  await withHome(async home => {
    const passwordFile = join(home.root, "password");
    const password = 'synthetic password/"';
    await writeFile(passwordFile, `\uFEFF${password}\r\n \t`, { mode: 0o600 });
    await home.save({ artium: { ...simple, bindPassword: { file: passwordFile } } }, "artium");
    const result = await run(["entry", "search", "--config", home.config, "--profile", "artium", "--base", "dc=example,dc=test"], {
      openDirectory: async options => {
        assert.equal(options.authPlan?.credentials?.password, password);
        return new RecordedDirectory("ldapv3", [byFilter(["objectClass"], [entry("uid=synthetic", { cn: [password, encodeURIComponent(password)] })])]);
      },
    });
    assert.equal(result.exitCode, 0, result.stdout);
    assert.doesNotMatch(result.stdout + result.stderr, /synthetic password|synthetic%20password/);
    assert.match(result.stdout, /REDACTED/);
    const offline = home.cli();
    assert.equal(offline.status, 0, offline.stdout);
    assert.match(offline.stdout, /bind_password_source: "file:/);
    assert.match(offline.stdout, process.platform === "win32" ? /credentials_file_permissions: unchecked \(windows\)/ : /credentials_file_permissions: checked/);
  });
});

test("ambient auth does not open a simple password file", async () => {
  await withHome(async home => {
    await home.save({ work: { ...simple, auth: "auto", bindPassword: { file: join(home.root, "does-not-exist") } } });
    const result = home.cli();
    assert.equal(result.status, 0, result.stdout);
    assert.match(result.stdout, /credentials: ambient \(unchecked\)/);
    assert.match(result.stdout, /credentials_file_permissions: not-used/);
  });
});

test("anonymous auth refuses configured simple credentials", async () => {
  await withHome(async home => {
    await home.save({ work: { ...simple, auth: "auto" } });
    const result = home.cli(["auth", "status", "--offline", "--anonymous"]);
    assert.equal(result.status, 2, result.stdout);
    assert.match(result.stdout, /VALIDATION_ERROR/);
  });
});

for (const target of ["config", "password"] as const) test(`POSIX refuses a group-readable ${target} file`, { skip: process.platform === "win32" }, async () => {
  await withHome(async home => {
    const passwordFile = join(home.root, "password");
    await writeFile(passwordFile, "synthetic-file-password", { mode: 0o600 });
    await home.save({ work: { ...simple, bindPassword: { file: passwordFile } } });
    await chmod(target === "config" ? home.config : passwordFile, 0o640);
    const result = home.cli();
    assert.notEqual(result.status, 0);
    assert.match(result.stdout, /CONFIG_INSECURE/);
    assert.doesNotMatch(result.stdout + result.stderr, /synthetic-file-password/);
  });
});

test("a symlink password file is refused before reading", { skip: process.platform === "win32" }, async () => {
  await withHome(async home => {
    const file = join(home.root, "password");
    await writeFile(file, "synthetic-file-password", { mode: 0o600 });
    const link = join(home.root, "link");
    await symlink(file, link);
    await home.save({ work: { ...simple, bindPassword: { file: link } } });
    const result = home.cli();
    assert.notEqual(result.status, 0);
    assert.match(result.stdout, /CONFIG_INSECURE/);
  });
});

test("relative XDG_CONFIG_HOME falls back to os.homedir rather than the working directory", { skip: process.platform === "win32" }, async () => {
  await withHome(async home => {
    const result = home.cli(["config", "path"], { XDG_CONFIG_HOME: "relative" });
    assert.equal(result.status, 0);
    assert.ok(result.stdout.includes(join(home.root, ".config", "ldap-axi", "config.json")));
  });
});

test("config flag precedes LDAP_AXI_CONFIG and its deprecated alias", async () => {
  await withHome(async home => {
    await home.save({ selected: ambient });
    const result = home.cli(["auth", "status", "--offline", "--config", home.config], { LDAP_AXI_CONFIG: join(home.root, "missing"), LDAP_AXI_CONFIG_FILE: "also-missing" });
    assert.equal(result.status, 0, result.stdout);
    assert.match(result.stdout, /profile: selected/);
    assert.equal(result.stderr, "");
  });
});

test("profile list does not resolve secrets", async () => {
  await withHome(async home => {
    await home.save({ work: simple });
    const result = home.cli(["profile", "list"]);
    assert.equal(result.status, 0, result.stdout);
    assert.match(result.stdout, /work/);
    assert.doesNotMatch(result.stdout, /ARTIUM_SECRET_0/);
  });
});

test("legacy credentials.env is reported without reading its contents", async () => {
  await withHome(async home => {
    await writeFile(join(home.root, "config", "ldap-axi", "credentials.env"), "LDAP_AXI_BIND_PASSWORD=synthetic-legacy-password", { mode: 0o600 });
    const result = home.cli();
    assert.notEqual(result.status, 0);
    assert.match(result.stdout, /CONFIG_MOVED/);
    assert.doesNotMatch(result.stdout + result.stderr, /synthetic-legacy-password/);
  });
});

test("legacy config format fails with migration help", async () => {
  await withHome(async home => {
    await writeFile(home.config, JSON.stringify({ url: endpoint }), { mode: 0o600 });
    const result = home.cli();
    assert.notEqual(result.status, 0);
    assert.match(result.stdout, /CONFIG_MOVED/);
    assert.match(result.stdout, /SecretRef/);
  });
});

for (const value of ["yes", "", "2"]) test(`invalid LDAP_AXI_READ_ONLY ${JSON.stringify(value)} fails closed`, async () => {
  await withHome(async home => {
    const result = home.cli(undefined, { LDAP_AXI_READ_ONLY: value });
    assert.notEqual(result.status, 0);
    assert.match(result.stdout, /CONFIG_INVALID/);
  });
});

