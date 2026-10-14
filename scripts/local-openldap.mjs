import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// Opt-in only. All credentials, tickets, CA keys and server data live in this
// invocation's Docker volume. Nothing reads or modifies host Kerberos state.
const prefix = `ldap-axi-test-${randomUUID()}`;
const network = `${prefix}-net`;
const volume = `${prefix}-data`;
const image = `${prefix}-mock`;
const kdc = `${prefix}-kdc`;
const ldap = `${prefix}-ldap`;
const client = `${prefix}-client`;
const root = fileURLToPath(new URL("../", import.meta.url));
const clientImage = "node@sha256:6dac556d980b7f0e5498d08f08cee0ca67798b4ad6c23964a9214920e67758d0";

function docker(args, options = {}) {
  const result = spawnSync("docker", args, { stdio: "inherit", ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`docker ${args[0]} failed (${result.status})`);
}

function cleanup() {
  for (const args of [["rm", "--force", client, ldap, kdc], ["network", "rm", network], ["volume", "rm", volume], ["image", "rm", image]]) {
    spawnSync("docker", args, { stdio: "ignore" });
  }
}
for (const [signal, code] of [["SIGINT", 130], ["SIGTERM", 143]]) {
  process.once(signal, () => { cleanup(); process.exit(code); });
}

function waitForLog(container, marker) {
  return new Promise((resolve, reject) => {
    const logs = spawn("docker", ["logs", "--follow", container], { stdio: ["ignore", "pipe", "pipe"] });
    let recent = "";
    let settled = false;
    const timeout = setTimeout(() => finish(new Error(`${container} did not report ${marker}`)), 60_000);
    function finish(error) {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      logs.removeAllListeners("exit");
      logs.kill();
      if (error) reject(error); else resolve();
    }
    function receive(chunk) {
      recent = (recent + chunk.toString()).slice(-8192);
      if (recent.includes(marker)) finish();
    }
    logs.stdout.on("data", receive);
    logs.stderr.on("data", receive);
    logs.once("error", finish);
    logs.once("exit", code => finish(new Error(`${container} exited before readiness (${code})`)));
  });
}

if (process.platform !== "linux") throw new Error("local-directory requires Linux and Docker");
if (!existsSync(new URL("../dist/src/cli.js", import.meta.url))) throw new Error("run npm run build first");
try {
  docker(["build", "--quiet", "--tag", image, `${root}test/local-directory/openldap`]);
  docker(["network", "create", network]);
  docker(["volume", "create", volume]);
  docker(["run", "--detach", "--name", kdc, "--network", network, "--network-alias", "kdc",
    "--volume", `${volume}:/data`, image, "sh", "/opt/mock/kdc-entry.sh"]);
  await waitForLog(kdc, "krb5kdc: starting");
  docker(["run", "--detach", "--name", ldap, "--network", network,
    "--volume", `${volume}:/data`, image, "sh", "/opt/mock/ldap-entry.sh"]);
  await waitForLog(ldap, "slapd starting");
  docker(["exec", ldap, "sh", "/opt/mock/seed.sh"]);

  // Sharing only this invocation's LDAP network namespace makes localhost the
  // actual ldap/localhost SPN and certificate identity, without host DNS edits.
  docker(["run", "--detach", "--name", client, "--network", `container:${ldap}`,
    "--volume", `${root}:/work:ro`, "--volume", `${volume}:/data`, "--workdir", "/work",
    "--env", "HOME=/tmp/ldap-axi-home", "--env", "XDG_CONFIG_HOME=/tmp/ldap-axi-config",
    "--env", "XDG_CACHE_HOME=/tmp/ldap-axi-cache", "--env", "XDG_DATA_HOME=/tmp/ldap-axi-data",
    "--env", "XDG_STATE_HOME=/tmp/ldap-axi-state", "--env", "KRB5_CONFIG=/data/krb5.conf",
    "--env", "KRB5CCNAME=FILE:/tmp/ldap-axi-ccache", "--env", "KRB5_KTNAME=/tmp/absent.keytab",
    "--env", "KRB5_CLIENT_KTNAME=/tmp/absent-client.keytab",
    clientImage, "sleep", "infinity"]);
  docker(["exec", "--env", "DEBIAN_FRONTEND=noninteractive", client, "sh", "-ec",
    "apt-get update -qq && apt-get install -y -qq krb5-user && mkdir -p \"$HOME\" \"$XDG_CONFIG_HOME\" \"$XDG_CACHE_HOME\" \"$XDG_DATA_HOME\" \"$XDG_STATE_HOME\""]);
  docker(["exec", client, "sh", "-ec", "kinit alice@LDAPAXI.TEST < /data/secrets/alice.pw"]);
  docker(["exec", "--env", "LDAP_AXI_LOCAL_OPENLDAP=1", client, "sh", "-ec",
    'export LDAP_AXI_BIND_DN=uid=svc-ldapaxi,ou=service-accounts,dc=ldapaxi,dc=test; export LDAP_AXI_BIND_PASSWORD="$(cat /data/secrets/svc.pw)"; exec node --test dist/test/local-directory/openldap.test.js']);
} finally {
  cleanup();
}
