// Fixed read-only live smoke sequence (docs/design/v1.md §19).
// It runs only with LDAP_AXI_LIVE=1, uses one authentication exchange per connected CLI invocation, and writes a
// redacted evidence file that records shapes and trace events, never directory content.
import { writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

if (process.env.LDAP_AXI_LIVE !== "1") {
  process.stderr.write("live smoke requires LDAP_AXI_LIVE=1 (docs/design/v1.md §19.1)\n");
  process.exit(2);
}

const argv = process.argv.slice(2);
let out;
const passthrough = [];
for (let index = 0; index < argv.length; index++) {
  if (argv[index] === "--out") { out = argv[++index]; continue; }
  passthrough.push(argv[index]);
}
const url = passthrough.includes("--url") ? passthrough[passthrough.indexOf("--url") + 1] : process.env.LDAP_AXI_URL;
if (!url) {
  process.stderr.write("live smoke requires --url ldaps://server:636 or LDAP_AXI_URL\n");
  process.exit(2);
}
out ??= join(tmpdir(), `ldap-axi-live-smoke-${process.pid}.json`);

process.env.LDAP_AXI_GSSAPI_TRACE = "1";
const { run } = await import("../dist/src/cli.js");

const STEPS = [
  { name: "home", argv: [] },
  { name: "auth status (offline)", argv: ["auth", "status", "--offline"] },
  { name: "auth status", argv: ["auth", "status"] },
  { name: "rootDSE read", argv: ["entry", "search", "--base", "", "--scope", "base", "--attributes", "objectClass"] },
  { name: "user list", argv: ["user", "list", "--limit", "1"] },
  { name: "group list", argv: ["group", "list", "--limit", "1"] },
];

/** Records the key names and element counts a TOON document carries, and none of its values. */
function shape(stdout) {
  const keys = [];
  for (const line of stdout.split("\n")) {
    const match = /^([A-Za-z0-9_]+)(?:\[(\d+)\])?:/.exec(line);
    if (match) keys.push(match[2] === undefined ? match[1] : `${match[1]}[${match[2]}]`);
  }
  return keys;
}
function errorCode(stdout) {
  return /^code: ([A-Z_]+)$/m.exec(stdout)?.[1];
}

const traces = [];
const write = process.stderr.write.bind(process.stderr);
process.stderr.write = (chunk, ...rest) => {
  const text = typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
  for (const line of text.split("\n")) {
    if (!line.startsWith("ldap-axi-trace ")) continue;
    try { traces.push(JSON.parse(line.slice("ldap-axi-trace ".length))); } catch { traces.push({ event: "unparsed-trace" }); }
  }
  return write(chunk, ...rest);
};

const evidence = { tool: "ldap-axi live smoke", url_scheme: new URL(url).protocol.replace(":", ""), steps: [] };
let failed = 0;
for (const step of STEPS) {
  const before = traces.length;
  const started = Date.now();
  const result = await run(step.name === "home" ? step.argv : [...step.argv, ...passthrough]);
  if (result.exitCode !== 0) failed++;
  evidence.steps.push({
    step: step.name,
    argv: step.argv,
    exit_code: result.exitCode,
    elapsed_ms: Date.now() - started,
    keys: shape(result.stdout),
    ...(errorCode(result.stdout) ? { error_code: errorCode(result.stdout) } : {}),
    warnings: result.stderr.split("\n").filter(Boolean),
    trace: traces.slice(before),
  });
  process.stdout.write(`${result.exitCode === 0 ? "ok  " : "FAIL"} ${step.name}\n`);
}
process.stderr.write = write;

await writeFile(out, `${JSON.stringify(evidence, null, 2)}\n`);
process.stdout.write(`evidence: ${out}\n`);
process.exitCode = failed ? 1 : 0;
