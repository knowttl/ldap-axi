import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { cp, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { register } from "node:module";
import { join, resolve } from "node:path";
import test from "node:test";
import { MessageChannel, type MessagePort } from "node:worker_threads";

test("architecture lint admits release automation but rejects additional workflows", async () => {
  const fixture = resolve(`.tmp/workflow-policy-${randomUUID()}`);
  try {
    for (const directory of ["src", "test", "vendor/kerberos", ".github/workflows"]) {
      await mkdir(join(fixture, directory), { recursive: true });
    }
    for (const path of ["package-lock.json", "vendor/kerberos/package.json", "vendor/kerberos/UPSTREAM.md", "prebuilds", "test", ".github/workflows"]) {
      await cp(path, join(fixture, path), { recursive: true });
    }
    const lint = () => execFileSync(process.execPath, [resolve("scripts/architecture-check.mjs")], { cwd: fixture, stdio: "pipe" });
    assert.doesNotThrow(lint);
    await writeFile(join(fixture, ".github/workflows/unauthorized.yml"), "name: unauthorized\n");
    assert.throws(lint, /only the native prebuild, local-directory, and release PR workflows are authorized/);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

async function modules(directory: URL): Promise<URL[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map(entry => {
    const url = new URL(entry.name + (entry.isDirectory() ? "/" : ""), directory);
    return entry.isDirectory() ? modules(url) : entry.name.endsWith(".js") ? [url] : [];
  }));
  return nested.flat();
}

function nextMessage(port: MessagePort): Promise<unknown> {
  return new Promise(resolve => port.once("message", resolve));
}

test("only the sealed GSSAPI adapter loads the Kerberos provider", async () => {
  const adapterUrl = new URL("../../src/directory/gssapi.js", import.meta.url);
  const { port1, port2 } = new MessageChannel();
  const loader = `
    let port;
    export function initialize(data) { port = data.port; }
    export async function resolve(specifier, context, nextResolve) {
      if (!specifier.endsWith("/vendor/kerberos/lib/index.js")) return nextResolve(specifier, context);
      port.postMessage(context.parentURL);
      return { url: "data:text/javascript,export default {}", shortCircuit: true };
    }
  `;
  register(`data:text/javascript,${encodeURIComponent(loader)}`, {
    parentURL: import.meta.url,
    data: { port: port2 },
    transferList: [port2],
  });

  for (const moduleUrl of await modules(new URL("../../src/", import.meta.url))) await import(moduleUrl.href);
  const { createKerberosProvider } = await import(adapterUrl.href);
  const loadedBy = nextMessage(port1);
  assert.deepEqual(await createKerberosProvider().prepare("ldap@directory.example.test"), { kind: "provider_unavailable" });
  assert.equal(await loadedBy, adapterUrl.href);
  port1.close();
});
