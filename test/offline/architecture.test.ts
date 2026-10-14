import assert from "node:assert/strict";
import { readdir } from "node:fs/promises";
import { register } from "node:module";
import test from "node:test";
import { MessageChannel, type MessagePort } from "node:worker_threads";

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
