import type { Directory } from "./core.js";
import { openDirectory as openInternalDirectory, type ConnectOptions } from "./directory/client.js";

export type { Directory } from "./core.js";

export type OpenDirectoryOptions = Omit<ConnectOptions, "authPlan" | "gssapiProvider">;

export function openDirectory(options: OpenDirectoryOptions): Promise<Directory> {
  return openInternalDirectory({
    url: options.url,
    startTls: options.startTls,
    caFile: options.caFile,
    caOnly: options.caOnly,
    tlsNoVerify: options.tlsNoVerify,
    tlsMaxVersion: options.tlsMaxVersion,
    insecurePlaintext: options.insecurePlaintext,
    auth: options.auth,
    authExplicit: options.authExplicit,
    gssapiService: options.gssapiService,
    gssapiProtection: options.gssapiProtection,
    credentialSource: options.credentialSource,
    bind: options.bind,
    anonymous: options.anonymous,
    timeoutMs: options.timeoutMs,
  });
}
