import type { AttributeMap, Directory, Entry, RootDse, SearchPage, SearchRequest, ServerFlavor } from "../../src/core.js";
import { encodeSid } from "../../src/directory/sid.js";
import { encodeGuid } from "../../src/directory/guid.js";

// Wholly synthetic fixtures (docs/design/v1.md §18.3): every DN, SID, GUID, and attribute value
// here is authored for this test suite, not captured from any real directory.
export function sidBase64(sid: string): string { return encodeSid(sid).toString("base64"); }
export function guidBase64(guid: string): string { return encodeGuid(guid).toString("base64"); }
export function entry(dn: string, attributes: Record<string, readonly string[]>): Entry { return { dn, attributes: attributes as AttributeMap }; }

export type Responder = (request: SearchRequest) => readonly SearchPage[] | undefined;
const singlePage = (entries: readonly Entry[]): readonly SearchPage[] => [{ entries, referrals: [] }];

/** Responds when the request is a base-scope read of exactly this DN (case-insensitive). */
export function byDn(dn: string, result: Entry | readonly SearchPage[] | undefined): Responder {
  return request => request.scope === "base" && request.base.toLowerCase() === dn.toLowerCase()
    ? (result === undefined ? singlePage([]) : Array.isArray(result) ? result as readonly SearchPage[] : singlePage([result as Entry]))
    : undefined;
}
/** Like byDn, but the response can depend on which attributes were requested (AD ranged-retrieval continuation). */
export function byDnFn(dn: string, resolve: (request: SearchRequest) => Entry | undefined): Responder {
  return request => {
    if (request.scope !== "base" || request.base.toLowerCase() !== dn.toLowerCase()) return undefined;
    const result = resolve(request);
    return singlePage(result ? [result] : []);
  };
}
/** Responds when the request's filter string contains every given substring. */
export function byFilter(substrings: readonly string[], result: readonly Entry[] | readonly SearchPage[]): Responder {
  return request => {
    const filter = typeof request.filter === "string" ? request.filter : "";
    if (!substrings.every(part => filter.includes(part))) return undefined;
    return result.length && "dn" in result[0] ? singlePage(result as readonly Entry[]) : result as readonly SearchPage[];
  };
}

export class RecordedDirectory implements Directory {
  readonly requests: SearchRequest[] = [];
  constructor(readonly flavor: ServerFlavor, private readonly responders: readonly Responder[], private readonly rootAttributes: AttributeMap = {}) {}
  async rootDSE(): Promise<RootDse> { return { flavor: this.flavor, attributes: this.rootAttributes }; }
  async *searchPages(request: SearchRequest): AsyncIterable<SearchPage> {
    this.requests.push(request);
    for (const responder of this.responders) {
      const pages = responder(request);
      if (pages) { for (const page of pages) yield page; return; }
    }
    yield { entries: [], referrals: [] };
  }
  async whoami(): Promise<string | undefined> { return undefined; }
  async close(): Promise<void> {}
}

// A handful of specification-authored constants reused across tests.
export const DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333";
export const DOMAIN_USERS_RID = 513;
export const BASE = "DC=example,DC=test";
