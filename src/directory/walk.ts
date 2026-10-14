import { CliError, type Directory, type Entry, type SearchRequest } from "../core.js";

// The bounded page walk shared by every list-shaped command: entry search, user list, group
// list, and the direct-membership resolution paths in user groups / group members. One page by
// default (incomplete only when a continuation exists), or a full bounded walk with --all plus a
// row budget (docs/design/v1.md §9.2-9.3).
export type WalkOptions = Readonly<{ maxRows?: number; all: boolean; include?: (entry: Entry) => boolean }>;
export type WalkResult = Readonly<{ entries: readonly Entry[]; referrals: readonly string[]; partial: boolean; incomplete: boolean; stopReason?: string }>;

export async function walkPages(directory: Directory, request: SearchRequest, options: WalkOptions): Promise<WalkResult> {
  const entries: Entry[] = []; const referrals: string[] = []; let stopReason: string | undefined; let firstPageRead = false;
  for await (const page of directory.searchPages(request)) {
    referrals.push(...(page.referrals ?? []));
    if (page.stopReason) stopReason = page.stopReason;
    // ldapts exposes no cookie. Advancing once proves exhaustion without I/O when the
    // first page was terminal; otherwise it fetches one continuation, which is discarded.
    if (firstPageRead && !options.all) { stopReason ??= "page_boundary"; break; }
    for (const entry of page.entries) {
      if (options.include && !options.include(entry)) continue;
      if (options.maxRows !== undefined && entries.length >= options.maxRows) { stopReason = "max_rows"; break; }
      entries.push(entry);
    }
    firstPageRead = true;
    if (stopReason) break;
  }
  if (referrals.length > 0 && (!stopReason || stopReason === "page_boundary")) stopReason = "referral";
  return { entries, referrals, partial: stopReason !== undefined && stopReason !== "page_boundary", incomplete: stopReason === "page_boundary", stopReason };
}

const LIMIT_STOP_REASONS = new Set(["server_size_limit", "server_admin_limit", "server_time_limit"]);
/** The count/partial/incomplete/referrals fragment shared by every list command. Throws SERVER_LIMIT when a server limit stopped the walk before anything was retained. */
export function walkMetadata(walk: WalkResult): Record<string, unknown> {
  if (walk.entries.length === 0 && walk.stopReason && LIMIT_STOP_REASONS.has(walk.stopReason)) throw new CliError("SERVER_LIMIT", `the directory stopped the search before returning any entries (${walk.stopReason})`, ["Narrow the filter, lower --max-rows, or scope the base more tightly"]);
  return {
    count: `${walk.entries.length} of ${walk.partial || walk.incomplete ? "unknown" : walk.entries.length} total`,
    ...(walk.partial ? { partial: true, stop_reason: walk.stopReason } : {}),
    ...(walk.incomplete ? { incomplete: "page_boundary" } : {}),
    ...(walk.referrals.length ? { referrals: walk.referrals.map(uri => ({ uri })) } : {}),
  };
}
export function walkHelp(walk: WalkResult): string[] {
  if (!walk.partial && !walk.incomplete) return [];
  if (walk.stopReason === "referral") return ["Referrals are reported but not chased; query the referred directory directly"];
  if (walk.stopReason?.startsWith("server_")) return ["Narrow the filter or search base to stay within the directory server limit"];
  if (walk.stopReason === "max_rows") return ["Re-run with a higher --max-rows for a more complete bounded read"];
  return ["Re-run with --all --max-rows <n> to complete a bounded in-process read"];
}
