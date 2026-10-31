import { CliError, first, type Directory } from "./core.js";
import { walkHelp, walkMetadata, walkPages } from "./directory/walk.js";
import { truncate } from "./render.js";

/** One description for the home view and the generated skill, so the two cannot drift (docs/design/v1.md §14.1, §17.2). */
export const LDAP_AXI_DESCRIPTION = "Read Active Directory and LDAPv3 directories safely with ldap-axi (read-only)";

export const HOME_GUIDANCE = [
  "Use the compact investigation guide in the ldap-axi skill; reserve --help for a failed or unfamiliar command",
] as const;

/** The implemented command surface, in the order the home view lists it (docs/design/v1.md §2.1). */
export const COMMANDS = [
  "entry search", "entry show",
  "user list", "user show", "user groups",
  "group list", "group show", "group members",
  "computer list", "computer show",
  "auth status", "server",
  "profile list", "config path", "setup",
] as const;

export function homeView(bin: string, url: string | undefined, credentialsResolved: boolean): { data: Record<string, unknown>; help: string[] } {
  return {
    data: {
      bin,
      description: LDAP_AXI_DESCRIPTION,
      ...(url ? { server: url } : {}),
      credentials: credentialsResolved ? "configured for simple auth" : "not configured",
      commands: [...COMMANDS],
    },
    help: [
      url ? "Run `ldap-axi auth status` to report the selected authentication and its transport" : "Set LDAP_AXI_URL or pass --url ldaps://server:636 to name a directory",
      ...HOME_GUIDANCE,
      ...(credentialsResolved ? ["Authentication auto selects ambient Kerberos/SSPI; use --auth simple to use configured simple credentials"] : []),
    ],
  };
}

export async function liveHome(directory: Directory, configuredBase: string | undefined): Promise<{ data: Record<string, unknown>; help: string[] }> {
  const root = await directory.rootDSE();
  const contexts = root.attributes.namingContexts ?? [];
  const base = configuredBase ?? (root.flavor === "ad" ? root.attributes.defaultNamingContext?.[0] : undefined) ?? (contexts.length === 1 ? contexts[0] : undefined);
  const data: Record<string, unknown> = { flavor: directory.flavor };
  if (base === undefined) return { data: { ...data, preview: "unavailable: select a search base" }, help: ["Pass --base <dn> to select a naming context; run `ldap-axi server` to inspect advertised contexts"] };
  data.base = truncate(base);
  try {
    const preview = await walkPages(directory, { base, filter: "(objectClass=*)", scope: "one", attributes: ["cn"], pageSize: 5 }, { maxRows: 5, all: false });
    const metadata = walkMetadata(preview);
    if (preview.referrals.length) {
      metadata.referrals = preview.referrals.slice(0, 5).map(uri => ({ uri: truncate(uri) }));
      metadata.referral_count = preview.referrals.length;
      if (preview.referrals.length > 5) metadata.referrals_truncated = true;
    }
    data.preview = {
      scope: "immediate children only",
      ...metadata,
      entries: preview.entries.length || preview.stopReason ? preview.entries.map(entry => ({ dn: truncate(entry.dn), cn: truncate(first(entry, "cn") ?? "") })) : "0 entries matched (entries hidden by access control are indistinguishable from absent entries)",
    };
    return { data, help: ["Run `ldap-axi entry search --scope one --all --max-rows <n>` with the same profile and base for a larger bounded preview", ...walkHelp(preview)] };
  } catch (error) {
    if (!(error instanceof CliError) || !["INSUFFICIENT_ACCESS", "NOT_FOUND", "SERVER_LIMIT", "UNSUPPORTED_BY_SERVER"].includes(error.code)) throw error;
    return { data: { ...data, preview: "unavailable", preview_error: error.code }, help: [...error.help, "Run `ldap-axi entry search --scope one` with the same profile and base to diagnose preview access"] };
  }
}
