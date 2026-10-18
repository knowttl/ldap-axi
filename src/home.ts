/** One description for the home view and the generated skill, so the two cannot drift (docs/design/v1.md §14.1, §17.2). */
export const LDAP_AXI_DESCRIPTION = "Read Active Directory and LDAPv3 directories safely with ldap-axi (read-only)";

/** The implemented command surface, in the order the home view lists it (docs/design/v1.md §2.1). */
export const COMMANDS = [
  "entry search", "entry show",
  "user list", "user show", "user groups",
  "group list", "group show", "group members",
  "computer list", "computer show",
  "auth status",
  "profile list", "config path",
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
      "Run `ldap-axi entry search --help` to explore a directory safely",
      ...(credentialsResolved ? ["Authentication auto selects ambient Kerberos/SSPI; use --auth simple to use configured simple credentials"] : []),
    ],
  };
}
