import { ROOT_DSE_ATTRIBUTES, type Directory, type ServerFlavor } from "./core.js";

/** Report advertised facts only; policy names do not establish effective limit values. */
export async function serverReport(directory: Directory, override?: ServerFlavor): Promise<{ data: Record<string, unknown>; help: string[] }> {
  const root = await directory.rootDSE();
  const facts = Object.fromEntries(ROOT_DSE_ATTRIBUTES.flatMap(name => {
    const values = root.attributes[name];
    return values?.length ? [[name, values]] : [];
  }));
  const limits = Object.fromEntries(["maxPageSize", "maxQueryDuration", "sizeLimit", "timeLimit"].flatMap(name => {
    const values = root.attributes[name];
    return values?.length ? [[name, values]] : [];
  }));
  return {
    data: {
      flavor: override ?? root.flavor,
      detected_flavor: root.flavor,
      flavor_overridden: override !== undefined,
      vendor: root.attributes.vendorName?.[0] ?? "unknown",
      root_dse: facts,
      advertised_limits: Object.keys(limits).length ? limits : "not advertised",
    },
    help: [],
  };
}
