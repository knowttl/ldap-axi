import { performance } from "node:perf_hooks";

type TraceValue = string | number | boolean;

type TraceFields = Readonly<Record<string, TraceValue>>;

const TRACE_ENABLED = process.env.LDAP_AXI_GSSAPI_TRACE === "1";
export const traceEnabled = TRACE_ENABLED;
let traceStartedAt: number | undefined;

export function trace(event: string, fields?: () => TraceFields): void {
  if (!TRACE_ENABLED) return;
  const now = performance.now();
  traceStartedAt ??= now;
  process.stderr.write(`ldap-axi-trace ${JSON.stringify({ ...fields?.(), event, elapsedMs: Math.floor(now - traceStartedAt) })}\n`);
}
