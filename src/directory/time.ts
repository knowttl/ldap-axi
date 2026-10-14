// AD FILETIME (100ns ticks since 1601-01-01 UTC) and RFC 4517 GeneralizedTime decoding, including
// the two FILETIME sentinels that must never be converted to a date (docs/design/v1.md §6.3).
const FILETIME_EPOCH_OFFSET_MS = 11_644_473_600_000n;
const FILETIME_NEVER = 9_223_372_036_854_775_807n;

export function decodeFiletime(value: string): string {
  const ticks = BigInt(value);
  if (ticks === 0n) return "unset";
  if (ticks === FILETIME_NEVER) return "never";
  const millis = ticks / 10_000n - FILETIME_EPOCH_OFFSET_MS;
  return new Date(Number(millis)).toISOString();
}

const GENERALIZED_TIME = /^(\d{4})(\d{2})(\d{2})(\d{2})(?:(\d{2})(?:(\d{2}))?)?(?:[.,](\d+))?(Z|[+-]\d{2}(?::?\d{2})?)$/;
export function decodeGeneralizedTime(value: string): string {
  const match = GENERALIZED_TIME.exec(value);
  if (!match) throw new Error(`not a GeneralizedTime value: ${value}`);
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction, rawZone] = match;
  const year = Number(yearText); const month = Number(monthText); const day = Number(dayText); const hour = Number(hourText);
  const minute = Number(minuteText ?? "0"); const second = Number(secondText ?? "0");
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, Math.min(second, 59), 0);
  if (month < 1 || month > 12 || day < 1 || date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day || hour > 23 || minute > 59 || second > 60) throw new Error(`not a valid GeneralizedTime value: ${value}`);
  const unitMillis = secondText !== undefined ? 1_000 : minuteText !== undefined ? 60_000 : 3_600_000;
  const fractionMillis = fraction ? Number(BigInt(fraction) * BigInt(unitMillis) / (10n ** BigInt(fraction.length))) : 0;
  let offsetMillis = 0;
  if (rawZone !== "Z") {
    const digits = rawZone.slice(1).replace(":", "");
    const zoneHour = Number(digits.slice(0, 2)); const zoneMinute = Number(digits.slice(2) || "0");
    if (zoneHour > 23 || zoneMinute > 59) throw new Error(`not a valid GeneralizedTime value: ${value}`);
    offsetMillis = (zoneHour * 60 + zoneMinute) * 60_000 * (rawZone[0] === "+" ? 1 : -1);
  }
  return new Date(date.getTime() + (second === 60 ? 1_000 : 0) + fractionMillis - offsetMillis).toISOString();
}
