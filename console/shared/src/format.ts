/**
 * Presentation of the two quantities that appear on both sides of the API.
 *
 * Server-generated insight text and the screens that show the same totals used
 * to disagree — one counted a kilobyte as 1024 bytes and the other as 1000, so
 * one traffic figure rendered two ways. Bytes here are SI throughout, matching
 * how every other network tool reports a transfer.
 */

export function formatBytes(value: number): string {
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1)} GB`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)} MB`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)} kB`;
  return `${value} B`;
}

/** Prose for a configured lookback, used in insight text and beside the screens it describes. */
export function windowLabel(hours: number): string {
  if (hours <= 1) return "the last hour";
  if (hours < 48) return `the last ${hours} hours`;
  return `the last ${Math.round(hours / 24)} days`;
}
