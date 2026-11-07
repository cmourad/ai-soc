/**
 * Process-lifetime counters behind the Stats gauge.
 *
 * They are counted here rather than derived from the retained collections
 * because those are capped ring buffers: "events seen since start" and "events
 * still in memory" diverge the moment the cap is hit, and the gauge is meant to
 * report the former.
 *
 * Callers count transitions, not writes — an LLM call is upserted several times
 * as it runs — so each function names the event it records.
 */

/** Trailing window for the events/sec gauge. Short enough to read as "now". */
const RATE_WINDOW_MS = 5_000;

const startedAt = Date.now();
const recentEventTimes: number[] = [];

let totalEvents = 0;
let llmTotal = 0;
let llmErrors = 0;
let tokensUsed = 0;
let detectionRuns = 0;
let detectionHits = 0;

export function countEvent(now = Date.now()): void {
  totalEvents += 1;
  recentEventTimes.push(now);
}

export function countLlmCall(): void {
  llmTotal += 1;
}

export function countLlmError(): void {
  llmErrors += 1;
}

export function countTokens(total: number): void {
  tokensUsed += total;
}

export function countDetectionRun(hits: number): void {
  detectionRuns += 1;
  detectionHits += hits;
}

export function eventsPerSecond(now = Date.now()): number {
  const cutoff = now - RATE_WINDOW_MS;
  while (recentEventTimes.length > 0 && recentEventTimes[0]! < cutoff) recentEventTimes.shift();
  return Math.round((recentEventTimes.length / (RATE_WINDOW_MS / 1_000)) * 10) / 10;
}

export function uptimeSeconds(now = Date.now()): number {
  return Math.round((now - startedAt) / 1_000);
}

export function counters(): {
  totalEvents: number;
  llmTotal: number;
  llmErrors: number;
  tokensUsed: number;
  detectionRuns: number;
  detectionHits: number;
} {
  return { totalEvents, llmTotal, llmErrors, tokensUsed, detectionRuns, detectionHits };
}
