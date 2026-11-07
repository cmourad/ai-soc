import type { Alert, LlmCall, TriageVerdict } from "@aisoc/shared";
import { getSettings } from "../settings.js";
import { runBatchTriageCall } from "./llm.js";
import { BATCH_SUFFIX, buildBatchContext } from "./prompt.js";

export type BatchOutcome =
  | { kind: "ok"; call: LlmCall; verdict: TriageVerdict }
  /** The batch ran but produced nothing usable for this alert. */
  | { kind: "missing"; call: LlmCall; reason: string }
  /** The whole call failed; every alert in it gets this. */
  | { kind: "failed"; call: LlmCall; error: string };

type Waiter = {
  alert: Alert;
  context: Record<string, unknown>;
  settle: (outcome: BatchOutcome) => void;
};

type Batcher = {
  submit(alert: Alert, context: Record<string, unknown>): Promise<BatchOutcome>;
  pending(): number;
};

/** The codex proxy's own MAX_INFLIGHT is 2; more would only queue there. */
const MAX_CONCURRENT_BATCHES = 2;

/**
 * Collects second-tier alerts into one model call. Most of a codex run is
 * process spawn rather than generation, so N alerts cost close to one — but the
 * alerts share a context window, which is why the batch prompt states that each
 * is judged alone and verdicts are correlated by id.
 */
export function createBatcher(
  systemPrompt: string,
  run: typeof runBatchTriageCall = runBatchTriageCall,
): Batcher {
  const waiting: Waiter[] = [];
  let timer: NodeJS.Timeout | null = null;
  let inFlight = 0;

  function clearTimer(): void {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  }

  /**
   * Only a couple of calls may be open at once — the codex proxy's own
   * `MAX_INFLIGHT` is 2, so more would just queue there. Holding the
   * line is also what makes batches fill: alerts arriving while a call is open
   * accumulate instead of each starting its own near-empty call, and the
   * finishing call sweeps them up.
   */
  function maybeFlush(): void {
    if (inFlight >= MAX_CONCURRENT_BATCHES || waiting.length === 0) return;
    void flush();
  }

  async function flush(): Promise<void> {
    clearTimer();
    const { secondTriage } = getSettings();
    // Splice synchronously: anything arriving during the await forms a new batch.
    const batch = waiting.splice(0, Math.max(1, secondTriage.batchSize));
    if (batch.length === 0) return;

    inFlight += 1;
    const ids = batch.map((item) => item.alert.id);
    try {
      const { call, verdicts, error } = await run(
        {
          stage: "second_triage",
          batchAlertIds: ids,
          config: secondTriage,
          systemPrompt: systemPrompt + BATCH_SUFFIX,
          context: buildBatchContext(batch.map((item) => item.context)),
        },
        ids,
      );

      for (const item of batch) {
        if (error) {
          item.settle({ kind: "failed", call, error });
          continue;
        }
        const verdict = verdicts.get(item.alert.id);
        if (verdict) item.settle({ kind: "ok", call, verdict });
        else
          item.settle({
            kind: "missing",
            call,
            reason: `the batch of ${batch.length} returned no verdict for this alert`,
          });
      }
    } finally {
      inFlight -= 1;
      // Sweep up whatever accumulated while this call was open.
      maybeFlush();
    }
  }

  return {
    pending: () => waiting.length,
    submit(alert, context) {
      return new Promise<BatchOutcome>((settle) => {
        waiting.push({ alert, context, settle });
        const { batchSize, batchLingerMs } = getSettings().secondTriage;
        if (waiting.length >= batchSize) {
          maybeFlush();
          return;
        }
        // Linger from the first arrival so a lone alert is not held indefinitely
        // waiting for company that never comes.
        if (!timer) {
          timer = setTimeout(() => {
            timer = null;
            maybeFlush();
          }, batchLingerMs);
        }
      });
    },
  };
}

export type { Batcher };
