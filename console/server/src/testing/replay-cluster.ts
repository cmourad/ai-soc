import { readFileSync } from "node:fs";
import { runDetection } from "../detect/engine.js";
import { clusterRecordToEvent } from "../sources/cluster.js";

/**
 * Replay a collector spool through the detection engine and print what fired.
 *
 * This is the closing step of a drill round: a technique is not covered because
 * the telemetry exists, it is covered because a rule fires on that telemetry.
 * Pointing this at a spool captured during a red action answers that question
 * in one command, without waiting for the console or the triage queue.
 *
 *   tsx server/src/testing/replay-cluster.ts /var/lib/aisoc-host-events/cluster-events.jsonl
 *
 * Behavioural rules keep state across events, so the file is replayed in order
 * and the exit code is 1 when nothing fired — which makes it usable as the
 * assertion in a scripted drill rather than something a human has to read.
 */

const path = process.argv[2];
if (!path) {
  console.error("usage: replay-cluster.ts <spool.jsonl>");
  process.exit(2);
}

let events = 0;
let fired = 0;
for (const line of readFileSync(path, "utf8").split("\n")) {
  if (!line.trim()) continue;
  let record: unknown;
  try {
    record = JSON.parse(line);
  } catch {
    continue;
  }
  const event = clusterRecordToEvent(record);
  if (!event) continue;
  events++;
  const detection = runDetection(event);
  if (detection.hits.length === 0) continue;
  fired++;
  const rules = detection.hits.map((hit) => hit.ruleId).join(",");
  console.log(
    `${detection.band.padEnd(10)} ${String(detection.score).padStart(3)}  ${rules}  ${event.signature}  ${(event.url ?? "").slice(0, 60)}`,
  );
}

console.log(`replayed ${events} events, ${fired} with a detection hit`);
process.exit(fired > 0 ? 0 : 1);
