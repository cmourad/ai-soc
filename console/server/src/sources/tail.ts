import { createReadStream, existsSync, statSync } from "node:fs";

/**
 * Follow an append-only JSONL file from its current end, surviving rotation.
 *
 * Every telemetry source here is a file somebody else writes — Suricata, or the
 * root collector that owns the cluster streams. Reading from the end matters:
 * on start there is no way to know which of the existing millions of lines were
 * already triaged, and replaying them would flood the queue with history.
 */
export function tailJsonl(options: {
  path: () => string;
  paused: () => boolean;
  onRecord: (raw: unknown) => void;
  onError: (message: string) => void;
  /** Name used in error messages, e.g. "eve.json". */
  label: string;
}): () => void {
  const { path, paused, onRecord, onError, label } = options;
  let offset = -1;
  let currentPath = "";
  let pending = "";
  let reading = false;

  const timer = setInterval(() => {
    if (paused()) return;
    const target = path();
    if (target !== currentPath) {
      currentPath = target;
      offset = -1;
      pending = "";
    }
    if (!existsSync(target)) {
      if (offset !== -2) {
        offset = -2;
        onError(`${label} not found at ${target}`);
      }
      return;
    }

    const size = statSync(target).size;
    if (offset < 0) {
      offset = size;
      return;
    }
    if (size < offset) offset = 0; // rotated
    if (size === offset || reading) return;

    reading = true;
    const start = offset;
    offset = size;
    const stream = createReadStream(target, { start, end: size - 1, encoding: "utf8" });
    stream.on("data", (chunk) => {
      pending += chunk;
      const lines = pending.split("\n");
      pending = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          onRecord(JSON.parse(line));
        } catch {
          // A partial or malformed line is skipped, not fatal.
        }
      }
    });
    stream.on("close", () => {
      reading = false;
    });
    stream.on("error", (err) => {
      reading = false;
      onError(`${label} read failed: ${err.message}`);
    });
  }, 500);

  return () => clearInterval(timer);
}

/**
 * Strip control characters from anything an attacker can influence — process
 * arguments, usernames, object names. Without this a crafted container name
 * reaches both the operator's terminal and an LLM prompt with its escapes
 * intact.
 */
export function clean(value: unknown, max = 400): string | undefined {
  if (typeof value !== "string") return undefined;
  let out = "";
  for (const ch of value) {
    const code = ch.codePointAt(0);
    if (code !== undefined && code >= 0x20 && code !== 0x7f) out += ch;
    if (out.length >= max) break;
  }
  return out || undefined;
}
