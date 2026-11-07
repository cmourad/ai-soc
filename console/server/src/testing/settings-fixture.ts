import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * A triage stage pointed at a port that refuses immediately, so a test that
 * unexpectedly reaches the network fails fast instead of hanging on a timeout.
 */
export function llmStage(model: string): Record<string, unknown> {
  return {
    provider: "openai-compatible",
    endpoint: "http://127.0.0.1:9/v1/chat/completions",
    model,
    temperature: 0.1,
    maxTokens: 512,
    timeoutMs: 1_000,
    apiKeySecret: "",
  };
}

/**
 * Throwaway data dir with the settings a test needs, installed before anything
 * imports the modules under test — settings are read at import time, so callers
 * pull their subject in with a dynamic import after this returns.
 */
export function useTemporaryDataDir(prefix: string, settings: Record<string, unknown>): string {
  const dataDir = mkdtempSync(join(tmpdir(), prefix));
  writeFileSync(join(dataDir, "settings.json"), JSON.stringify(settings));
  process.env.AISOC_DATA_DIR = dataDir;
  return dataDir;
}
