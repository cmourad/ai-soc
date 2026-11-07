import type { AnalystChatModelOption, StageConfig } from "@aisoc/shared";
import { getSecret } from "../crypto.js";
import { getSettings } from "../settings.js";

/** Strictly a provider model identifier, never free-form prompt text. */
const MODEL_NAME = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/;

export function resolveAnalystModel(model: string): {
  config: StageConfig;
  model: string;
} | null {
  const settings = getSettings();
  const requested = model.trim();
  if (requested === "firstTriage") {
    return { config: settings.firstTriage, model: settings.firstTriage.model };
  }
  if (requested === "secondTriage") {
    return { config: settings.secondTriage, model: settings.secondTriage.model };
  }
  const name = requested.startsWith("live:") ? requested.slice("live:".length) : requested;
  if (!MODEL_NAME.test(name)) return null;
  return { config: { ...settings.firstTriage, model: name }, model: name };
}

/** Configured analyst stages plus valid models advertised by the first-tier endpoint. */
export async function listAnalystModels(): Promise<AnalystChatModelOption[]> {
  const settings = getSettings();
  const options: AnalystChatModelOption[] = [
    {
      id: "firstTriage",
      label: `first tier · ${settings.firstTriage.model}`,
      model: settings.firstTriage.model,
      provider: settings.firstTriage.provider,
      source: "stage",
    },
    {
      id: "secondTriage",
      label: `second tier · ${settings.secondTriage.model}`,
      model: settings.secondTriage.model,
      provider: settings.secondTriage.provider,
      source: "stage",
    },
  ];

  const first = settings.firstTriage;
  if (first.provider !== "openai-compatible") return options;
  const modelsUrl = first.endpoint.replace(/\/chat\/completions$/, "/models");
  try {
    const headers: Record<string, string> = {};
    const apiKey = getSecret(first.apiKeySecret);
    if (apiKey) headers.authorization = `Bearer ${apiKey}`;
    const response = await fetch(modelsUrl, {
      headers,
      signal: AbortSignal.timeout(2_000),
    });
    if (!response.ok) return options;
    const body = (await response.json()) as { data?: { id?: string }[] };
    for (const entry of body.data ?? []) {
      if (typeof entry.id !== "string" || !MODEL_NAME.test(entry.id)) continue;
      if (options.some((option) => option.model === entry.id)) continue;
      options.push({
        id: `live:${entry.id}`,
        label: `loaded · ${entry.id}`,
        model: entry.id,
        provider: first.provider,
        source: "live",
      });
    }
  } catch {
    // Discovery is a convenience; configured stages remain usable.
  }
  return options;
}
