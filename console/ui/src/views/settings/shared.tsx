import type { FirstTriageConfig, SecondTriageConfig, Settings, TriageStage } from "@aisoc/shared";
import { useState } from "react";
import { Button, Card, Field, Input, SectionTitle, Select } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { severityLabel } from "@/lib/utils";
import { useStore } from "@/store";

/**
 * The pieces every settings section shares: the props contract, the two editors
 * that appear in more than one domain, and the option lists that must read the
 * same wherever they are offered.
 */

/**
 * Sections never own settings state. The view holds one draft and hands down a
 * patcher, so "unsaved changes" and discard stay a single decision rather than
 * sixteen independent ones.
 */
export type SettingsSectionProps = {
  draft: Settings;
  patch: <K extends keyof Settings>(key: K, value: Partial<Settings[K]>) => void;
};

export const PROVIDERS = [
  { value: "openai-compatible", label: "OpenAI-compatible (llama.cpp, vLLM, Ollama)" },
  { value: "codex-proxy", label: "Codex CLI via openaiserver proxy" },
  { value: "anthropic", label: "Anthropic (cloud)" },
];

export const ANTHROPIC_MODELS = [
  { value: "claude-opus-5", label: "claude-opus-5 (most capable)" },
  { value: "claude-sonnet-5", label: "claude-sonnet-5 (balanced)" },
  { value: "claude-haiku-4-5", label: "claude-haiku-4-5 (fastest)" },
  { value: "claude-fable-5", label: "claude-fable-5 (frontier)" },
];

export const SEVERITY_OPTIONS = [1, 2, 3, 4].map((severity) => ({
  value: String(severity),
  label: `${severity} — ${severityLabel(severity)} and worse`,
}));

export const STAGE_OPTIONS: TriageStage[] = ["needs_human", "resolved", "second_triage"];

export const AUTONOMY_MODES: {
  value: Settings["response"]["autonomy"];
  label: string;
  hint: string;
}[] = [
  {
    value: "manual",
    label: "manual — everything waits",
    hint: "Every proposed action waits for a human. Nothing is ever applied on its own.",
  },
  {
    value: "guarded",
    label: "guarded — self-execute when confident",
    hint: "High-confidence actions execute themselves, the rest wait. Guardrails and the always-confirm list still apply.",
  },
  {
    value: "full",
    label: "full — execute everything proposed",
    hint: "Everything the engine proposes executes. Guardrails are still enforced before execution.",
  },
];

export const RESPONSE_TYPES: {
  value: Settings["response"]["guardrails"]["alwaysConfirm"][number];
  label: string;
}[] = [
  { value: "block_ip", label: "block IP" },
  { value: "block_domain", label: "block domain" },
  { value: "quarantine_file", label: "quarantine file" },
  { value: "isolate_host", label: "isolate host" },
  { value: "kill_process", label: "kill process" },
];

export const GROUP_DIMENSIONS: {
  value: Settings["incidents"]["groupBy"][number];
  label: string;
}[] = [
  { value: "scenario", label: "scenario" },
  { value: "remote_ip", label: "remote IP" },
  { value: "asset", label: "asset" },
  { value: "hash", label: "hash" },
  { value: "signature", label: "signature" },
];

export const NOTIFICATION_KINDS: {
  value: Settings["notifications"]["telegramKinds"][number];
  label: string;
  hint: string;
}[] = [
  { value: "detection", label: "Detections", hint: "The engine scored something as malicious." },
  { value: "response", label: "Response", hint: "An action was applied, held, or undone." },
  { value: "incident", label: "Incidents", hint: "Alerts correlated into a new incident." },
  { value: "asset", label: "Hosts", hint: "A host crossed the risk threshold or was isolated." },
  { value: "oncall", label: "On-call", hint: "A page was raised or escalated." },
  { value: "system", label: "System", hint: "Console and pipeline health." },
];

export function SecretField({
  label,
  name,
  hint,
  present,
}: {
  label: string;
  name: string;
  hint?: string;
  present: boolean;
}) {
  const [value, setValue] = useState("");
  const pushToast = useStore((s) => s.pushToast);

  return (
    <Field label={label} hint={hint}>
      <div className="flex gap-1.5">
        <Input
          type="password"
          value={value}
          placeholder={present ? "•••••••• stored (encrypted)" : "not set"}
          onChange={(event) => setValue(event.target.value)}
          autoComplete="off"
        />
        <Button
          size="md"
          variant="secondary"
          disabled={!value}
          onClick={() => {
            api
              .saveSecret(name, value)
              .then(() => {
                setValue("");
                pushToast("success", `${label} stored.`);
              })
              .catch((error: Error) => pushToast("error", error.message));
          }}
        >
          store
        </Button>
        {present ? (
          <Button
            size="md"
            variant="ghost"
            onClick={() =>
              api
                .saveSecret(name, "")
                .then(() => pushToast("info", `${label} cleared.`))
                .catch((error: Error) => pushToast("error", error.message))
            }
          >
            clear
          </Button>
        ) : null}
      </div>
    </Field>
  );
}

export function StageEditor<T extends FirstTriageConfig | SecondTriageConfig>({
  title,
  config,
  onChange,
  secretName,
  secretPresent,
  children,
}: {
  title: string;
  config: T;
  onChange: (patch: Partial<T>) => void;
  secretName: string;
  secretPresent: boolean;
  children?: React.ReactNode;
}) {
  const isAnthropic = config.provider === "anthropic";
  const isCodexProxy = config.provider === "codex-proxy";
  // Only llama.cpp-style endpoints take sampling parameters: Claude rejects
  // them outright, and codex exposes none.
  const takesSampling = !isAnthropic && !isCodexProxy;

  const defaultModelFor = (provider: string): string => {
    if (provider === "anthropic") return "claude-opus-5";
    if (provider === "codex-proxy") return "gpt-5.6-luna";
    return config.model;
  };
  const defaultEndpointFor = (provider: string): string =>
    provider === "codex-proxy" ? "http://127.0.0.1:8080/v1/chat/completions" : config.endpoint;

  return (
    <Card className="flex flex-col gap-3">
      <SectionTitle>{title}</SectionTitle>

      <Field label="Provider">
        <Select
          value={config.provider}
          onValueChange={(value) =>
            onChange({
              provider: value as T["provider"],
              model: defaultModelFor(value),
              endpoint: defaultEndpointFor(value),
              apiKeySecret: value === "codex-proxy" ? "codexProxy.token" : config.apiKeySecret,
            } as Partial<T>)
          }
          options={PROVIDERS}
        />
      </Field>

      {isAnthropic ? (
        <Field label="Model">
          <Select
            value={config.model}
            onValueChange={(model) => onChange({ model } as Partial<T>)}
            options={ANTHROPIC_MODELS}
          />
        </Field>
      ) : (
        <div className="grid grid-cols-2 gap-3">
          <Field label="Endpoint">
            <Input
              value={config.endpoint}
              onChange={(event) => onChange({ endpoint: event.target.value } as Partial<T>)}
            />
          </Field>
          <Field label="Model">
            <Input
              value={config.model}
              onChange={(event) => onChange({ model: event.target.value } as Partial<T>)}
            />
          </Field>
        </div>
      )}

      <div className="grid grid-cols-3 gap-3">
        {!takesSampling ? (
          <Field
            label="Temperature"
            hint={
              isAnthropic
                ? "Not sent — current Claude models reject sampling parameters."
                : "Not sent — codex exposes no sampling parameters."
            }
          >
            <Input value="n/a" disabled />
          </Field>
        ) : (
          <Field label="Temperature">
            <Input
              type="number"
              step="0.05"
              min="0"
              max="2"
              value={config.temperature}
              onChange={(event) =>
                onChange({ temperature: Number(event.target.value) } as Partial<T>)
              }
            />
          </Field>
        )}
        <Field label="Max tokens">
          <Input
            type="number"
            min="64"
            value={config.maxTokens}
            onChange={(event) => onChange({ maxTokens: Number(event.target.value) } as Partial<T>)}
          />
        </Field>
        <Field label="Timeout (s)">
          <Input
            type="number"
            min="1"
            value={Math.round(config.timeoutMs / 1000)}
            onChange={(event) =>
              onChange({ timeoutMs: Number(event.target.value) * 1000 } as Partial<T>)
            }
          />
        </Field>
      </div>

      <SecretField
        label={isCodexProxy ? "Proxy bearer token" : "API key"}
        name={config.apiKeySecret || secretName}
        present={secretPresent}
        hint={
          isAnthropic
            ? "Falls back to ANTHROPIC_API_KEY in the backend environment when unset."
            : isCodexProxy
              ? "Bearer token configured on your proxy — the proxy rejects unauthenticated calls."
              : "Only needed if your local endpoint requires a bearer token."
        }
      />

      {isCodexProxy ? (
        <p className="text-[10px] leading-snug text-ink-dim">
          The proxy forwards only the last user message, so the system prompt is folded into it.
          Codex constrains the verdict shape at the sampler via <code>--output-schema</code>, and
          reports no token usage — the LLM activity panel shows both facts per call.
        </p>
      ) : null}

      {children}
    </Card>
  );
}
