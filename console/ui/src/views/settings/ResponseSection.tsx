import { Card, Field, Input, SectionTitle, Select, Switch } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import type { SettingsSectionProps } from "./shared";
import { AUTONOMY_MODES, RESPONSE_TYPES } from "./shared";

export function ResponseSection({ draft, patch }: SettingsSectionProps) {
  return (
    <Card className="flex flex-col gap-3">
      <SectionTitle>Automated response</SectionTitle>
      <Switch
        checked={draft.response.enabled}
        onCheckedChange={(enabled) => patch("response", { enabled })}
        label="Response enabled"
        hint="With this off, nothing is ever proposed or applied."
      />

      <Field label="AI autonomy" hint="Guardrails are evaluated before this, never after.">
        <div className="grid gap-1.5">
          {AUTONOMY_MODES.map((mode) => (
            <button
              key={mode.value}
              type="button"
              onClick={() => patch("response", { autonomy: mode.value })}
              className={cn(
                "rounded-sm border px-2 py-1.5 text-left transition-colors",
                draft.response.autonomy === mode.value
                  ? "border-status bg-active"
                  : "border-edge hover:bg-hover",
              )}
            >
              <span className="flex items-center gap-2">
                <span
                  className={cn(
                    "h-2 w-2 rounded-full",
                    draft.response.autonomy === mode.value ? "bg-status" : "bg-edge",
                  )}
                />
                <span className="text-[11px] font-medium text-ink">{mode.label}</span>
              </span>
              <span className="mt-0.5 block pl-4 text-[10px] leading-snug text-ink-dim">
                {mode.hint}
              </span>
            </button>
          ))}
        </div>
      </Field>

      <Field
        label="Execution"
        hint="Simulate records the exact command without running it. nftables runs block and isolate for real via argv — no shell."
      >
        <Select
          value={draft.response.execution}
          onValueChange={(execution) =>
            patch("response", { execution: execution as "simulate" | "nftables" })
          }
          options={[
            { value: "simulate", label: "simulate — record the command only" },
            { value: "nftables", label: "nftables — apply blocks and isolation for real" },
          ]}
        />
      </Field>

      <SectionTitle>Guardrails</SectionTitle>
      <Switch
        checked={draft.response.guardrails.protectPrivateRanges}
        onCheckedChange={(protectPrivateRanges) =>
          patch("response", {
            guardrails: { ...draft.response.guardrails, protectPrivateRanges },
          })
        }
        label="Never act on private ranges"
        hint="RFC1918, loopback, and link-local addresses are refused."
      />
      <Switch
        checked={draft.response.guardrails.respectAllowlist}
        onCheckedChange={(respectAllowlist) =>
          patch("response", {
            guardrails: { ...draft.response.guardrails, respectAllowlist },
          })
        }
        label="Never act on allowlisted indicators"
        hint="Refused even under full autonomy."
      />
      <div className="grid grid-cols-3 gap-3">
        <Field label="Guarded: min score">
          <Input
            type="number"
            min="0"
            max="100"
            value={draft.response.guardrails.autoExecuteAtScore}
            onChange={(event) =>
              patch("response", {
                guardrails: {
                  ...draft.response.guardrails,
                  autoExecuteAtScore: Number(event.target.value),
                },
              })
            }
          />
        </Field>
        <Field label="Guarded: min confidence">
          <Input
            type="number"
            step="0.05"
            min="0"
            max="1"
            value={draft.response.guardrails.autoExecuteAtConfidence}
            onChange={(event) =>
              patch("response", {
                guardrails: {
                  ...draft.response.guardrails,
                  autoExecuteAtConfidence: Number(event.target.value),
                },
              })
            }
          />
        </Field>
        <Field label="Auto actions per hour">
          <Input
            type="number"
            min="0"
            value={draft.response.guardrails.maxAutoActionsPerHour}
            onChange={(event) =>
              patch("response", {
                guardrails: {
                  ...draft.response.guardrails,
                  maxAutoActionsPerHour: Number(event.target.value),
                },
              })
            }
          />
        </Field>
      </div>
      <Field
        label="Always require confirmation for"
        hint="These wait for a human under every autonomy setting."
      >
        <div className="flex flex-wrap gap-1">
          {RESPONSE_TYPES.map((type) => {
            const on = draft.response.guardrails.alwaysConfirm.includes(type.value);
            return (
              <button
                key={type.value}
                type="button"
                onClick={() =>
                  patch("response", {
                    guardrails: {
                      ...draft.response.guardrails,
                      alwaysConfirm: on
                        ? draft.response.guardrails.alwaysConfirm.filter(
                            (entry) => entry !== type.value,
                          )
                        : [...draft.response.guardrails.alwaysConfirm, type.value],
                    },
                  })
                }
                className={cn(
                  "rounded-sm border px-2 py-0.5 text-[10px] transition-colors",
                  on ? "border-edge bg-active text-ink" : "border-edge text-ink-dim",
                )}
              >
                {type.label}
              </button>
            );
          })}
        </div>
      </Field>
    </Card>
  );
}
