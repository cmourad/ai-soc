import { Field, Input, ListEditor, Select, Switch } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import { useStore } from "@/store";
import type { SettingsSectionProps } from "./shared";
import { SEVERITY_OPTIONS, StageEditor } from "./shared";

export function TriageSection({ draft, patch }: SettingsSectionProps) {
  const secrets = useStore((s) => s.secrets);

  return (
    <>
      <StageEditor
        title="First triage"
        config={draft.firstTriage}
        onChange={(value) => patch("firstTriage", value)}
        secretName="firstTriage.apiKey"
        secretPresent={Boolean(secrets["firstTriage.apiKey"])}
      >
        <div className="grid grid-cols-2 gap-3">
          <Field
            label="Auto-close confidence"
            hint="At or above this, a first-tier verdict closes without escalating."
          >
            <Input
              type="number"
              step="0.05"
              min="0"
              max="1"
              value={draft.firstTriage.autoCloseConfidence}
              onChange={(event) =>
                patch("firstTriage", { autoCloseConfidence: Number(event.target.value) })
              }
            />
          </Field>
          <Field
            label="Escalate below confidence"
            hint="Below this, always hand off to second triage."
          >
            <Input
              type="number"
              step="0.05"
              min="0"
              max="1"
              value={draft.firstTriage.escalateBelowConfidence}
              onChange={(event) =>
                patch("firstTriage", { escalateBelowConfidence: Number(event.target.value) })
              }
            />
          </Field>
        </div>
        <Field label="Escalate at or below severity">
          <Select
            value={String(draft.firstTriage.escalateAtOrBelowSeverity)}
            onValueChange={(value) =>
              patch("firstTriage", { escalateAtOrBelowSeverity: Number(value) })
            }
            options={[{ value: "0", label: "never on severity alone" }, ...SEVERITY_OPTIONS]}
          />
        </Field>
        <ListEditor
          label="Escalate these categories"
          hint="Suricata category strings, matched exactly."
          values={draft.firstTriage.escalateCategories}
          onChange={(escalateCategories) => patch("firstTriage", { escalateCategories })}
          placeholder="Web Application Attack"
        />
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] text-ink">Verdicts that always escalate:</span>
          {(["BLOCK", "WATCH", "IGNORE"] as const).map((verdict) => {
            const on = draft.firstTriage.escalateVerdicts.includes(verdict);
            return (
              <button
                key={verdict}
                type="button"
                onClick={() =>
                  patch("firstTriage", {
                    escalateVerdicts: on
                      ? draft.firstTriage.escalateVerdicts.filter((v) => v !== verdict)
                      : [...draft.firstTriage.escalateVerdicts, verdict],
                  })
                }
                className={cn(
                  "rounded-sm border px-2 py-0.5 font-mono text-[10px]",
                  on ? "border-status bg-active text-ink" : "border-edge text-ink-dim",
                )}
              >
                {verdict}
              </button>
            );
          })}
        </div>
      </StageEditor>

      <StageEditor
        title="Second triage"
        config={draft.secondTriage}
        onChange={(value) => patch("secondTriage", value)}
        secretName="secondTriage.apiKey"
        secretPresent={Boolean(secrets["secondTriage.apiKey"])}
      >
        <Switch
          label="Second-tier verdicts may auto-resolve"
          hint="Off means every escalated alert waits for human confirmation."
          checked={draft.secondTriage.autoResolve}
          onCheckedChange={(autoResolve) => patch("secondTriage", { autoResolve })}
        />
        <Field
          label="Auto-resolve confidence"
          hint="Below this, an escalated alert still lands in needs-a-human."
        >
          <Input
            type="number"
            step="0.05"
            min="0"
            max="1"
            disabled={!draft.secondTriage.autoResolve}
            value={draft.secondTriage.autoResolveConfidence}
            onChange={(event) =>
              patch("secondTriage", { autoResolveConfidence: Number(event.target.value) })
            }
          />
        </Field>

        <div className="grid grid-cols-2 gap-3">
          <Field
            label="Alerts per model call"
            hint="Batching amortises per-call startup, but puts several alerts' attacker-controlled text in one context. Set to 1 for strict per-alert isolation."
          >
            <Input
              type="number"
              min="1"
              max="20"
              value={draft.secondTriage.batchSize}
              onChange={(event) => patch("secondTriage", { batchSize: Number(event.target.value) })}
            />
          </Field>
          <Field
            label="Batch wait (ms)"
            hint="How long a partial batch waits for company before it is sent anyway."
          >
            <Input
              type="number"
              min="0"
              step="250"
              disabled={draft.secondTriage.batchSize <= 1}
              value={draft.secondTriage.batchLingerMs}
              onChange={(event) =>
                patch("secondTriage", { batchLingerMs: Number(event.target.value) })
              }
            />
          </Field>
        </div>
      </StageEditor>
    </>
  );
}
