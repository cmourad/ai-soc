import { Card, Field, ListEditor, SectionTitle, Select } from "@/components/ui/primitives";
import type { SettingsSectionProps } from "./shared";
import { SEVERITY_OPTIONS } from "./shared";

export function EscalationSection({ draft, patch }: SettingsSectionProps) {
  return (
    <Card className="flex flex-col gap-3">
      <SectionTitle>Escalation rules</SectionTitle>
      <Field
        label="Straight to second triage at or below severity"
        hint="Critical alerts skip the small model entirely."
      >
        <Select
          value={String(draft.escalation.directToSecondAtOrBelowSeverity)}
          onValueChange={(value) =>
            patch("escalation", { directToSecondAtOrBelowSeverity: Number(value) })
          }
          options={[
            { value: "0", label: "never — always start at first triage" },
            ...SEVERITY_OPTIONS,
          ]}
        />
      </Field>
      <ListEditor
        label="Deterministic auto-block signatures"
        hint="Regex against the signature. Matches resolve as BLOCK without consulting any model — immune to prompt injection and to model downtime."
        values={draft.escalation.autoBlockPatterns}
        onChange={(autoBlockPatterns) => patch("escalation", { autoBlockPatterns })}
        placeholder="^ET (DROP|CINS) "
      />
    </Card>
  );
}
