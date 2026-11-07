import type { Settings } from "@aisoc/shared";
import { Card, Field, Input, SectionTitle, Select } from "@/components/ui/primitives";
import type { SettingsSectionProps } from "./shared";
import { SEVERITY_OPTIONS } from "./shared";

export function IngestSection({ draft, patch }: SettingsSectionProps) {
  return (
    <Card className="flex flex-col gap-3">
      <SectionTitle>Ingest</SectionTitle>
      <div className="grid grid-cols-2 gap-3">
        <Field
          label="Source"
          hint="Seeded traffic for demos; eve.json tails the live Suricata sensor."
        >
          <Select
            value={draft.ingest.source}
            onValueChange={(source) =>
              patch("ingest", { source: source as Settings["ingest"]["source"] })
            }
            options={[
              { value: "seed", label: "seeded demo traffic" },
              { value: "eve", label: "Suricata eve.json" },
            ]}
          />
        </Field>
        <Field label="Events per second" hint="Seeded source only.">
          <Input
            type="number"
            step="0.5"
            min="0.1"
            value={draft.ingest.eventsPerSecond}
            onChange={(event) => patch("ingest", { eventsPerSecond: Number(event.target.value) })}
          />
        </Field>
      </div>
      <Field
        label="eve.json path"
        hint="Relative paths resolve against the repository root; separate sensor paths with commas."
      >
        <Input
          value={draft.ingest.evePath}
          onChange={(event) => patch("ingest", { evePath: event.target.value })}
        />
      </Field>
      <Field
        label="Triage severity threshold"
        hint="Events worse than this enter the queue; the rest are counted only."
      >
        <Select
          value={String(draft.ingest.maxTriageSeverity)}
          onValueChange={(value) => patch("ingest", { maxTriageSeverity: Number(value) })}
          options={SEVERITY_OPTIONS}
        />
      </Field>
    </Card>
  );
}
