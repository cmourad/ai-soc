import { Card, Field, Input, ListEditor, SectionTitle, Switch } from "@/components/ui/primitives";
import type { SettingsSectionProps } from "./shared";

export function DetectionSection({ draft, patch }: SettingsSectionProps) {
  return (
    <Card className="flex flex-col gap-3">
      <SectionTitle>Detection engine</SectionTitle>
      <p className="-mt-1 text-[10px] leading-snug text-ink-dim">
        Runs on every event before any model is consulted. Its hits are what response actions and
        incident correlation are built from, so a model being down or manipulated never costs you
        detection.
      </p>
      <Switch
        checked={draft.detection.enabled}
        onCheckedChange={(enabled) => patch("detection", { enabled })}
        label="Detection engine enabled"
        hint="Turning this off leaves the LLM as the only detection layer — not recommended."
      />
      <div className="grid grid-cols-3 gap-3">
        <Switch
          checked={draft.detection.iocEnabled}
          onCheckedChange={(iocEnabled) => patch("detection", { iocEnabled })}
          label="Indicator matching"
          hint="Curated IP, domain, and hash feeds."
        />
        <Switch
          checked={draft.detection.rulesEnabled}
          onCheckedChange={(rulesEnabled) => patch("detection", { rulesEnabled })}
          label="Rules"
          hint="Sigma-style field predicates."
        />
        <Switch
          checked={draft.detection.heuristicsEnabled}
          onCheckedChange={(heuristicsEnabled) => patch("detection", { heuristicsEnabled })}
          label="Behavioural heuristics"
          hint="Beaconing, scanning, volume, mass writes."
        />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <Field
          label="Open an alert at score"
          hint="An event scoring at or above this becomes an alert even if the sensor called it low severity."
        >
          <Input
            type="number"
            min="1"
            max="100"
            value={draft.detection.alertAtScore}
            onChange={(event) => patch("detection", { alertAtScore: Number(event.target.value) })}
          />
        </Field>
        <Field
          label="Call it malicious at score"
          hint="At or above this, an IGNORE verdict from a model is floored to WATCH."
        >
          <Input
            type="number"
            min="1"
            max="100"
            value={draft.detection.maliciousAtScore}
            onChange={(event) =>
              patch("detection", { maliciousAtScore: Number(event.target.value) })
            }
          />
        </Field>
      </div>
      <ListEditor
        label="Muted rule ids"
        hint="Rules that stop contributing to scores. Their hits are no longer produced at all."
        values={draft.detection.mutedRuleIds}
        onChange={(mutedRuleIds) => patch("detection", { mutedRuleIds })}
        placeholder="AISOC-DISC-0001"
      />
    </Card>
  );
}
