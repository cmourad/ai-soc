import { Card, Field, Input, ListEditor, SectionTitle } from "@/components/ui/primitives";
import type { SettingsSectionProps } from "./shared";

export function SiteSection({ draft, patch }: SettingsSectionProps) {
  return (
    <Card className="flex flex-col gap-3">
      <SectionTitle>Site</SectionTitle>
      <Field label="Site name" hint="Labels the defended network on the threat map and in reports.">
        <Input
          value={draft.site.name}
          onChange={(event) => patch("site", { name: event.target.value })}
        />
      </Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Latitude">
          <Input
            type="number"
            step="0.0001"
            value={draft.site.lat}
            onChange={(event) => patch("site", { lat: Number(event.target.value) })}
          />
        </Field>
        <Field label="Longitude">
          <Input
            type="number"
            step="0.0001"
            value={draft.site.lon}
            onChange={(event) => patch("site", { lon: Number(event.target.value) })}
          />
        </Field>
      </div>
      <ListEditor
        label="Home networks"
        hint="Guardrails refuse any block action whose target falls inside these."
        values={draft.site.homeNetworks}
        onChange={(homeNetworks) => patch("site", { homeNetworks })}
        placeholder="192.0.2.0/24"
      />
    </Card>
  );
}
