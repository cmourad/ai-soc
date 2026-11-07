import { Card, Field, Input, SectionTitle, Switch } from "@/components/ui/primitives";
import { useStore } from "@/store";
import type { SettingsSectionProps } from "./shared";
import { SecretField } from "./shared";

export function IntelSection({ draft, patch }: SettingsSectionProps) {
  const secrets = useStore((s) => s.secrets);

  return (
    <Card className="flex flex-col gap-3">
      <SectionTitle>Threat intelligence</SectionTitle>
      <Switch
        checked={draft.intel.enabled}
        onCheckedChange={(enabled) => patch("intel", { enabled })}
        label="Enrich alerts with reputation data"
        hint="Attaches country, ASN, and a 0–100 reputation to the remote indicator."
      />
      <Switch
        checked={draft.intel.useLocalFeed}
        onCheckedChange={(useLocalFeed) => patch("intel", { useLocalFeed })}
        label="Use the bundled offline feed"
        hint="Keeps enrichment and the threat map working with no keys and no outbound requests."
      />
      <Field label="Cache (minutes)" hint="How long a verdict is reused before refetching.">
        <Input
          type="number"
          min="1"
          value={draft.intel.cacheMinutes}
          onChange={(event) => patch("intel", { cacheMinutes: Number(event.target.value) })}
        />
      </Field>
      <SecretField
        label="VirusTotal API key"
        name={draft.intel.virusTotalSecret}
        present={Boolean(secrets[draft.intel.virusTotalSecret])}
        hint="Optional. Without it the bundled feed is used and nothing leaves the machine."
      />
      <SecretField
        label="AbuseIPDB API key"
        name={draft.intel.abuseIpdbSecret}
        present={Boolean(secrets[draft.intel.abuseIpdbSecret])}
        hint="Optional. Used for IP indicators only."
      />
    </Card>
  );
}
