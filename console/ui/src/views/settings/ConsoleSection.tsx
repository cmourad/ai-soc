import { Card, Field, Input, SectionTitle } from "@/components/ui/primitives";
import { useStore } from "@/store";

export function ConsoleSection() {
  const analyst = useStore((s) => s.analyst);
  const setAnalyst = useStore((s) => s.setAnalyst);

  return (
    <Card className="flex flex-col gap-3">
      <SectionTitle>This console</SectionTitle>
      <Field label="Analyst name" hint="Recorded on overrides, notes, and acknowledgements.">
        <Input value={analyst} onChange={(event) => setAnalyst(event.target.value)} />
      </Field>
    </Card>
  );
}
