import type { Settings } from "@aisoc/shared";
import { RotateCcw, Save } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { useStore } from "@/store";
import { ConsoleSection } from "./settings/ConsoleSection";
import { CorrelationSection } from "./settings/CorrelationSection";
import { DetectionSection } from "./settings/DetectionSection";
import { EscalationSection } from "./settings/EscalationSection";
import { IngestSection } from "./settings/IngestSection";
import { IntelSection } from "./settings/IntelSection";
import { NotificationsSection } from "./settings/NotificationsSection";
import { OncallSection } from "./settings/OncallSection";
import { RemoteAccessSection } from "./settings/RemoteAccessSection";
import { ResponseSection } from "./settings/ResponseSection";
import { SiteSection } from "./settings/SiteSection";
import { SmtpSection } from "./settings/SmtpSection";
import { TelegramSection } from "./settings/TelegramSection";
import { TriageSection } from "./settings/TriageSection";
import { VpnSection } from "./settings/VpnSection";

/**
 * Sixteen configuration domains behind one save.
 *
 * The view owns exactly one thing: a draft of the whole settings object, and
 * the decision to keep or discard it. Every domain is a section component that
 * reads the draft and patches its own key — which is what keeps "unsaved
 * changes" honest, because a half-saved console is a security control in an
 * unknown state.
 */
export function SettingsView() {
  const settings = useStore((s) => s.settings);
  const pushToast = useStore((s) => s.pushToast);

  const [draft, setDraft] = useState<Settings>(settings);
  const [saving, setSaving] = useState(false);

  useEffect(() => setDraft(settings), [settings]);

  const dirty = useMemo(
    () => JSON.stringify(draft) !== JSON.stringify(settings),
    [draft, settings],
  );

  const patch = <K extends keyof Settings>(key: K, value: Partial<Settings[K]>) =>
    setDraft((prev) => ({ ...prev, [key]: { ...prev[key], ...value } }));

  const save = () => {
    setSaving(true);
    api
      .saveSettings(draft)
      .then(() => pushToast("success", "Settings saved."))
      .catch((error: Error) => pushToast("error", error.message))
      .finally(() => setSaving(false));
  };

  const section = { draft, patch };

  return (
    <div className="flex h-full flex-col">
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto flex max-w-5xl flex-col gap-4 p-4 pb-24">
          <IngestSection {...section} />
          <TriageSection {...section} />
          <DetectionSection {...section} />
          <ResponseSection {...section} />
          <IntelSection {...section} />
          <CorrelationSection {...section} />
          <EscalationSection {...section} />
          <TelegramSection {...section} />
          <SmtpSection {...section} />
          <OncallSection {...section} />
          <NotificationsSection {...section} />
          <VpnSection {...section} />
          <RemoteAccessSection {...section} />
          <SiteSection {...section} />
          <ConsoleSection />
        </div>
      </div>

      {dirty ? (
        <div className="flex shrink-0 items-center gap-3 border-t border-status bg-[#04395e] px-4 py-2">
          <span className="text-[11px]">Unsaved changes</span>
          <Button variant="primary" onClick={save} disabled={saving} className="ml-auto">
            <Save className="h-3 w-3" />
            {saving ? "saving…" : "save settings"}
          </Button>
          <Button variant="ghost" onClick={() => setDraft(settings)} disabled={saving}>
            <RotateCcw className="h-3 w-3" />
            discard
          </Button>
        </div>
      ) : null}
    </div>
  );
}
