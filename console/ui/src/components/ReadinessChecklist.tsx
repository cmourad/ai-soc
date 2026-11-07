import type { VpnCheck } from "@aisoc/shared";
import { AlertTriangle, Check, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Button, SectionTitle } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";

/**
 * Independent preconditions, all shown at once with the exact fix — failing one
 * at a time makes an operator run the same setup four times.
 *
 * `signature` is whatever would change the answer (a mode, a device count); the
 * list re-checks when it changes.
 */
export function ReadinessChecklist({
  load,
  signature,
  successText,
}: {
  load: () => Promise<VpnCheck[]>;
  signature: string;
  successText: string;
}) {
  const [checks, setChecks] = useState<VpnCheck[]>([]);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(() => {
    setLoading(true);
    load()
      .then(setChecks)
      .catch(() => setChecks([]))
      .finally(() => setLoading(false));
  }, [load]);

  useEffect(() => {
    void signature;
    refresh();
  }, [signature, refresh]);

  const blocking = checks.filter((check) => !check.ok);

  return (
    <div>
      <div className="flex items-center gap-2">
        <SectionTitle>Readiness</SectionTitle>
        <Button size="sm" variant="ghost" className="mb-2 ml-auto" onClick={refresh}>
          <RefreshCw className={cn("h-3 w-3", loading && "animate-spin")} />
          re-check
        </Button>
      </div>
      <div className="flex flex-col gap-1">
        {checks.map((check) => (
          <div
            key={check.id}
            className={cn(
              "rounded-sm border px-2 py-1.5",
              check.ok ? "border-edge bg-panel" : "border-[#7a5a2d] bg-[#2a2113]",
            )}
          >
            <div className="flex items-center gap-2">
              {check.ok ? (
                <Check className="h-3 w-3 shrink-0 text-ignore" />
              ) : (
                <AlertTriangle className="h-3 w-3 shrink-0 text-sev2" />
              )}
              <span className={cn("text-[11px]", check.ok ? "text-ink" : "text-sev2")}>
                {check.label}
              </span>
            </div>
            <p className="mt-0.5 pl-5 text-[10px] leading-snug text-ink-dim">{check.detail}</p>
            {check.fix ? (
              <pre className="mt-1 ml-5 overflow-x-auto rounded-sm border border-edge bg-shell p-1.5 font-mono text-[10px] text-ink">
                {check.fix}
              </pre>
            ) : null}
          </div>
        ))}
        {checks.length === 0 && !loading ? (
          <p className="text-[11px] text-ink-dim">No checks returned.</p>
        ) : null}
        {blocking.length === 0 && checks.length > 0 ? (
          <p className="text-[10px] text-ignore">{successText}</p>
        ) : null}
      </div>
    </div>
  );
}
