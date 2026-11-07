import { CheckCircle2, Info, X, XCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import { useStore } from "@/store";

const ICONS = { info: Info, success: CheckCircle2, error: XCircle };
const TONES = {
  info: "border-edge bg-panel text-ink",
  success: "border-[#2d5a3d] bg-[#1e3226] text-[#a8e6a3]",
  error: "border-[#5a2d2d] bg-[#321e1e] text-[#f5b8b8]",
};

export function Toasts() {
  const toasts = useStore((s) => s.toasts);
  const dismiss = useStore((s) => s.dismissToast);

  return (
    <div className="pointer-events-none fixed right-3 bottom-8 z-50 flex w-80 flex-col gap-2">
      {toasts.map((toast) => {
        const Icon = ICONS[toast.level];
        return (
          <div
            key={toast.id}
            className={cn(
              "row-in pointer-events-auto flex items-start gap-2 rounded-sm border px-3 py-2 text-xs shadow-lg",
              TONES[toast.level],
            )}
          >
            <Icon className="mt-px h-3.5 w-3.5 shrink-0" />
            <span className="flex-1 leading-snug">{toast.message}</span>
            <button
              type="button"
              onClick={() => dismiss(toast.id)}
              className="text-ink-dim hover:text-ink"
              aria-label="Dismiss"
            >
              <X className="h-3 w-3" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
