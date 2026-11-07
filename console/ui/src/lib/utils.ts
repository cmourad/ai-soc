import { SEVERITY_LABEL } from "@aisoc/shared";
import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

export function timeOf(iso: string): string {
  const date = new Date(iso);
  return date.toLocaleTimeString("en-GB", { hour12: false });
}

export function shortAge(iso: string, now = Date.now()): string {
  const seconds = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

export function severityLabel(severity: number): string {
  return SEVERITY_LABEL[severity] ?? "unknown";
}

/** Coarse elapsed time for timelines, where the exact second is noise. */
export function relativeTime(iso: string): string {
  const seconds = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1_000));
  if (seconds < 60) return "just now";
  if (seconds < 3_600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3_600)}h ago`;
  return `${Math.floor(seconds / 86_400)}d ago`;
}

export function severityColor(severity: number): string {
  return (
    { 1: "text-sev1", 2: "text-sev2", 3: "text-sev3", 4: "text-sev4" }[severity] ?? "text-ink-dim"
  );
}

export function severityBg(severity: number): string {
  return { 1: "bg-sev1", 2: "bg-sev2", 3: "bg-sev3", 4: "bg-sev4" }[severity] ?? "bg-ink-dim";
}

export function verdictColor(verdict: string | null): string {
  if (verdict === "BLOCK") return "text-block";
  if (verdict === "WATCH") return "text-watch";
  if (verdict === "IGNORE") return "text-ignore";
  return "text-ink-dim";
}

export function formatNumber(value: number): string {
  return value >= 10_000 ? `${(value / 1000).toFixed(1)}k` : String(value);
}

export function bandColor(band: string | undefined): string {
  if (band === "malicious") return "text-block";
  if (band === "suspicious") return "text-watch";
  return "text-ignore";
}

export function bandBg(band: string | undefined): string {
  if (band === "malicious") return "bg-block";
  if (band === "suspicious") return "bg-watch";
  return "bg-ignore";
}

/** Detection score → the same three-colour ramp used for verdicts and risk. */
export function scoreColor(score: number): string {
  if (score >= 70) return "text-block";
  if (score >= 30) return "text-watch";
  return "text-ignore";
}

export function riskColor(score: number): string {
  if (score >= 60) return "text-block";
  if (score >= 30) return "text-watch";
  return "text-ignore";
}

export function riskBg(score: number): string {
  if (score >= 60) return "bg-block";
  if (score >= 30) return "bg-watch";
  return "bg-ignore";
}

const HIT_KIND_STYLE: Record<string, string> = {
  ioc: "border-[#7a3d5a] text-[#e08ab4]",
  rule: "border-[#3f5f7a] text-[#8ab4d8]",
  heuristic: "border-[#6a4f7a] text-[#c99ce0]",
};

export function hitKindStyle(kind: string): string {
  return HIT_KIND_STYLE[kind] ?? "border-edge text-ink-dim";
}

const ACTION_STATUS_STYLE: Record<string, string> = {
  applied: "border-[#2d5a3d] text-ignore",
  pending_approval: "border-[#7a5a2d] text-sev2",
  blocked_by_guardrail: "border-[#5a2d2d] text-block",
  failed: "border-[#5a2d2d] text-block",
  rejected: "border-edge text-ink-dim",
  undone: "border-edge text-ink-dim",
};

export function actionStatusStyle(status: string): string {
  return ACTION_STATUS_STYLE[status] ?? "border-edge text-ink-dim";
}

export function titleCase(value: string): string {
  return value.replace(/_/g, " ");
}

/** The console is often served over plain http on the LAN, where `navigator.clipboard` is absent. */
export async function copyText(text: string): Promise<boolean> {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // fall through to the textarea path
    }
  }
  const scratch = document.createElement("textarea");
  scratch.value = text;
  scratch.setAttribute("readonly", "");
  scratch.style.position = "fixed";
  scratch.style.opacity = "0";
  document.body.appendChild(scratch);
  scratch.select();
  const ok = document.execCommand("copy");
  scratch.remove();
  return ok;
}
