import type { ResponseAction, ResponseType } from "@aisoc/shared";
import { Ban, Bot, Hand, ScanSearch, ShieldOff, Skull, Undo2, Workflow } from "lucide-react";
import { useMemo, useState } from "react";
import { Badge, Button, Input, SectionTitle, Select } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { actionStatusStyle, cn, timeOf, titleCase } from "@/lib/utils";
import { useStore } from "@/store";

const TYPE_ICON: Record<ResponseType, typeof Ban> = {
  block_ip: Ban,
  block_domain: Ban,
  quarantine_file: ShieldOff,
  isolate_host: ShieldOff,
  kill_process: Skull,
};

const ORIGIN_ICON = {
  engine: ScanSearch,
  llm: Bot,
  playbook: Workflow,
  human: Hand,
} as const;

const AUTONOMY_COPY = {
  manual: "Every action waits for you.",
  guarded: "High-confidence actions fire themselves; everything else waits.",
  full: "Everything the engine proposes fires immediately.",
} as const;

function AutonomyBanner() {
  const settings = useStore((s) => s.settings);
  const stats = useStore((s) => s.stats);
  const setView = useStore((s) => s.setView);
  const rails = settings.response.guardrails;

  return (
    <div className="flex items-center gap-3 border-b border-edge bg-panel px-3 py-2">
      <Badge
        className={cn(
          "font-mono",
          settings.response.autonomy === "full"
            ? "border-[#7a2d2d] text-block"
            : settings.response.autonomy === "guarded"
              ? "border-[#7a5a2d] text-sev2"
              : "border-[#2d5a3d] text-ignore",
        )}
      >
        {titleCase(settings.response.autonomy)}
      </Badge>
      <span className="text-[11px] text-ink">{AUTONOMY_COPY[settings.response.autonomy]}</span>
      <span className="text-[10px] text-ink-dim">
        Guarded needs score ≥ {rails.autoExecuteAtScore} and confidence ≥{" "}
        {rails.autoExecuteAtConfidence.toFixed(2)} · {rails.maxAutoActionsPerHour}/hour cap ·{" "}
        {settings.response.execution === "simulate"
          ? "commands are recorded, not run"
          : "commands run via nftables"}
      </span>
      <span className="ml-auto text-[10px] text-ink-dim">
        {stats?.pendingActions ?? 0} pending · {stats?.appliedActions ?? 0} applied
      </span>
      <Button size="sm" variant="outline" onClick={() => setView("settings")}>
        change autonomy
      </Button>
    </div>
  );
}

function ActionRow({ action }: { action: ResponseAction }) {
  const analyst = useStore((s) => s.analyst);
  const pushToast = useStore((s) => s.pushToast);
  const selectAlert = useStore((s) => s.selectAlert);
  const setView = useStore((s) => s.setView);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);

  const Icon = TYPE_ICON[action.type];
  const OriginIcon = ORIGIN_ICON[action.origin];

  const call = (fn: Promise<unknown>, message: string) => {
    setBusy(true);
    fn.then(() => pushToast("success", message))
      .catch((error: Error) => pushToast("error", error.message))
      .finally(() => setBusy(false));
  };

  return (
    <div className="border-b border-edge/60">
      <div
        className={cn(
          "row-in grid grid-cols-[16px_54px_1fr_140px_120px_auto] items-center gap-2 px-3 py-1.5 text-[11px]",
          open ? "bg-active" : "hover:bg-hover",
        )}
      >
        <Icon className="h-3.5 w-3.5 text-ink-dim" />
        <span className="font-mono text-[10px] text-ink-dim tabular-nums">
          {timeOf(action.createdAt)}
        </span>
        <button type="button" onClick={() => setOpen(!open)} className="min-w-0 text-left">
          <span className="block truncate font-mono text-ink">
            {titleCase(action.type)} · {action.target}
          </span>
          <span className="block truncate text-[10px] text-ink-dim">{action.reason}</span>
        </button>
        <Badge className={cn("font-mono", actionStatusStyle(action.status))}>
          {titleCase(action.status)}
        </Badge>
        <span className="flex items-center gap-1.5 text-[10px] text-ink-dim">
          <OriginIcon className="h-3 w-3" />
          {action.origin}
          {action.simulated ? <Badge className="text-ink-dim">sim</Badge> : null}
        </span>
        <span className="flex shrink-0 gap-1">
          {action.status === "pending_approval" ? (
            <>
              <Button
                size="sm"
                variant="primary"
                disabled={busy}
                onClick={() => call(api.approveAction(action.id, analyst), "Action applied.")}
              >
                apply
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={busy}
                onClick={() => call(api.rejectAction(action.id, analyst), "Action rejected.")}
              >
                reject
              </Button>
            </>
          ) : null}
          {action.status === "applied" ? (
            <Button
              size="sm"
              variant="outline"
              disabled={busy}
              onClick={() => call(api.undoAction(action.id, analyst), "Action undone.")}
            >
              <Undo2 className="h-3 w-3" />
              undo
            </Button>
          ) : null}
          {action.alertId ? (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                selectAlert(action.alertId!);
                setView("triage");
              }}
            >
              alert
            </Button>
          ) : null}
        </span>
      </div>

      {open ? (
        <div className="flex flex-col gap-2 border-t border-edge bg-panel px-3 py-2 text-[11px]">
          <div className="flex flex-wrap gap-x-5 gap-y-1 text-[10px] text-ink-dim">
            <span>
              requested by <span className="font-mono text-ink">{action.requestedBy}</span>
            </span>
            <span>
              autonomy at filing <span className="font-mono text-ink">{action.autonomy}</span>
            </span>
            {action.playbookId ? (
              <span>
                playbook <span className="font-mono text-ink">{action.playbookId}</span>
              </span>
            ) : null}
            {action.decidedBy ? (
              <span>
                decided by <span className="font-mono text-ink">{action.decidedBy}</span>
              </span>
            ) : null}
            {action.appliedAt ? <span>applied {timeOf(action.appliedAt)}</span> : null}
            {action.undoneAt ? <span>undone {timeOf(action.undoneAt)}</span> : null}
          </div>

          {action.guardrail ? (
            <div className="rounded-sm border border-[#7a5a2d] bg-[#2a2113] px-2 py-1.5 text-[11px] text-sev2">
              <span className="font-semibold">
                {action.status === "blocked_by_guardrail"
                  ? "Guardrail refused: "
                  : "Held because: "}
              </span>
              {action.guardrail}
            </div>
          ) : null}
          {action.error ? (
            <div className="rounded-sm border border-[#5a2d2d] bg-[#321e1e] px-2 py-1.5 text-[11px] text-[#f5b8b8]">
              <span className="font-semibold">Error: </span>
              {action.error}
            </div>
          ) : null}

          <div>
            <div className="mb-1 text-[10px] uppercase tracking-wide text-ink-dim">
              {action.simulated ? "Command that would run" : "Command run"}
            </div>
            <pre className="overflow-x-auto rounded-sm border border-edge bg-shell p-2 font-mono text-[11px] text-ink">
              {action.command || "handled inside the console"}
            </pre>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function ManualAction() {
  const analyst = useStore((s) => s.analyst);
  const pushToast = useStore((s) => s.pushToast);
  const [type, setType] = useState<ResponseType>("block_ip");
  const [target, setTarget] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);

  return (
    <div className="flex items-end gap-1.5 border-b border-edge bg-panel px-3 py-2">
      <Select
        className="w-40"
        value={type}
        onValueChange={(value) => setType(value as ResponseType)}
        options={[
          { value: "block_ip", label: "Block IP" },
          { value: "block_domain", label: "Block domain" },
          { value: "quarantine_file", label: "Quarantine file" },
          { value: "isolate_host", label: "Isolate host (by IP)" },
          { value: "kill_process", label: "Kill process (pid)" },
        ]}
      />
      <Input
        className="w-48"
        value={target}
        placeholder="target"
        onChange={(event) => setTarget(event.target.value)}
      />
      <Input
        className="flex-1"
        value={reason}
        placeholder="why — recorded on the action and in the audit log"
        onChange={(event) => setReason(event.target.value)}
      />
      <Button
        variant="secondary"
        disabled={busy || !target.trim()}
        onClick={() => {
          setBusy(true);
          api
            .createAction({ alertId: null, type, target: target.trim(), reason, by: analyst })
            .then(() => {
              setTarget("");
              setReason("");
              pushToast("success", "Action filed.");
            })
            .catch((error: Error) => pushToast("error", error.message))
            .finally(() => setBusy(false));
        }}
      >
        run action
      </Button>
    </div>
  );
}

function Playbooks() {
  const playbooks = useStore((s) => s.playbooks);
  const pushToast = useStore((s) => s.pushToast);

  return (
    <div className="border-t border-edge bg-panel px-3 py-2">
      <SectionTitle>Playbooks</SectionTitle>
      <div className="grid gap-1 md:grid-cols-2">
        {playbooks.map((playbook) => (
          <div key={playbook.id} className="rounded-sm border border-edge bg-shell p-2">
            <div className="flex items-center gap-2">
              <Workflow className="h-3 w-3 shrink-0 text-ink-dim" />
              <span className="truncate text-[11px] text-ink">{playbook.name}</span>
              <Button
                size="sm"
                variant="ghost"
                className="ml-auto shrink-0"
                onClick={() =>
                  api
                    .togglePlaybook(playbook.id)
                    .catch((error: Error) => pushToast("error", error.message))
                }
              >
                {playbook.enabled ? "disable" : "enable"}
              </Button>
            </div>
            <p className="mt-0.5 text-[10px] leading-snug text-ink-dim">{playbook.description}</p>
            <div className="mt-1.5 flex flex-wrap gap-1">
              {playbook.steps.map((step, index) => (
                <Badge key={`${step.type}-${step.targetFrom}`} className="text-ink-dim">
                  {index + 1}. {titleCase(step.type)}
                </Badge>
              ))}
            </div>
            <p className="mt-1 text-[10px] text-ink-dim">
              fires at score ≥ {playbook.minScore} on {playbook.triggerRuleIds.length} rule
              {playbook.triggerRuleIds.length === 1 ? "" : "s"}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

export function ResponseView() {
  const actions = useStore((s) => s.actions);
  const [filter, setFilter] = useState<"all" | "pending_approval" | "applied" | "blocked">("all");

  const visible = useMemo(() => {
    const list = actions.filter((action) => {
      if (filter === "all") return true;
      if (filter === "blocked") return action.status === "blocked_by_guardrail";
      return action.status === filter;
    });
    return [...list].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }, [actions, filter]);

  const count = (status: string) =>
    status === "all"
      ? actions.length
      : actions.filter((action) =>
          status === "blocked"
            ? action.status === "blocked_by_guardrail"
            : action.status === status,
        ).length;

  return (
    <div className="flex h-full flex-col">
      <AutonomyBanner />
      <ManualAction />

      <div className="flex shrink-0 items-center gap-2 border-b border-edge bg-panel px-3 py-1.5">
        {(["all", "pending_approval", "applied", "blocked"] as const).map((value) => (
          <button
            key={value}
            type="button"
            onClick={() => setFilter(value)}
            className={cn(
              "rounded-sm px-2 py-0.5 text-[11px] transition-colors",
              filter === value ? "bg-active text-ink" : "text-ink-dim hover:text-ink",
            )}
          >
            {titleCase(value)}
            <span className="ml-1.5 font-mono text-[10px] tabular-nums opacity-70">
              {count(value)}
            </span>
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto">
        {visible.length === 0 ? (
          <p className="p-6 text-center text-xs text-ink-dim">
            No response actions here yet. They are filed when a BLOCK verdict lands or the detection
            engine scores an alert at 60 or above.
          </p>
        ) : (
          visible.map((action) => <ActionRow key={action.id} action={action} />)
        )}
      </div>

      <Playbooks />
    </div>
  );
}
