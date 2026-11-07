import type { Incident, IncidentStatus, TimelineKind } from "@aisoc/shared";
import {
  Braces,
  BrainCircuit,
  MessageSquare,
  ScanSearch,
  Send,
  Shield,
  StickyNote,
  Zap,
} from "lucide-react";
import { useMemo, useState } from "react";
import { FlowPath } from "@/components/FlowPath";
import { ScoreBar } from "@/components/security";
import {
  Badge,
  Button,
  CopyButton,
  Input,
  SectionTitle,
  Select,
  Textarea,
} from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { type IncidentContext, incidentJson, incidentMarkdown } from "@/lib/dossier";
import { cn, severityBg, severityLabel, shortAge, timeOf } from "@/lib/utils";
import { useStore } from "@/store";

const STATUSES: IncidentStatus[] = ["open", "investigating", "contained", "closed"];

const STATUS_STYLE: Record<IncidentStatus, string> = {
  open: "border-[#7a2d2d] text-block",
  investigating: "border-[#7a5a2d] text-sev2",
  contained: "border-[#3f5f7a] text-[#8ab4d8]",
  closed: "border-[#2d5a3d] text-ignore",
};

const TIMELINE_ICON: Record<TimelineKind, typeof Shield> = {
  alert: Shield,
  detection: ScanSearch,
  response: Zap,
  note: StickyNote,
  llm: BrainCircuit,
  notify: Send,
  status: Shield,
};

const TIMELINE_TONE: Record<TimelineKind, string> = {
  alert: "text-sev2",
  detection: "text-[#e08ab4]",
  response: "text-ignore",
  note: "text-ink-dim",
  llm: "text-[#c99ce0]",
  notify: "text-[#8ab4d8]",
  status: "text-status",
};

function IncidentRow({ incident, selected }: { incident: Incident; selected: boolean }) {
  const selectIncident = useStore((s) => s.selectIncident);
  return (
    <button
      type="button"
      onClick={() => selectIncident(incident.id)}
      className={cn(
        "row-in grid w-full grid-cols-[72px_10px_1fr_110px_70px_90px_80px] items-center gap-2 px-3 py-1.5 text-left text-[11px]",
        selected ? "bg-active" : "hover:bg-hover",
      )}
    >
      <span className="font-mono text-status">{incident.ref}</span>
      <span
        className={cn("h-2 w-2 rounded-full", severityBg(incident.severity))}
        title={severityLabel(incident.severity)}
      />
      <span className="min-w-0">
        <span className="block truncate text-ink" title={incident.title}>
          {incident.title}
        </span>
        <span className="block truncate text-[10px] text-ink-dim">
          {incident.correlationBasis} · {incident.alertIds.length} alerts ·{" "}
          {incident.assetIds.length} host{incident.assetIds.length === 1 ? "" : "s"}
        </span>
      </span>
      <Badge className={cn("font-mono", STATUS_STYLE[incident.status])}>{incident.status}</Badge>
      <ScoreBar score={incident.score} width="w-10" />
      <span className="truncate font-mono text-[10px] text-ink-dim">
        {incident.assignee ?? "unassigned"}
      </span>
      <span className="font-mono text-[10px] text-ink-dim tabular-nums">
        {shortAge(incident.createdAt)}
      </span>
    </button>
  );
}

function IncidentDetail({ incident }: { incident: Incident }) {
  const analyst = useStore((s) => s.analyst);
  const openAssistant = useStore((s) => s.openAssistant);
  const alerts = useStore((s) => s.alerts);
  const assets = useStore((s) => s.assets);
  const actions = useStore((s) => s.actions);
  const pushToast = useStore((s) => s.pushToast);
  const selectAlert = useStore((s) => s.selectAlert);
  const setView = useStore((s) => s.setView);
  const [note, setNote] = useState("");
  const [assignee, setAssignee] = useState(incident.assignee ?? "");
  const [busy, setBusy] = useState(false);

  const members = alerts.filter((alert) => incident.alertIds.includes(alert.id));
  const hosts = assets.filter((asset) => incident.assetIds.includes(asset.id));
  const related = actions.filter((action) => action.incidentId === incident.id);

  const dossier: IncidentContext = {
    incident,
    alerts: members,
    assets: hosts,
    actions: related,
  };

  const fail = (error: Error) => pushToast("error", error.message);

  return (
    <div className="flex h-full flex-col overflow-y-auto">
      <div className="border-b border-edge bg-panel px-3 py-2">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm text-status">{incident.ref}</span>
          <Badge className={cn("font-mono", STATUS_STYLE[incident.status])}>
            {incident.status}
          </Badge>
          <ScoreBar score={incident.score} className="ml-auto" />
          <span className="h-4 w-px bg-edge" />
          <CopyButton
            label="copy"
            title={`Copy ${incident.ref} as markdown — full evidence, intel, response and timeline, ready to paste into a model`}
            text={() => incidentMarkdown(dossier)}
          />
          <CopyButton
            label="json"
            icon={Braces}
            title={`Copy ${incident.ref} as raw JSON`}
            text={() => incidentJson(dossier)}
            variant="ghost"
          />
        </div>
        <h3 className="mt-1 text-[13px] leading-snug text-ink-bright">{incident.title}</h3>
        <p className="mt-0.5 text-[10px] text-ink-dim">
          Correlated on {incident.correlationBasis} · opened{" "}
          {new Date(incident.createdAt).toLocaleString()}
        </p>
      </div>

      <div className="flex flex-col gap-4 p-3">
        <div>
          <SectionTitle>Flow &amp; decision path</SectionTitle>
          <FlowPath
            key={incident.id}
            incident={incident}
            alerts={members}
            actions={related}
            onSelectAlert={(alertId) => {
              selectAlert(alertId);
              setView("triage");
            }}
          />
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <Select
            className="w-36"
            value={incident.status}
            onValueChange={(status) =>
              api.setIncidentStatus(incident.id, status, analyst).catch(fail)
            }
            options={STATUSES.map((status) => ({ value: status, label: status }))}
          />
          <Input
            className="w-40"
            value={assignee}
            placeholder="assignee"
            onChange={(event) => setAssignee(event.target.value)}
          />
          <Button
            size="md"
            variant="secondary"
            onClick={() => api.assignIncident(incident.id, assignee, analyst).catch(fail)}
          >
            assign
          </Button>
          <Button
            size="md"
            variant="outline"
            className="ml-auto"
            disabled={busy}
            onClick={() => {
              setBusy(true);
              api
                .narrateIncident(incident.id)
                .then(() => pushToast("info", "Asked the model to write this incident up."))
                .catch(fail)
                .finally(() => setBusy(false));
            }}
          >
            <BrainCircuit className="h-3 w-3" />
            {incident.narrative ? "re-narrate" : "narrate"}
          </Button>
        </div>

        {incident.narrative ? (
          <div className="rounded-sm border border-[#6a4f7a] bg-[#221a2a] p-2">
            <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-[#c99ce0]">
              <BrainCircuit className="h-3 w-3" />
              model narrative · {incident.narrativeModel}
            </div>
            <p className="text-[11px] leading-relaxed text-ink">{incident.narrative}</p>
            {incident.suggestedResponse ? (
              <p className="mt-1.5 text-[11px] leading-snug text-[#c99ce0]">
                <span className="font-semibold">Suggested: </span>
                {incident.suggestedResponse}
              </p>
            ) : null}
            <div className="mt-2 flex flex-wrap items-center gap-2 border-t border-[#6a4f7a]/50 pt-2">
              <p className="min-w-48 flex-1 text-[10px] leading-snug text-ink-dim">
                Written from the detection timeline. It explains the incident; it does not decide it
                or trigger a response.
              </p>
              <Button
                size="sm"
                variant="outline"
                onClick={() => openAssistant({ kind: "incident", id: incident.id })}
              >
                <MessageSquare className="h-3.5 w-3.5" /> Ask assistant
              </Button>
            </div>
          </div>
        ) : null}

        {incident.mitre.length > 0 ? (
          <div>
            <SectionTitle>ATT&amp;CK techniques</SectionTitle>
            <div className="flex flex-col gap-1">
              {incident.mitre.map((ref) => (
                <div
                  key={ref.techniqueId}
                  className="flex items-center gap-2 rounded-sm border border-edge bg-shell px-2 py-1 text-[11px]"
                >
                  <span className="w-20 shrink-0 font-mono text-[#a8a8d8]">{ref.techniqueId}</span>
                  <span className="truncate text-ink">{ref.technique}</span>
                  <span className="ml-auto shrink-0 text-[10px] text-ink-dim">{ref.tactic}</span>
                </div>
              ))}
            </div>
          </div>
        ) : null}

        <div>
          <SectionTitle>Evidence — {members.length} alerts</SectionTitle>
          <div className="flex flex-col gap-1">
            {members.map((alert) => (
              <button
                key={alert.id}
                type="button"
                onClick={() => {
                  selectAlert(alert.id);
                  setView("triage");
                }}
                className="flex items-center gap-2 rounded-sm border border-edge bg-shell px-2 py-1 text-left text-[11px] hover:border-status"
              >
                <span
                  className={cn(
                    "h-1.5 w-1.5 shrink-0 rounded-full",
                    severityBg(alert.event.severity),
                  )}
                />
                <span className="truncate font-mono text-ink">{alert.event.signature}</span>
                <span className="ml-auto shrink-0 font-mono text-[10px] text-ink-dim">
                  {alert.verdict ?? alert.stage}
                </span>
              </button>
            ))}
          </div>
        </div>

        {hosts.length > 0 ? (
          <div>
            <SectionTitle>Affected hosts</SectionTitle>
            <div className="flex flex-wrap gap-1">
              {hosts.map((asset) => (
                <Badge key={asset.id} className="gap-1.5 text-ink">
                  <span className="font-mono normal-case">{asset.hostname}</span>
                  <span className="text-ink-dim">risk {asset.riskScore}</span>
                </Badge>
              ))}
            </div>
          </div>
        ) : null}

        {related.length > 0 ? (
          <div>
            <SectionTitle>Response</SectionTitle>
            <div className="flex flex-col gap-1">
              {related.map((action) => (
                <div
                  key={action.id}
                  className="flex items-center gap-2 rounded-sm border border-edge bg-shell px-2 py-1 text-[11px]"
                >
                  <Zap className="h-3 w-3 shrink-0 text-ink-dim" />
                  <span className="font-mono text-ink">
                    {action.type.replace(/_/g, " ")} {action.target}
                  </span>
                  <span className="ml-auto shrink-0 text-[10px] text-ink-dim">
                    {action.status.replace(/_/g, " ")}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ) : null}

        <div>
          <SectionTitle>Timeline</SectionTitle>
          <div className="flex flex-col">
            {[...incident.timeline].reverse().map((item) => {
              const Icon = TIMELINE_ICON[item.kind];
              return (
                <div key={item.id} className="flex gap-2 border-l border-edge pl-3">
                  <span className="relative -ml-[19px] mt-1 flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-full bg-shell">
                    <Icon className={cn("h-2.5 w-2.5", TIMELINE_TONE[item.kind])} />
                  </span>
                  <div className="min-w-0 flex-1 pb-2.5">
                    <div className="flex items-baseline gap-2">
                      <span className="truncate text-[11px] text-ink">{item.title}</span>
                      <span className="ml-auto shrink-0 font-mono text-[10px] text-ink-dim">
                        {timeOf(item.at)}
                      </span>
                    </div>
                    <p className="text-[10px] leading-snug text-ink-dim">{item.detail}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div>
          <SectionTitle>Add a note</SectionTitle>
          <Textarea
            rows={2}
            value={note}
            onChange={(event) => setNote(event.target.value)}
            placeholder="What did you find? Appended to the timeline."
          />
          <Button
            size="sm"
            variant="outline"
            className="mt-1.5 w-full"
            disabled={!note.trim()}
            onClick={() => {
              api
                .incidentNote(incident.id, analyst, note)
                .then(() => setNote(""))
                .catch(fail);
            }}
          >
            add to timeline
          </Button>
        </div>
      </div>
    </div>
  );
}

export function IncidentsView() {
  const incidents = useStore((s) => s.incidents);
  const selectedIncidentId = useStore((s) => s.selectedIncidentId);
  const [filter, setFilter] = useState<"active" | "all">("active");

  const visible = useMemo(() => {
    const list = filter === "all" ? incidents : incidents.filter((i) => i.status !== "closed");
    return [...list].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }, [incidents, filter]);

  const selected = incidents.find((incident) => incident.id === selectedIncidentId) ?? visible[0];

  return (
    <div className="flex h-full">
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex shrink-0 items-center gap-2 border-b border-edge bg-panel px-3 py-1.5">
          {(["active", "all"] as const).map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => setFilter(value)}
              className={cn(
                "rounded-sm px-2 py-0.5 text-[11px] transition-colors",
                filter === value ? "bg-active text-ink" : "text-ink-dim hover:text-ink",
              )}
            >
              {value}
              <span className="ml-1.5 font-mono text-[10px] tabular-nums opacity-70">
                {value === "all"
                  ? incidents.length
                  : incidents.filter((i) => i.status !== "closed").length}
              </span>
            </button>
          ))}
          <span className="ml-auto text-[10px] text-ink-dim">
            Alerts group by shared indicator, host, hash, or scripted behaviour inside the
            correlation window.
          </span>
        </div>

        <div className="grid shrink-0 grid-cols-[72px_10px_1fr_110px_70px_90px_80px] gap-2 border-b border-edge bg-panel px-3 py-1 text-[10px] uppercase tracking-wide text-ink-dim">
          <span>ref</span>
          <span />
          <span>incident</span>
          <span>status</span>
          <span>score</span>
          <span>assignee</span>
          <span>age</span>
        </div>

        <div className="flex-1 overflow-y-auto">
          {visible.length === 0 ? (
            <p className="p-6 text-center text-xs text-ink-dim">
              No incidents yet. Run a scenario from the overview to correlate one.
            </p>
          ) : (
            visible.map((incident) => (
              <IncidentRow
                key={incident.id}
                incident={incident}
                selected={incident.id === selected?.id}
              />
            ))
          )}
        </div>
      </div>

      <aside className="flex w-[460px] shrink-0 flex-col border-l border-edge bg-panel">
        {selected ? (
          <IncidentDetail incident={selected} />
        ) : (
          <p className="p-6 text-center text-xs text-ink-dim">Select an incident.</p>
        )}
      </aside>
    </div>
  );
}
