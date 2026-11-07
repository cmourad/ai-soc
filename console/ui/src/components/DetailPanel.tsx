import type { Alert, SecurityEvent, Verdict } from "@aisoc/shared";
import { MessageSquare, PanelRightClose, ShieldAlert, X, Zap } from "lucide-react";
import { useState } from "react";
import { DetectionPanel, IntelPanel } from "@/components/security";
import { Badge, Button, SectionTitle, Textarea } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import {
  actionStatusStyle,
  cn,
  severityBg,
  severityLabel,
  shortAge,
  timeOf,
  titleCase,
  verdictColor,
} from "@/lib/utils";
import { useStore } from "@/store";

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[110px_1fr] gap-2 py-[3px] text-[11px]">
      <span className="text-ink-dim">{label}</span>
      <span className="break-words font-mono text-ink">{value}</span>
    </div>
  );
}

function EventFacts({ event }: { event: SecurityEvent }) {
  return (
    <div>
      <SectionTitle>Event</SectionTitle>
      <Row label="signature" value={event.signature} />
      <Row label="signature id" value={event.signatureId} />
      <Row label="category" value={event.category} />
      <Row
        label="severity"
        value={
          <span className="flex items-center gap-1.5">
            <span className={cn("h-2 w-2 rounded-full", severityBg(event.severity))} />
            {event.severity} · {severityLabel(event.severity)}
          </span>
        }
      />
      <Row label="observed" value={new Date(event.ts).toLocaleString()} />
      <Row label="source" value={`${event.srcIp}:${event.srcPort}`} />
      <Row label="destination" value={`${event.destIp}:${event.destPort}`} />
      <Row
        label="protocol"
        value={`${event.proto}${event.appProto ? ` / ${event.appProto}` : ""}`}
      />
      <Row label="matched packet" value={event.direction} />
      <Row label="bytes sent" value={event.bytesToServer.toLocaleString()} />
      <Row label="bytes received" value={event.bytesToClient.toLocaleString()} />
      <Row label="feed" value={event.source} />
      {event.tags.length > 0 ? (
        <div className="mt-2 flex flex-wrap gap-1">
          {event.tags.map((tag) => (
            <Badge key={tag} className="text-ink-dim">
              {tag}
            </Badge>
          ))}
        </div>
      ) : null}

      {event.processName || event.filePath || event.user ? (
        <div className="mt-3">
          <SectionTitle>Endpoint</SectionTitle>
          {event.processName ? <Row label="process" value={event.processName} /> : null}
          {event.processPid ? <Row label="pid" value={event.processPid} /> : null}
          {event.parentProcess ? <Row label="parent" value={event.parentProcess} /> : null}
          {event.user ? <Row label="user" value={event.user} /> : null}
          {event.filePath ? <Row label="file" value={event.filePath} /> : null}
          {event.fileSha256 ? <Row label="sha256" value={event.fileSha256} /> : null}
        </div>
      ) : null}

      {event.sni || event.hostname || event.url || event.userAgent ? (
        <div className="mt-3 rounded-sm border border-[#7a5a2d] bg-[#2a2113] p-2">
          <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-sev2">
            <ShieldAlert className="h-3 w-3" />
            attacker-controlled data
          </div>
          {event.sni ? <Row label="tls sni" value={event.sni} /> : null}
          {event.hostname ? <Row label="hostname" value={event.hostname} /> : null}
          {event.url ? <Row label="url" value={event.url} /> : null}
          {event.userAgent ? <Row label="user agent" value={event.userAgent} /> : null}
        </div>
      ) : null}
    </div>
  );
}

/** Alert → host → incident → response, the pivots an investigation actually walks. */
function Pivots({ alert }: { alert: Alert }) {
  const assets = useStore((s) => s.assets);
  const incidents = useStore((s) => s.incidents);
  const setView = useStore((s) => s.setView);
  const selectAsset = useStore((s) => s.selectAsset);
  const selectIncident = useStore((s) => s.selectIncident);
  const setTextFilter = useStore((s) => s.setTextFilter);
  const setSourceFilter = useStore((s) => s.setSourceFilter);

  const asset = assets.find((entry) => entry.id === alert.assetId);
  const incident = incidents.find((entry) => entry.id === alert.incidentId);
  const remote = alert.enrichment?.indicator;

  return (
    <div className="flex flex-wrap gap-1.5">
      {asset ? (
        <Button
          size="sm"
          variant="outline"
          onClick={() => {
            selectAsset(asset.id);
            setView("assets");
          }}
        >
          host {asset.hostname} · risk {asset.riskScore}
        </Button>
      ) : null}
      {incident ? (
        <Button
          size="sm"
          variant="outline"
          onClick={() => {
            selectIncident(incident.id);
            setView("incidents");
          }}
        >
          {incident.ref} · {incident.alertIds.length} alerts
        </Button>
      ) : null}
      {remote ? (
        <Button
          size="sm"
          variant="outline"
          onClick={() => {
            setSourceFilter(remote);
            setTextFilter("");
            setView("traffic");
          }}
        >
          all traffic for {remote}
        </Button>
      ) : null}
      {alert.event.fileSha256 ? (
        <Button
          size="sm"
          variant="outline"
          onClick={() => {
            setTextFilter(alert.event.fileSha256!);
            setSourceFilter("");
            setView("traffic");
          }}
        >
          this hash elsewhere
        </Button>
      ) : null}
    </div>
  );
}

function ResponsePanel({ alert }: { alert: Alert }) {
  const actions = useStore((s) => s.actions);
  const analyst = useStore((s) => s.analyst);
  const pushToast = useStore((s) => s.pushToast);
  const setView = useStore((s) => s.setView);
  const [busy, setBusy] = useState(false);

  const mine = actions.filter((action) => alert.responseIds.includes(action.id));
  if (mine.length === 0) return null;

  const decide = (id: string, kind: "approve" | "reject" | "undo") => {
    setBusy(true);
    const call =
      kind === "approve"
        ? api.approveAction(id, analyst)
        : kind === "reject"
          ? api.rejectAction(id, analyst)
          : api.undoAction(id, analyst);
    call
      .then(() => pushToast("success", `Action ${kind === "undo" ? "undone" : `${kind}d`}.`))
      .catch((error: Error) => pushToast("error", error.message))
      .finally(() => setBusy(false));
  };

  return (
    <div>
      <SectionTitle>Response</SectionTitle>
      <div className="flex flex-col gap-1">
        {mine.map((action) => (
          <div key={action.id} className="rounded-sm border border-edge bg-shell p-2">
            <div className="flex items-center gap-2">
              <Zap className="h-3 w-3 shrink-0 text-ink-dim" />
              <span className="truncate font-mono text-[11px] text-ink">
                {titleCase(action.type)} {action.target}
              </span>
              <Badge className={cn("ml-auto shrink-0 font-mono", actionStatusStyle(action.status))}>
                {titleCase(action.status)}
              </Badge>
            </div>
            <p className="mt-1 text-[10px] leading-snug text-ink-dim">{action.reason}</p>
            {action.guardrail ? (
              <p className="mt-1 text-[10px] leading-snug text-sev2">{action.guardrail}</p>
            ) : null}
            <div className="mt-1.5 flex gap-1.5">
              {action.status === "pending_approval" ? (
                <>
                  <Button
                    size="sm"
                    variant="primary"
                    disabled={busy}
                    onClick={() => decide(action.id, "approve")}
                  >
                    apply
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={busy}
                    onClick={() => decide(action.id, "reject")}
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
                  onClick={() => decide(action.id, "undo")}
                >
                  undo
                </Button>
              ) : null}
              <Button
                size="sm"
                variant="ghost"
                className="ml-auto"
                onClick={() => setView("response")}
              >
                open queue
              </Button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function PagePanel({ alert }: { alert: Alert }) {
  const incident = useStore((s) => s.pages.find((page) => page.id === alert.pageId));
  const analyst = useStore((s) => s.analyst);
  const pushToast = useStore((s) => s.pushToast);
  if (!incident) return null;

  return (
    <div>
      <SectionTitle>On-call page</SectionTitle>
      <Row
        label="status"
        value={
          incident.acked
            ? `acknowledged by ${incident.ackedBy}`
            : incident.exhausted
              ? "rotation exhausted — nobody acknowledged"
              : `paging ${incident.rotation[incident.currentIndex]?.slice(0, 8) ?? "?"} (step ${incident.currentIndex + 1}/${incident.rotation.length})`
        }
      />
      {incident.nextEscalationAt && !incident.acked ? (
        <Row label="escalates" value={new Date(incident.nextEscalationAt).toLocaleTimeString()} />
      ) : null}

      <div className="mt-2 flex flex-col gap-1">
        {incident.attempts.map((attempt) => (
          <div
            key={`${attempt.at}-${attempt.personId}-${attempt.channel}`}
            className="flex items-center gap-2 rounded-sm border border-edge bg-shell px-2 py-1 text-[10px]"
          >
            <span
              className={cn("h-1.5 w-1.5 rounded-full", attempt.ok ? "bg-ignore" : "bg-block")}
            />
            <span className="font-mono text-ink">{attempt.personName}</span>
            <span className="text-ink-dim">{attempt.channel}</span>
            <span className="ml-auto text-ink-dim">{timeOf(attempt.at)}</span>
            {attempt.error ? <span className="w-full text-block">{attempt.error}</span> : null}
          </div>
        ))}
      </div>

      {!incident.acked ? (
        <Button
          variant="primary"
          size="sm"
          className="mt-2 w-full"
          onClick={() =>
            api.ack(incident.id, analyst).catch((error: Error) => pushToast("error", error.message))
          }
        >
          acknowledge page
        </Button>
      ) : null}
    </div>
  );
}

function AlertPanel({ alert }: { alert: Alert }) {
  const analyst = useStore((s) => s.analyst);
  const openAssistant = useStore((s) => s.openAssistant);
  const setView = useStore((s) => s.setView);
  const selectCall = useStore((s) => s.selectCall);
  const pushToast = useStore((s) => s.pushToast);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const override = (verdict: Verdict) => {
    setBusy(true);
    api
      .override(alert.id, verdict, analyst, note)
      .then(() => {
        setNote("");
        pushToast("success", `Verdict overridden to ${verdict}.`);
      })
      .catch((error: Error) => pushToast("error", error.message))
      .finally(() => setBusy(false));
  };

  return (
    <>
      <Pivots alert={alert} />

      <div>
        <SectionTitle>Detection engine</SectionTitle>
        <DetectionPanel detection={alert.detection} />
      </div>

      <div>
        <SectionTitle>Model triage</SectionTitle>
        <div className="rounded-sm border border-edge bg-shell p-2">
          <div className="flex items-baseline justify-between">
            <span className={cn("font-mono text-lg font-semibold", verdictColor(alert.verdict))}>
              {alert.verdict ?? "pending"}
            </span>
            <span className="font-mono text-[11px] text-ink-dim tabular-nums">
              confidence {alert.confidence.toFixed(2)}
            </span>
          </div>
          <p className="mt-1 text-[11px] leading-snug text-ink">
            {alert.reason ?? "No verdict yet."}
          </p>
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[10px] text-ink-dim">
            <span>stage: {alert.stage.replace(/_/g, " ")}</span>
            <span>origin: {alert.origin === "compass_beacon" ? "Compass beacon" : "event"}</span>
            <span>model: {alert.model ?? "—"}</span>
            <span>age: {shortAge(alert.createdAt)}</span>
          </div>
          {alert.origin === "compass_beacon" ? (
            <p className="mt-1.5 text-[10px] text-watch">
              Automatic response is disabled for this alert; any action requires you to confirm it.
            </p>
          ) : null}
          {alert.escalationReason ? (
            <p className="mt-1.5 text-[10px] text-sev2">escalated: {alert.escalationReason}</p>
          ) : null}
          {alert.verdict && alert.reason ? (
            <div className="mt-2 flex justify-end border-t border-edge/60 pt-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => openAssistant({ kind: "alert", id: alert.id })}
              >
                <MessageSquare className="h-3.5 w-3.5" /> Ask assistant
              </Button>
            </div>
          ) : null}
        </div>
      </div>

      {alert.humanOverride ? (
        <div className="rounded-sm border border-[#3f5f7a] bg-[#182430] p-2 text-[11px]">
          <div className="text-[10px] uppercase tracking-wide text-[#8ab4d8]">Human override</div>
          <div className="mt-0.5 font-mono">
            {alert.humanOverride.previousVerdict ?? "none"} → {alert.humanOverride.verdict} by{" "}
            {alert.humanOverride.by}
          </div>
          {alert.humanOverride.note ? <p className="mt-1">{alert.humanOverride.note}</p> : null}
        </div>
      ) : null}

      <div>
        <SectionTitle>Threat intelligence</SectionTitle>
        <IntelPanel enrichment={alert.enrichment} />
      </div>

      <ResponsePanel alert={alert} />
      <PagePanel alert={alert} />

      <div>
        <SectionTitle>Override</SectionTitle>
        <Textarea
          rows={2}
          value={note}
          onChange={(event) => setNote(event.target.value)}
          placeholder="Why? Stored as context on the alert."
        />
        <div className="mt-1.5 flex gap-1.5">
          <Button variant="danger" size="sm" disabled={busy} onClick={() => override("BLOCK")}>
            block
          </Button>
          <Button variant="secondary" size="sm" disabled={busy} onClick={() => override("WATCH")}>
            watch
          </Button>
          <Button variant="secondary" size="sm" disabled={busy} onClick={() => override("IGNORE")}>
            ignore
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="ml-auto"
            disabled={busy}
            onClick={() =>
              api
                .requeue(alert.id)
                .then(() => pushToast("info", "Re-queued for second triage."))
                .catch((error: Error) => pushToast("error", error.message))
            }
          >
            re-run second triage
          </Button>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="mt-1.5 w-full"
          disabled={busy || !note.trim()}
          onClick={() => {
            setBusy(true);
            api
              .comment(alert.id, analyst, note)
              .then(() => setNote(""))
              .catch((error: Error) => pushToast("error", error.message))
              .finally(() => setBusy(false));
          }}
        >
          add note without changing the verdict
        </Button>
      </div>

      {alert.notes.length > 0 ? (
        <div>
          <SectionTitle>Notes</SectionTitle>
          <div className="flex flex-col gap-1">
            {alert.notes.map((entry) => (
              <div
                key={entry.id}
                className="rounded-sm border border-edge bg-shell p-2 text-[11px]"
              >
                <div className="flex justify-between text-[10px] text-ink-dim">
                  <span>
                    {entry.author} · {entry.kind}
                  </span>
                  <span>{timeOf(entry.at)}</span>
                </div>
                <p className="mt-0.5 leading-snug">{entry.body}</p>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {alert.llmCallIds.length > 0 ? (
        <div>
          <SectionTitle>Model calls</SectionTitle>
          <Button
            variant="outline"
            size="sm"
            className="w-full"
            onClick={() => {
              selectCall(alert.llmCallIds[alert.llmCallIds.length - 1] ?? null);
              setView("llm");
            }}
          >
            open {alert.llmCallIds.length} call{alert.llmCallIds.length === 1 ? "" : "s"} in LLM
            activity
          </Button>
        </div>
      ) : null}
    </>
  );
}

export function DetailPanel() {
  const view = useStore((s) => s.view);
  const detailOpen = useStore((s) => s.detailOpen);
  const setDetailOpen = useStore((s) => s.setDetailOpen);
  const width = useStore((s) => s.detailWidth);
  const setWidth = useStore((s) => s.setDetailWidth);
  const events = useStore((s) => s.events);
  const alerts = useStore((s) => s.alerts);
  const selectedEventId = useStore((s) => s.selectedEventId);
  const selectedAlertId = useStore((s) => s.selectedAlertId);

  if (!detailOpen) {
    return (
      <button
        type="button"
        onClick={() => setDetailOpen(true)}
        className="w-6 shrink-0 border-l border-edge bg-panel text-ink-dim hover:text-ink"
        title="Show details"
      >
        <PanelRightClose className="mx-auto h-4 w-4 rotate-180" />
      </button>
    );
  }

  const alert =
    view === "triage"
      ? alerts.find((a) => a.id === selectedAlertId)
      : alerts.find((a) => a.event.id === selectedEventId);
  const event = alert?.event ?? events.find((e) => e.id === selectedEventId);

  const startResize = (down: React.PointerEvent) => {
    down.preventDefault();
    const startX = down.clientX;
    const startWidth = width;
    const move = (event: PointerEvent) => setWidth(startWidth + (startX - event.clientX));
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  return (
    <aside className="flex shrink-0" style={{ width }}>
      <button
        type="button"
        onPointerDown={startResize}
        onKeyDown={(event) => {
          if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
          event.preventDefault();
          setWidth(width + (event.key === "ArrowLeft" ? 24 : -24));
        }}
        aria-label="Resize detail panel"
        className="w-1 shrink-0 cursor-col-resize bg-edge hover:bg-status focus-visible:bg-status focus-visible:outline-none"
      />
      <div className="flex min-w-0 flex-1 flex-col border-l border-edge bg-panel">
        <header className="flex h-8 shrink-0 items-center justify-between border-b border-edge px-3">
          <span className="text-[11px] uppercase tracking-wide text-ink-dim">
            {alert ? "Alert detail" : "Event detail"}
          </span>
          <button
            type="button"
            onClick={() => setDetailOpen(false)}
            className="text-ink-dim hover:text-ink"
            aria-label="Hide details"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </header>

        <div className="flex flex-1 flex-col gap-4 overflow-y-auto p-3">
          {!event ? (
            <p className="pt-8 text-center text-xs text-ink-dim">Select a row to inspect it.</p>
          ) : (
            <>
              {alert ? <AlertPanel alert={alert} /> : null}
              <EventFacts event={event} />
            </>
          )}
        </div>
      </div>
    </aside>
  );
}
