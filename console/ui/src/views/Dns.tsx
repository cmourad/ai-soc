import type { DnsCount, DnsQueryStatus, DnsSummary } from "@aisoc/shared";
import { AlertTriangle, Loader2, MessageSquare, RefreshCw, Shield, ShieldOff } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Badge, Button, Card, SectionTitle } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { cn, shortAge } from "@/lib/utils";
import { useStore } from "@/store";

const REFRESH_MS = 15_000;

const STATUS_TONE: Record<DnsQueryStatus, string> = {
  blocked: "text-block",
  forwarded: "text-ink",
  cached: "text-ink-dim",
  other: "text-ink-dim",
};

function Tile({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <Card className="flex-1">
      <div className="text-[11px] uppercase tracking-wide text-ink-dim">{label}</div>
      <div className={cn("mt-1 text-2xl tabular-nums", tone ?? "text-ink-bright")}>
        {value.toLocaleString()}
      </div>
    </Card>
  );
}

function TopList({
  title,
  rows,
  head,
  tone,
  showBlocked = false,
}: {
  title: string;
  rows: DnsCount[];
  head: string;
  tone?: string;
  showBlocked?: boolean;
}) {
  return (
    <div className="min-w-0 flex-1">
      <SectionTitle>{title}</SectionTitle>
      {rows.length === 0 ? (
        <p className="px-1 py-2 text-[12px] text-ink-dim">Nothing in this window.</p>
      ) : (
        <table className="w-full text-[12px]">
          <thead>
            <tr className="border-b border-edge text-[10px] uppercase tracking-wide text-ink-dim">
              <th className="py-1 text-left font-normal">&nbsp;</th>
              <th className="w-16 py-1 text-right font-normal">{head}</th>
              {showBlocked ? <th className="w-16 py-1 text-right font-normal">blocked</th> : null}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.key} className="border-b border-edge/50 last:border-0">
                <td className="truncate py-1 pr-2 text-ink" title={row.key}>
                  {row.key}
                </td>
                <td className={cn("w-16 py-1 text-right tabular-nums", tone ?? "text-ink-dim")}>
                  {row.queries.toLocaleString()}
                </td>
                {showBlocked ? (
                  <td className="w-16 py-1 text-right tabular-nums text-block">
                    {row.blocked > 0 ? row.blocked.toLocaleString() : ""}
                  </td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function Unavailable({ error }: { error: string | null }) {
  return (
    <Card>
      <div className="flex items-start gap-2">
        <AlertTriangle className="mt-0.5 size-4 shrink-0 text-watch" />
        <div className="min-w-0 text-[12px]">
          <div className="text-ink">Pi-hole DNS data is unavailable.</div>
          <p className="mt-1 text-ink-dim">
            Verify that the Kubernetes Pi-hole pod is healthy, the stored pihole.password matches
            its retained configuration, and this host uses Pi-hole as its resolver.
          </p>
          {error ? (
            <pre className="mt-2 overflow-x-auto rounded bg-bar p-2 text-[11px] text-ink-dim">
              {error}
            </pre>
          ) : null}
        </div>
      </div>
    </Card>
  );
}

export function DnsView() {
  const openAssistant = useStore((s) => s.openAssistant);
  const [summary, setSummary] = useState<DnsSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [toggling, setToggling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.dns();
      setSummary(response.summary);
      setError(null);
    } catch (failure) {
      // Without this the view sits on its spinner forever when the console
      // itself is unreachable, which reads as a quiet network.
      setError(failure instanceof Error ? failure.message : String(failure));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), REFRESH_MS);
    return () => clearInterval(timer);
  }, [load]);

  const toggleBlocking = useCallback(async () => {
    const enabled = summary?.blockingEnabled;
    if (typeof enabled !== "boolean" || toggling) return;
    setToggling(true);
    let failure: string | null = null;
    try {
      await api.dnsBlocking(!enabled);
    } catch (error) {
      failure = error instanceof Error ? error.message : String(error);
    }
    setToggling(false);
    // Reload either way: a failed flip may still have changed the state. The
    // refresh clears `error`, so the failure has to be re-raised after it.
    await load();
    if (failure) setError(failure);
  }, [summary, toggling, load]);

  if (!summary) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 p-3 text-ink-dim">
        {error ? (
          <>
            <Unavailable error={error} />
            <Button onClick={() => void load()} disabled={loading}>
              <RefreshCw className={cn("size-3.5", loading && "animate-spin")} />
              Retry
            </Button>
          </>
        ) : (
          <Loader2 className="size-4 animate-spin" />
        )}
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col gap-3 overflow-y-auto p-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-ink-dim">Last {summary.windowHours}h</span>
          {summary.available && summary.blockingEnabled !== null ? (
            <Button
              size="sm"
              variant={summary.blockingEnabled ? "outline" : "danger"}
              onClick={() => void toggleBlocking()}
              disabled={toggling}
              title="Blocking is network-wide: this affects every device that uses Pi-hole, not just your desktop"
            >
              {toggling ? (
                <Loader2 className="size-3.5 animate-spin" />
              ) : summary.blockingEnabled ? (
                <ShieldOff className="size-3.5" />
              ) : (
                <Shield className="size-3.5" />
              )}
              {summary.blockingEnabled ? "Pause blocking" : "Resume blocking"}
            </Button>
          ) : null}
        </div>
        <Button onClick={() => void load()} disabled={loading}>
          <RefreshCw className={cn("size-3.5", loading && "animate-spin")} />
          Refresh
        </Button>
      </div>

      {summary.available && !error ? null : <Unavailable error={summary.error ?? error} />}

      <div className="flex gap-3">
        <Tile label="Queries" value={summary.totals.queries} />
        <Tile
          label="Blocked"
          value={summary.totals.blocked}
          tone={summary.totals.blocked > 0 ? "text-block" : undefined}
        />
        <Tile label="Cached" value={summary.totals.cached} />
        <Tile label="Forwarded" value={summary.totals.forwarded} />
        <Tile label="Clients" value={summary.totals.clients} />
      </div>

      <div className="flex gap-6">
        <TopList title="Top domains (allowed)" rows={summary.topDomains} head="queries" />
        <TopList
          title="Top blocked domains"
          rows={summary.blockedDomains}
          head="blocked"
          tone="text-block"
        />
        <TopList title="Top clients" rows={summary.topClients} head="queries" showBlocked />
      </div>

      {summary.available ? (
        <div className="flex justify-end">
          <Button
            size="sm"
            variant="outline"
            onClick={() => openAssistant({ kind: "dns", id: "current" })}
          >
            <MessageSquare className="h-3.5 w-3.5" /> Ask assistant
          </Button>
        </div>
      ) : null}

      <div className="min-h-0">
        <SectionTitle>Recent queries</SectionTitle>
        {summary.recent.length === 0 ? (
          <p className="px-1 py-2 text-[12px] text-ink-dim">No queries in this window.</p>
        ) : (
          <table className="w-full text-[12px]">
            <tbody>
              {summary.recent.map((query) => (
                <tr key={query.id} className="border-b border-edge/50 last:border-0">
                  <td className="w-14 py-1 tabular-nums text-ink-dim">{shortAge(query.at)}</td>
                  <td className="w-36 truncate py-1 pr-2 text-ink-dim">{query.client}</td>
                  <td className="truncate py-1 pr-2 text-ink" title={query.domain}>
                    {query.domain}
                  </td>
                  <td className="w-14 py-1 text-ink-dim">{query.type}</td>
                  <td className="w-24 py-1 text-right">
                    <Badge className={STATUS_TONE[query.status]}>{query.status}</Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
