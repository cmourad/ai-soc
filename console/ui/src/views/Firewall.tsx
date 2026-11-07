import { Loader2, ShieldOff, TriangleAlert } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Button, Card, SectionTitle } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useStore } from "@/store";

/**
 * What is actually enforced right now, read from the agent's nft table.
 *
 * The console cannot write that table — the agent owns it — so this view is
 * deliberately read-plus-lift: it shows the live elements and can ask the agent
 * to drop one, and nothing here can invent a block that skipped Guard.
 */

interface Blocked {
  ip: string;
  set: string;
  timeout: number | null;
  expires: number | null;
}

const REFRESH_MS = 10_000;

/** nft counts down in seconds; an element with no timeout never expires. */
function remaining(seconds: number | null): string {
  if (seconds === null) return "no expiry";
  if (seconds <= 0) return "expiring";
  const days = Math.floor(seconds / 86_400);
  if (days > 0) return `${days}d ${Math.floor((seconds % 86_400) / 3600)}h`;
  const hours = Math.floor(seconds / 3600);
  if (hours > 0) return `${hours}h ${Math.floor((seconds % 3600) / 60)}m`;
  const minutes = Math.floor(seconds / 60);
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

function originalLifetime(seconds: number | null): string {
  if (seconds === null) return "—";
  if (seconds >= 86_400) return `${Math.round(seconds / 86_400)}d`;
  if (seconds >= 3600) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 60)}m`;
}

export function FirewallView() {
  const pushToast = useStore((s) => s.pushToast);
  const [blocked, setBlocked] = useState<Blocked[]>([]);
  const [protectedIps, setProtectedIps] = useState<string[]>([]);
  const [budget, setBudget] = useState({ used: 0, max: 0 });
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [lifting, setLifting] = useState<string | null>(null);

  const load = useCallback(() => {
    api
      .firewall()
      .then((state) => {
        if (!state.ok) {
          setError(state.error ?? "the agent did not answer");
          return;
        }
        setError(null);
        setBlocked(state.blocked);
        setProtectedIps(state.protected);
        setBudget({ used: state.blocksLastHour, max: state.maxBlocksPerHour });
      })
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, REFRESH_MS);
    return () => clearInterval(timer);
  }, [load]);

  const lift = (ip: string) => {
    setLifting(ip);
    api
      .firewallUnblock(ip)
      .then(() => {
        pushToast("success", `Asked the agent to unblock ${ip}.`);
        load();
      })
      .catch((err: Error) => pushToast("error", err.message))
      .finally(() => setLifting(null));
  };

  return (
    <div className="h-full overflow-y-auto">
      <div className="flex flex-col gap-4 p-4">
        {error ? (
          <Card className="border-[#5a2d2d]">
            <div className="flex items-start gap-2 text-block">
              <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" />
              <div className="flex flex-col gap-1">
                <span className="font-semibold">The agent's control socket is unreachable.</span>
                <span className="font-mono text-[11px] text-ink-dim">{error}</span>
                <span className="text-[11px] text-ink-dim">
                  Enforcement is unaffected — the agent blocks on its own. Only this view and the
                  console's response actions need the socket.
                </span>
              </div>
            </div>
          </Card>
        ) : null}

        <div>
          <SectionTitle>
            Enforced blocks{blocked.length > 0 ? ` · ${blocked.length}` : ""}
          </SectionTitle>
          <Card>
            {loading ? (
              <div className="flex items-center gap-2 text-ink-dim">
                <Loader2 className="h-3 w-3 animate-spin" /> reading the nft table
              </div>
            ) : blocked.length === 0 ? (
              <span className="text-ink-dim">
                Nothing is blocked. The table is armed and empty.
              </span>
            ) : (
              <table className="w-full text-left">
                <thead className="text-[10px] uppercase text-ink-dim">
                  <tr>
                    <th className="pb-2 font-normal">address</th>
                    <th className="pb-2 font-normal">set</th>
                    <th className="pb-2 font-normal">lifetime</th>
                    <th className="pb-2 font-normal">expires in</th>
                    <th className="pb-2" />
                  </tr>
                </thead>
                <tbody>
                  {blocked.map((entry) => (
                    <tr key={`${entry.set}-${entry.ip}`} className="border-t border-edge">
                      <td className="py-2 font-mono text-ink">{entry.ip}</td>
                      <td className="py-2 text-ink-dim">{entry.set}</td>
                      <td className="py-2 text-ink-dim">{originalLifetime(entry.timeout)}</td>
                      <td
                        className={cn(
                          "py-2",
                          entry.expires !== null && entry.expires < 600
                            ? "text-watch"
                            : "text-ink-dim",
                        )}
                      >
                        {remaining(entry.expires)}
                      </td>
                      <td className="py-2 text-right">
                        <Button
                          variant="danger"
                          disabled={lifting === entry.ip}
                          onClick={() => lift(entry.ip)}
                        >
                          {lifting === entry.ip ? (
                            <Loader2 className="h-3 w-3 animate-spin" />
                          ) : (
                            <ShieldOff className="h-3 w-3" />
                          )}
                          unblock
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </div>

        <div>
          <SectionTitle>Block budget</SectionTitle>
          <Card>
            <span className={budget.used >= budget.max ? "text-block" : "text-ink"}>
              {budget.used} of {budget.max} blocks used in the last hour
            </span>
            <span className="ml-2 text-[11px] text-ink-dim">
              The cap applies to the agent and the console alike — a runaway model and a runaway
              playbook fail the same way.
            </span>
          </Card>
        </div>

        <div>
          <SectionTitle>Never blockable · {protectedIps.length}</SectionTitle>
          <Card>
            <p className="mb-2 text-[11px] text-ink-dim">
              Refreshed by the agent every five minutes from this host's own addresses, the default
              gateway, the resolvers and allowlist.txt. Loopback, multicast, link-local and the
              docker bridge range are refused by shape rather than by list.
            </p>
            <div className="flex flex-wrap gap-1.5">
              {protectedIps.map((ip) => (
                <span
                  key={ip}
                  className="rounded-sm border border-edge px-1.5 py-0.5 font-mono text-[11px] text-ink-dim"
                >
                  {ip}
                </span>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
