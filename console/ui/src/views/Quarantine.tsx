import type { ListEntry } from "@aisoc/shared";
import { formatBytes } from "@aisoc/shared";
import { Check, FileLock2, Globe, Network, Plus, Trash2, Undo2 } from "lucide-react";
import { useState } from "react";
import { Badge, Button, Input, SectionTitle, Select } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { cn, timeOf } from "@/lib/utils";
import { useStore } from "@/store";

const KIND_ICON = {
  file: FileLock2,
  ip: Network,
  domain: Globe,
  process: FileLock2,
} as const;

function Vault() {
  const quarantine = useStore((s) => s.quarantine);
  const assets = useStore((s) => s.assets);
  const analyst = useStore((s) => s.analyst);
  const pushToast = useStore((s) => s.pushToast);
  const selectAlert = useStore((s) => s.selectAlert);
  const setView = useStore((s) => s.setView);
  const [busy, setBusy] = useState<string | null>(null);
  const [showReleased, setShowReleased] = useState(false);

  const items = [...quarantine]
    .filter((item) => showReleased || item.status === "held")
    .sort((a, b) => b.quarantinedAt.localeCompare(a.quarantinedAt));

  const act = (id: string, restore: boolean) => {
    setBusy(id);
    const call = restore ? api.restoreQuarantine(id, analyst) : api.deleteQuarantine(id, analyst);
    call
      .then(() => pushToast("success", restore ? "Restored." : "Deleted permanently."))
      .catch((error: Error) => pushToast("error", error.message))
      .finally(() => setBusy(null));
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex shrink-0 items-center gap-2 border-b border-edge bg-panel px-3 py-1.5">
        <SectionTitle>Quarantine vault</SectionTitle>
        <button
          type="button"
          onClick={() => setShowReleased(!showReleased)}
          className={cn(
            "ml-auto rounded-sm px-2 py-0.5 text-[11px] transition-colors",
            showReleased ? "bg-active text-ink" : "text-ink-dim hover:text-ink",
          )}
        >
          show released
        </button>
      </div>

      <div className="grid shrink-0 grid-cols-[16px_54px_1fr_120px_90px_140px] gap-2 border-b border-edge bg-panel px-3 py-1 text-[10px] uppercase tracking-wide text-ink-dim">
        <span />
        <span>held</span>
        <span>item</span>
        <span>host</span>
        <span>status</span>
        <span />
      </div>

      <div className="flex-1 overflow-y-auto">
        {items.length === 0 ? (
          <p className="p-6 text-center text-xs text-ink-dim">
            Nothing in the vault. Applied block and quarantine actions land here, and everything is
            reversible from this page.
          </p>
        ) : (
          items.map((item) => {
            const Icon = KIND_ICON[item.kind];
            const asset = assets.find((entry) => entry.id === item.assetId);
            return (
              <div
                key={item.id}
                className="row-in grid grid-cols-[16px_54px_1fr_120px_90px_140px] items-center gap-2 border-b border-edge/60 px-3 py-1.5 text-[11px] hover:bg-hover"
              >
                <Icon className="h-3.5 w-3.5 text-ink-dim" />
                <span className="font-mono text-[10px] text-ink-dim tabular-nums">
                  {timeOf(item.quarantinedAt)}
                </span>
                <span className="min-w-0">
                  <span className="block truncate font-mono text-ink" title={item.value}>
                    {item.value}
                  </span>
                  <span className="block truncate text-[10px] text-ink-dim">
                    {item.reason}
                    {item.sizeBytes ? ` · ${formatBytes(item.sizeBytes)}` : ""}
                  </span>
                  {item.sha256 ? (
                    <span className="block truncate font-mono text-[10px] text-ink-dim">
                      {item.sha256}
                    </span>
                  ) : null}
                </span>
                <span className="truncate font-mono text-[10px] text-ink-dim">
                  {asset?.hostname ?? "—"}
                </span>
                <Badge
                  className={cn(
                    "font-mono",
                    item.status === "held"
                      ? "border-[#7a5a2d] text-sev2"
                      : item.status === "restored"
                        ? "border-[#2d5a3d] text-ignore"
                        : "border-edge text-ink-dim",
                  )}
                >
                  {item.status}
                </Badge>
                <span className="flex justify-end gap-1">
                  {item.status === "held" ? (
                    <>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={busy === item.id}
                        onClick={() => act(item.id, true)}
                      >
                        <Undo2 className="h-3 w-3" />
                        restore
                      </Button>
                      <Button
                        size="sm"
                        variant="danger"
                        disabled={busy === item.id}
                        onClick={() => act(item.id, false)}
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </>
                  ) : null}
                  {item.alertId ? (
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => {
                        selectAlert(item.alertId!);
                        setView("triage");
                      }}
                    >
                      alert
                    </Button>
                  ) : null}
                </span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

function ListColumn({ list, entries }: { list: "allow" | "block"; entries: ListEntry[] }) {
  const analyst = useStore((s) => s.analyst);
  const pushToast = useStore((s) => s.pushToast);
  const [kind, setKind] = useState("ip");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");

  const own = entries.filter((entry) => entry.list === list);

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="shrink-0 border-b border-edge bg-panel px-3 py-1.5">
        <SectionTitle>{list === "allow" ? "Allowlist" : "Blocklist"}</SectionTitle>
        <p className="-mt-1 mb-2 text-[10px] leading-snug text-ink-dim">
          {list === "allow"
            ? "Suppresses detection scoring and hard-refuses any response action against the indicator — checked before autonomy, so full autonomy cannot override it."
            : "Resolves matching traffic to BLOCK before any model is consulted."}
        </p>
        <div className="flex items-end gap-1.5">
          <Select
            className="w-28"
            value={kind}
            onValueChange={setKind}
            options={[
              { value: "ip", label: "IP" },
              { value: "domain", label: "domain" },
              { value: "hash", label: "hash" },
              { value: "signature", label: "signature" },
            ]}
          />
          <Input
            className="flex-1"
            value={value}
            placeholder="indicator"
            onChange={(event) => setValue(event.target.value)}
          />
          <Input
            className="flex-1"
            value={note}
            placeholder="note"
            onChange={(event) => setNote(event.target.value)}
          />
          <Button
            size="md"
            variant="secondary"
            disabled={!value.trim()}
            onClick={() => {
              api
                .addListEntry({ list, kind, value: value.trim(), note, by: analyst })
                .then(() => {
                  setValue("");
                  setNote("");
                  pushToast("success", `Added to the ${list}list.`);
                })
                .catch((error: Error) => pushToast("error", error.message));
            }}
          >
            <Plus className="h-3 w-3" />
          </Button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {own.map((entry) => (
          <div
            key={entry.id}
            className="flex items-center gap-2 border-b border-edge/60 px-3 py-1.5 text-[11px] hover:bg-hover"
          >
            <Badge className="shrink-0 text-ink-dim">{entry.kind}</Badge>
            <span className="min-w-0">
              <span className="block truncate font-mono text-ink">{entry.value}</span>
              <span className="block truncate text-[10px] text-ink-dim">
                {entry.note || "no note"} · {entry.addedBy}
              </span>
            </span>
            <Button
              size="icon"
              variant="ghost"
              className="ml-auto shrink-0"
              aria-label="Remove entry"
              onClick={() =>
                api
                  .removeListEntry(entry.id, analyst)
                  .catch((error: Error) => pushToast("error", error.message))
              }
            >
              <Trash2 className="h-3 w-3" />
            </Button>
          </div>
        ))}
        {own.length === 0 ? <p className="p-4 text-center text-xs text-ink-dim">Empty.</p> : null}
      </div>
    </div>
  );
}

export function QuarantineView() {
  const lists = useStore((s) => s.lists);
  const [tab, setTab] = useState<"vault" | "lists">("vault");
  const stats = useStore((s) => s.stats);

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 items-center gap-2 border-b border-edge bg-panel px-3 py-1.5">
        {(["vault", "lists"] as const).map((value) => (
          <button
            key={value}
            type="button"
            onClick={() => setTab(value)}
            className={cn(
              "rounded-sm px-2 py-0.5 text-[11px] transition-colors",
              tab === value ? "bg-active text-ink" : "text-ink-dim hover:text-ink",
            )}
          >
            {value === "vault" ? "quarantine vault" : "allow / blocklist"}
            <span className="ml-1.5 font-mono text-[10px] tabular-nums opacity-70">
              {value === "vault" ? (stats?.quarantined ?? 0) : lists.length}
            </span>
          </button>
        ))}
        <span className="ml-auto flex items-center gap-1.5 text-[10px] text-ink-dim">
          <Check className="h-3 w-3 text-ignore" />
          nothing here is destroyed on the way in — every hold is reversible
        </span>
      </div>

      {tab === "vault" ? (
        <Vault />
      ) : (
        <div className="flex min-h-0 flex-1 divide-x divide-edge">
          <ListColumn list="allow" entries={lists} />
          <ListColumn list="block" entries={lists} />
        </div>
      )}
    </div>
  );
}
