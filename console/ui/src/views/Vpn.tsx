import type { VpnProfile, VpnServer, VpnStatus } from "@aisoc/shared";
import { formatBytes } from "@aisoc/shared";
import { Gauge, Loader2, Lock, Power, ShieldOff, Star, Trash2, Unlock, Upload } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { ReadinessChecklist } from "@/components/ReadinessChecklist";
import { Badge, Button, Field, Input, SectionTitle, Textarea } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { cn, shortAge } from "@/lib/utils";
import { useStore } from "@/store";

const STATUS_COPY: Record<VpnStatus, { label: string; tone: string; dot: string }> = {
  connected: { label: "Protected", tone: "text-ignore", dot: "bg-ignore" },
  connecting: { label: "Connecting", tone: "text-watch", dot: "bg-watch" },
  reconnecting: { label: "Reconnecting", tone: "text-watch", dot: "bg-watch" },
  disconnected: { label: "Not protected", tone: "text-ink-dim", dot: "bg-ink-dim" },
  error: { label: "Tunnel failed", tone: "text-block", dot: "bg-block" },
};

function flagOf(countryCode: string): string {
  // Regional-indicator arithmetic: 'A' → U+1F1E6.
  return String.fromCodePoint(
    ...[...countryCode.toUpperCase()].map((ch) => 0x1_f1_a5 + ch.charCodeAt(0)),
  );
}

function StatusPanel() {
  const vpn = useStore((s) => s.vpn);
  const servers = useStore((s) => s.vpnServers);
  const settings = useStore((s) => s.settings);
  const profiles = useStore((s) => s.vpnProfiles);
  const analyst = useStore((s) => s.analyst);
  const pushToast = useStore((s) => s.pushToast);
  const setView = useStore((s) => s.setView);
  const [busy, setBusy] = useState(false);

  if (!vpn) return null;
  const status = STATUS_COPY[vpn.status];
  const server = servers.find((entry) => entry.id === vpn.serverId);
  const profile = profiles.find((entry) => entry.id === vpn.profileId);
  const connected = vpn.status === "connected";
  const working = vpn.status === "connecting" || vpn.status === "reconnecting";

  const toggle = () => {
    setBusy(true);
    const call =
      connected || working
        ? api.vpnDisconnect(analyst)
        : api.vpnConnect({ profileId: profiles[0]?.id ?? null }, analyst);
    call
      .then(() => pushToast("success", connected ? "Tunnel down." : "Tunnel up."))
      .catch((error: Error) => pushToast("error", error.message))
      .finally(() => setBusy(false));
  };

  return (
    <div className="flex flex-col gap-3 rounded-sm border border-edge bg-panel p-4">
      <div className="flex items-center gap-3">
        <span className="relative flex h-3 w-3 items-center justify-center">
          <span className={cn("h-2.5 w-2.5 rounded-full", status.dot, working && "pulse")} />
        </span>
        <span className={cn("text-lg font-semibold", status.tone)}>{status.label}</span>
        {vpn.simulated && connected ? (
          <Badge className="border-[#7a5a2d] text-sev2" title="No routes were changed">
            simulated
          </Badge>
        ) : null}
        {settings.vpn.killSwitch ? (
          <Badge
            className={cn(vpn.killSwitchEngaged ? "border-[#7a2d2d] text-block" : "text-ink-dim")}
            title={
              settings.vpn.execution === "simulate"
                ? "Simulate mode changes no routes, so the kill switch is configuration only."
                : "Routes everything into the tunnel, so a drop leaves no route."
            }
          >
            kill switch{" "}
            {vpn.killSwitchEngaged
              ? "engaged"
              : settings.vpn.execution === "simulate"
                ? "configured"
                : "armed"}
          </Badge>
        ) : (
          <Badge className="border-[#7a5a2d] text-sev2">kill switch off</Badge>
        )}

        <Button
          className="ml-auto min-w-32"
          variant={connected ? "danger" : "primary"}
          disabled={busy || !settings.vpn.enabled}
          onClick={toggle}
        >
          {busy || working ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : connected ? (
            <ShieldOff className="h-3 w-3" />
          ) : (
            <Power className="h-3 w-3" />
          )}
          {connected ? "disconnect" : working ? "connecting…" : "quick connect"}
        </Button>
      </div>

      {!settings.vpn.enabled ? (
        <p className="rounded-sm border border-[#7a5a2d] bg-[#2a2113] px-2 py-1.5 text-[11px] text-sev2">
          The VPN is disabled.{" "}
          <button type="button" className="underline" onClick={() => setView("settings")}>
            Enable it in Settings
          </button>{" "}
          to pick an exit.
        </p>
      ) : null}

      {vpn.error ? (
        <p className="rounded-sm border border-[#5a2d2d] bg-[#321e1e] px-2 py-1.5 text-[11px] text-[#f5b8b8]">
          {vpn.error}
        </p>
      ) : null}

      {vpn.killSwitchEngaged && !connected ? (
        <p className="rounded-sm border border-[#5a2d2d] bg-[#321e1e] px-2 py-1.5 text-[11px] text-[#f5b8b8]">
          Kill switch is holding egress down. Nothing leaves this host until a tunnel is back up, or
          until the kill switch is turned off in Settings.
        </p>
      ) : null}

      {vpn.status === "error" && !vpn.killSwitchEngaged ? (
        <p className="rounded-sm border border-edge bg-shell px-2 py-1.5 text-[11px] text-ink-dim">
          No routes were changed, so your normal internet connection is unaffected.
        </p>
      ) : null}

      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        <Fact
          label="Exit"
          value={
            profile ? profile.name : server ? `${flagOf(server.countryCode)} ${server.city}` : "—"
          }
          sub={profile ? `${profile.host}:${profile.port}` : (server?.country ?? "")}
        />
        <Fact
          label={profile ? "Endpoint" : "Public IP"}
          value={vpn.exitIp ?? "—"}
          sub={
            profile
              ? "the address the tunnel dials"
              : connected
                ? "as seen by the internet"
                : "direct"
          }
        />
        <Fact
          label="Uptime"
          value={vpn.connectedAt ? shortAge(vpn.connectedAt) : "—"}
          sub={vpn.lastHandshake ? `handshake ${shortAge(vpn.lastHandshake)} ago` : ""}
        />
        <Fact
          label="Transfer"
          value={`${formatBytes(vpn.bytesDown)} ↓`}
          sub={`${formatBytes(vpn.bytesUp)} ↑ on ${vpn.interfaceName}`}
        />
      </div>

      <div className="flex flex-wrap gap-x-5 gap-y-1 text-[10px] text-ink-dim">
        <span>protocol {settings.vpn.protocol}</span>
        <span>tunnel IP {vpn.tunnelIp ?? "—"}</span>
        <span>
          DNS{" "}
          {settings.vpn.dnsLeakProtection
            ? `${(profile?.dns.length ? profile.dns : [settings.vpn.dns]).join(", ")} (leak protection on)`
            : "system resolver"}
        </span>
        <span>
          split tunnel{" "}
          {settings.vpn.splitTunnel.mode === "off"
            ? "off — everything routed"
            : `${settings.vpn.splitTunnel.mode} ${settings.vpn.splitTunnel.networks.length} network(s)`}
        </span>
        <span>execution {settings.vpn.execution}</span>
      </div>
    </div>
  );
}

function Fact({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-sm border border-edge bg-shell px-2 py-1.5">
      <div className="text-[10px] uppercase tracking-wide text-ink-dim">{label}</div>
      <div className="truncate font-mono text-[13px] text-ink" title={value}>
        {value}
      </div>
      {sub ? <div className="truncate text-[10px] text-ink-dim">{sub}</div> : null}
    </div>
  );
}

function ServerRow({ server, active }: { server: VpnServer; active: boolean }) {
  const analyst = useStore((s) => s.analyst);
  const enabled = useStore((s) => s.settings.vpn.enabled);
  const pushToast = useStore((s) => s.pushToast);
  const [busy, setBusy] = useState(false);

  const loadTone = server.load >= 75 ? "bg-block" : server.load >= 45 ? "bg-watch" : "bg-ignore";

  return (
    <div
      className={cn(
        "row-in grid grid-cols-[28px_1fr_92px_80px_1fr_92px] items-center gap-2 border-b border-edge/60 px-3 py-1.5 text-[11px]",
        active ? "bg-active" : "hover:bg-hover",
      )}
    >
      <span className="text-base leading-none">{flagOf(server.countryCode)}</span>
      <span className="min-w-0">
        <span className="block truncate text-ink">
          {server.city}
          {active ? <span className="ml-1.5 text-[10px] text-ignore">· connected</span> : null}
        </span>
        <span className="block truncate text-[10px] text-ink-dim">{server.country}</span>
      </span>
      <span className="flex items-center gap-1.5 font-mono text-[10px] text-ink-dim tabular-nums">
        <Gauge className="h-3 w-3" />
        {server.latencyMs}ms
      </span>
      <span className="flex items-center gap-1.5">
        <span className="h-1 w-9 overflow-hidden rounded-full bg-edge">
          <span className={cn("block h-full", loadTone)} style={{ width: `${server.load}%` }} />
        </span>
        <span className="font-mono text-[10px] text-ink-dim tabular-nums">{server.load}%</span>
      </span>
      <span className="flex flex-wrap gap-1">
        {server.tags.map((tag) => (
          <Badge key={tag} className="text-ink-dim">
            {tag}
          </Badge>
        ))}
      </span>
      <Button
        size="sm"
        variant={active ? "secondary" : "outline"}
        disabled={busy || !enabled}
        onClick={() => {
          setBusy(true);
          api
            .vpnConnect({ serverId: server.id }, analyst)
            .then(() => pushToast("success", `Connected via ${server.city}.`))
            .catch((error: Error) => pushToast("error", error.message))
            .finally(() => setBusy(false));
        }}
      >
        {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : null}
        {active ? "reconnect" : "connect"}
      </Button>
    </div>
  );
}

function ConfigPreview() {
  const vpn = useStore((s) => s.vpn);
  const settings = useStore((s) => s.settings);
  const [config, setConfig] = useState("");
  const [open, setOpen] = useState(false);

  // The settings that actually change the generated file, as one primitive. It
  // both re-runs the fetch and gets shown under the config, so what you are
  // reading is always labelled with the inputs that produced it.
  const inputs = [
    settings.vpn.protocol,
    settings.vpn.interfaceName,
    settings.vpn.killSwitch ? "kill-switch" : "no-kill-switch",
    settings.vpn.dnsLeakProtection ? `dns ${settings.vpn.dns}` : "system dns",
    `split ${settings.vpn.splitTunnel.mode}`,
    ...settings.vpn.splitTunnel.networks,
  ].join(" · ");

  useEffect(() => {
    if (!open) return;
    void inputs;
    api
      .vpnConfig({ serverId: vpn?.serverId ?? null, profileId: vpn?.profileId ?? null })
      .then((result) => setConfig(result.config))
      .catch((error: Error) => setConfig(`# could not build a config: ${error.message}`));
  }, [open, vpn?.serverId, vpn?.profileId, inputs]);

  return (
    <div>
      <div className="flex items-center gap-2">
        <SectionTitle>Tunnel configuration</SectionTitle>
        <Button size="sm" variant="ghost" className="mb-2 ml-auto" onClick={() => setOpen(!open)}>
          {open ? "hide" : "show generated config"}
        </Button>
      </div>
      {open ? (
        <>
          <pre className="max-h-72 overflow-auto rounded-sm border border-edge bg-shell p-2 font-mono text-[11px] leading-relaxed text-ink">
            {config || "building…"}
          </pre>
          <p className="mt-1 font-mono text-[10px] text-ink-dim">built from: {inputs}</p>
          <p className="mt-1 text-[10px] leading-snug text-ink-dim">
            The private key is read from the encrypted secret store and never sent to this view. In
            exclude-mode split tunnelling, AllowedIPs is the computed complement of your excluded
            ranges — WireGuard has no "route everything except" syntax, so it has to be expanded.
          </p>
        </>
      ) : null}
    </div>
  );
}

/**
 * Four independent things can each block a real tunnel. `signature` re-checks
 * when the execution mode or the set of imported profiles changes.
 */
function VpnReadiness() {
  const execution = useStore((s) => s.settings.vpn.execution);
  const profiles = useStore((s) => s.vpnProfiles);
  return (
    <ReadinessChecklist
      load={api.vpnPreflight}
      signature={`${execution}:${profiles.length}`}
      successText="Everything needed for a real tunnel is in place."
    />
  );
}

function ImportProfile() {
  const analyst = useStore((s) => s.analyst);
  const pushToast = useStore((s) => s.pushToast);
  const [text, setText] = useState("");
  const [name, setName] = useState("");
  const [source, setSource] = useState("");
  const [busy, setBusy] = useState(false);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  const readFile = (file: File) => {
    setSource(file.name);
    if (!name) setName(file.name.replace(/\.conf$/i, ""));
    file
      .text()
      .then(setText)
      .catch(() => pushToast("error", "Could not read that file."));
  };

  const submit = () => {
    setBusy(true);
    setError(null);
    api
      .vpnImport({ config: text, source: source || "pasted config", name, by: analyst })
      .then((result) => {
        setText("");
        setName("");
        setSource("");
        setWarnings(result.warnings);
        pushToast("success", `Imported "${result.profile.name}".`);
      })
      .catch((problem: Error) => setError(problem.message))
      .finally(() => setBusy(false));
  };

  return (
    <div>
      <SectionTitle>Import a VPN profile</SectionTitle>
      <p className="-mt-1 mb-2 text-[10px] leading-snug text-ink-dim">
        Download a WireGuard config from your provider — Mullvad, ProtonVPN, IVPN and others all
        give you a <code>.conf</code> file — then drop it here or paste its contents. The private
        key is moved straight into the encrypted store and never sent back to this page.
      </p>

      <div className="flex flex-col gap-2 rounded-sm border border-edge bg-panel p-3">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name" hint="Optional — taken from the filename if left blank.">
            <Input
              value={name}
              placeholder="e.g. Mullvad Stockholm"
              onChange={(event) => setName(event.target.value)}
            />
          </Field>
          <Field label="Config file">
            <input
              type="file"
              accept=".conf,text/plain"
              className="h-7 w-full text-[11px] text-ink-dim file:mr-2 file:h-7 file:rounded-sm file:border file:border-edge file:bg-[#3a3d41] file:px-2 file:text-[11px] file:text-ink"
              onChange={(event) => {
                const file = event.target.files?.[0];
                if (file) readFile(file);
              }}
            />
          </Field>
        </div>

        <Field label="Or paste the config">
          <Textarea
            rows={8}
            value={text}
            spellCheck={false}
            placeholder={
              "[Interface]\nPrivateKey = ...\nAddress = 10.64.0.2/32\nDNS = 10.64.0.1\n\n[Peer]\nPublicKey = ...\nEndpoint = se-sto-wg-001.example.net:51820\nAllowedIPs = 0.0.0.0/0"
            }
            onChange={(event) => setText(event.target.value)}
            className="font-mono"
          />
        </Field>

        {error ? (
          <p className="rounded-sm border border-[#5a2d2d] bg-[#321e1e] px-2 py-1.5 text-[11px] text-[#f5b8b8]">
            {error}
          </p>
        ) : null}
        {warnings.length > 0 ? (
          <ul className="rounded-sm border border-[#7a5a2d] bg-[#2a2113] px-2 py-1.5 text-[10px] text-sev2">
            {warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        ) : null}

        <Button variant="primary" disabled={busy || !text.trim()} onClick={submit}>
          <Upload className="h-3 w-3" />
          {busy ? "importing…" : "import profile"}
        </Button>
      </div>
    </div>
  );
}

function ProfileList() {
  const profiles = useStore((s) => s.vpnProfiles);
  const vpn = useStore((s) => s.vpn);
  const enabled = useStore((s) => s.settings.vpn.enabled);
  const analyst = useStore((s) => s.analyst);
  const pushToast = useStore((s) => s.pushToast);
  const [busy, setBusy] = useState<string | null>(null);
  const live = vpn?.status === "connected";

  if (profiles.length === 0) return null;

  const act = (profile: VpnProfile, action: "connect" | "disconnect" | "remove") => {
    setBusy(profile.id);
    const call =
      action === "remove"
        ? api.vpnRemoveProfile(profile.id, analyst)
        : action === "disconnect"
          ? api.vpnDisconnect(analyst)
          : api.vpnConnect({ profileId: profile.id }, analyst);
    call
      .then(() =>
        pushToast(
          "success",
          action === "remove"
            ? "Profile removed."
            : action === "disconnect"
              ? "Tunnel down."
              : `Connecting via ${profile.name}.`,
        ),
      )
      .catch((error: Error) => pushToast("error", error.message))
      .finally(() => setBusy(null));
  };

  return (
    <div>
      <SectionTitle>Your VPN profiles</SectionTitle>
      <div className="flex flex-col gap-1">
        {profiles.map((profile) => (
          <div
            key={profile.id}
            className={cn(
              "rounded-sm border px-2 py-1.5",
              profile.id === vpn?.profileId && live
                ? "border-status bg-active"
                : "border-edge bg-panel",
            )}
          >
            <div className="flex items-center gap-2">
              <span className="truncate text-[11px] text-ink">{profile.name}</span>
              {profile.id === vpn?.profileId && live ? (
                <Badge className="border-[#2d5a3d] text-ignore">connected</Badge>
              ) : null}
              {profile.hasPresharedKey ? (
                <Badge className="text-ink-dim">preshared key</Badge>
              ) : null}
              <Button
                size="sm"
                variant={profile.id === vpn?.profileId && live ? "secondary" : "outline"}
                className="ml-auto shrink-0"
                disabled={busy === profile.id || !enabled}
                onClick={() =>
                  act(profile, profile.id === vpn?.profileId && live ? "disconnect" : "connect")
                }
              >
                {profile.id === vpn?.profileId && live ? "disconnect" : "connect"}
              </Button>
              <Button
                size="icon"
                variant="ghost"
                className="shrink-0"
                aria-label="Remove profile"
                disabled={busy === profile.id || (profile.id === vpn?.profileId && live)}
                onClick={() => act(profile, "remove")}
              >
                <Trash2 className="h-3 w-3" />
              </Button>
            </div>
            <div className="mt-0.5 flex flex-wrap gap-x-4 gap-y-0.5 text-[10px] text-ink-dim">
              <span className="font-mono">
                {profile.host}:{profile.port}
              </span>
              <span>address {profile.addresses.join(", ")}</span>
              {profile.dns.length > 0 ? <span>dns {profile.dns.join(", ")}</span> : null}
              <span className="truncate">from {profile.source}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function VpnView() {
  const servers = useStore((s) => s.vpnServers);
  const vpn = useStore((s) => s.vpn);
  const profiles = useStore((s) => s.vpnProfiles);
  const preferred = useStore((s) => s.settings.vpn.preferredCountry);
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<"latency" | "load" | "country">("latency");
  // Once there is a real profile the sample list is just noise, so it folds away
  // rather than filling the page below the thing the operator actually uses.
  const [showDemo, setShowDemo] = useState(profiles.length === 0);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const filtered = needle
      ? servers.filter((server) =>
          `${server.country} ${server.city} ${server.countryCode} ${server.tags.join(" ")}`
            .toLowerCase()
            .includes(needle),
        )
      : servers;
    return [...filtered].sort((a, b) => {
      if (sort === "load") return a.load - b.load;
      if (sort === "country") return a.country.localeCompare(b.country);
      return (a.latencyMs ?? 0) - (b.latencyMs ?? 0);
    });
  }, [servers, query, sort]);

  return (
    <div className="h-full overflow-y-auto">
      <div className="flex flex-col gap-4 p-4">
        <StatusPanel />

        <ImportProfile />
        <ProfileList />
        <VpnReadiness />

        <div>
          <div className="flex flex-wrap items-center gap-2">
            <SectionTitle>Demo exit servers</SectionTitle>
            <Button
              size="sm"
              variant="ghost"
              className="mb-2"
              onClick={() => setShowDemo(!showDemo)}
            >
              {showDemo ? "hide" : `show ${servers.length} sample exits`}
            </Button>
            <span className={cn("mb-2 flex items-center gap-2", !showDemo && "hidden")}>
              {(["latency", "load", "country"] as const).map((value) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => setSort(value)}
                  className={cn(
                    "rounded-sm px-2 py-0.5 text-[11px] transition-colors",
                    sort === value ? "bg-active text-ink" : "text-ink-dim hover:text-ink",
                  )}
                >
                  {value === "latency" ? "fastest" : value === "load" ? "quietest" : "A–Z"}
                </button>
              ))}
            </span>
            <Input
              className={cn("mb-2 ml-auto w-64", !showDemo && "hidden")}
              value={query}
              placeholder="country, city, or tag…"
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>

          {showDemo ? (
            <>
              <p className="mb-2 rounded-sm border border-[#7a5a2d] bg-[#2a2113] px-2 py-1.5 text-[10px] leading-snug text-sev2">
                These exits are sample data, not real servers — the hostnames do not resolve. They
                exist so the interface can be explored without an account, and they only work while
                execution is set to simulate. To tunnel for real, import a profile above.
              </p>

              {preferred ? (
                <p className="mb-1 flex items-center gap-1.5 text-[10px] text-ink-dim">
                  <Star className="h-3 w-3" />
                  Quick connect prefers {preferred} — the least loaded of the quickest third.
                </p>
              ) : null}

              <div className="overflow-hidden rounded-sm border border-edge">
                <div className="grid grid-cols-[28px_1fr_92px_80px_1fr_92px] gap-2 border-b border-edge bg-panel px-3 py-1 text-[10px] uppercase tracking-wide text-ink-dim">
                  <span />
                  <span>location</span>
                  <span>latency</span>
                  <span>load</span>
                  <span>features</span>
                  <span />
                </div>
                {visible.map((server) => (
                  <ServerRow key={server.id} server={server} active={server.id === vpn?.serverId} />
                ))}
                {visible.length === 0 ? (
                  <p className="bg-panel p-6 text-center text-xs text-ink-dim">
                    No exit matches that search.
                  </p>
                ) : null}
              </div>
            </>
          ) : null}
        </div>

        <PrivacyPosture />
        <ConfigPreview />
      </div>
    </div>
  );
}

/**
 * The security half of a VPN feature: what this tunnel does and does not
 * protect. A consumer client that only shows a green shield trains people to
 * believe things that are not true.
 */
function PrivacyPosture() {
  const settings = useStore((s) => s.settings);
  const vpn = useStore((s) => s.vpn);
  const profile = useStore((s) => s.vpnProfiles.find((entry) => entry.id === vpn?.profileId));
  const connected = vpn?.status === "connected";

  const rows = [
    {
      on: connected,
      label: "Traffic encrypted to the exit",
      detail: connected
        ? `Everything routed through ${vpn?.interfaceName} is encrypted between this host and the exit server.`
        : "No tunnel is up — traffic leaves this host in the clear.",
    },
    {
      on: settings.vpn.killSwitch && settings.vpn.execution !== "simulate",
      label: "Kill switch",
      detail: !settings.vpn.killSwitch
        ? "A dropped tunnel silently falls back to direct traffic."
        : settings.vpn.execution === "simulate"
          ? "Configured, but simulate mode installs no routes — nothing is being held down."
          : "Expressed as AllowedIPs = 0.0.0.0/0 on the peer, so a dropped tunnel leaves no route rather than falling back to the open network.",
    },
    {
      on: settings.vpn.dnsLeakProtection,
      label: "DNS leak protection",
      detail: settings.vpn.dnsLeakProtection
        ? `Lookups go to ${(profile?.dns.length ? profile.dns : [settings.vpn.dns]).join(", ")} inside the tunnel.`
        : "Lookups use the system resolver and reveal every domain visited, whatever the tunnel carries.",
    },
    {
      on: settings.vpn.splitTunnel.mode === "off",
      label: "Full-tunnel routing",
      detail:
        settings.vpn.splitTunnel.mode === "off"
          ? "Every destination goes through the tunnel."
          : `Split tunnelling is on (${settings.vpn.splitTunnel.mode}): ${settings.vpn.splitTunnel.networks.join(", ") || "no networks listed"} ${settings.vpn.splitTunnel.mode === "exclude" ? "bypass the tunnel" : "are the only traffic routed"}.`,
    },
    {
      on: !vpn?.simulated || !connected,
      label: "Routes actually applied",
      detail:
        connected && vpn?.simulated
          ? "Execution is set to simulate: the tunnel is described but no routes were changed. Nothing is actually encrypted."
          : "Execution applies the tunnel with wg-quick.",
    },
  ];

  return (
    <div>
      <SectionTitle>What this protects</SectionTitle>
      <div className="flex flex-col gap-1">
        {rows.map((row) => (
          <div
            key={row.label}
            className="flex items-start gap-2 rounded-sm border border-edge bg-panel px-2 py-1.5"
          >
            {row.on ? (
              <Lock className="mt-0.5 h-3 w-3 shrink-0 text-ignore" />
            ) : (
              <Unlock className="mt-0.5 h-3 w-3 shrink-0 text-sev2" />
            )}
            <span className="min-w-0">
              <span className={cn("block text-[11px]", row.on ? "text-ink" : "text-sev2")}>
                {row.label}
              </span>
              <span className="block text-[10px] leading-snug text-ink-dim">{row.detail}</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
