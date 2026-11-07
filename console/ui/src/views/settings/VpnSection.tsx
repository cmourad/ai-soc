import type { Settings } from "@aisoc/shared";
import {
  Card,
  Field,
  Input,
  ListEditor,
  SectionTitle,
  Select,
  Switch,
} from "@/components/ui/primitives";
import type { SettingsSectionProps } from "./shared";

export function VpnSection({ draft, patch }: SettingsSectionProps) {
  return (
    <Card className="flex flex-col gap-3">
      <SectionTitle>VPN</SectionTitle>
      <Switch
        checked={draft.vpn.enabled}
        onCheckedChange={(enabled) => patch("vpn", { enabled })}
        label="VPN enabled"
        hint="Exposes the VPN view and lets the console bring tunnels up."
      />
      <Switch
        checked={draft.vpn.autoConnect}
        onCheckedChange={(autoConnect) => patch("vpn", { autoConnect })}
        label="Connect on startup"
        hint="Brings the preferred exit up as soon as the backend starts."
      />
      <Switch
        checked={draft.vpn.killSwitch}
        onCheckedChange={(killSwitch) => patch("vpn", { killSwitch })}
        label="Kill switch"
        hint="Routes everything into the tunnel, so a drop leaves no route rather than silently falling back to direct traffic. Turning this off means a dropped tunnel leaks."
      />
      <Switch
        checked={draft.vpn.reconnectOnDrop}
        onCheckedChange={(reconnectOnDrop) => patch("vpn", { reconnectOnDrop })}
        label="Reconnect automatically"
        hint="Re-dials the same exit when a handshake goes stale."
      />
      <Switch
        checked={draft.vpn.dnsLeakProtection}
        onCheckedChange={(dnsLeakProtection) => patch("vpn", { dnsLeakProtection })}
        label="DNS leak protection"
        hint="Sends lookups through the tunnel's resolver. Without it every domain visited is still visible locally."
      />

      <div className="grid grid-cols-2 gap-3">
        <Field label="Protocol">
          <Select
            value={draft.vpn.protocol}
            onValueChange={(protocol) =>
              patch("vpn", { protocol: protocol as Settings["vpn"]["protocol"] })
            }
            options={[
              { value: "wireguard", label: "WireGuard" },
              { value: "openvpn", label: "OpenVPN" },
            ]}
          />
        </Field>
        <Field
          label="Preferred country"
          hint="Quick connect stays in this country. Empty means anywhere."
        >
          <Input
            value={draft.vpn.preferredCountry}
            placeholder="e.g. Switzerland or CH"
            onChange={(event) => patch("vpn", { preferredCountry: event.target.value })}
          />
        </Field>
      </div>

      <div className="grid grid-cols-3 gap-3">
        <Field label="Interface" hint="Letters, digits, dash, underscore.">
          <Input
            value={draft.vpn.interfaceName}
            onChange={(event) => patch("vpn", { interfaceName: event.target.value })}
          />
        </Field>
        <Field label="Tunnel DNS">
          <Input
            value={draft.vpn.dns}
            onChange={(event) => patch("vpn", { dns: event.target.value })}
          />
        </Field>
        <Field
          label="Execution"
          hint="Simulate changes no routes. wg-quick needs an imported profile."
        >
          <Select
            value={draft.vpn.execution}
            onValueChange={(execution) =>
              patch("vpn", { execution: execution as Settings["vpn"]["execution"] })
            }
            options={[
              { value: "simulate", label: "simulate — describe only" },
              { value: "wg-quick", label: "wg-quick — bring the tunnel up" },
            ]}
          />
        </Field>
      </div>

      <Field
        label="Split tunnelling"
        hint="Include routes only the listed networks through the tunnel; exclude routes everything except them. Ignored while the kill switch is on, which always routes everything."
      >
        <Select
          value={draft.vpn.splitTunnel.mode}
          onValueChange={(mode) =>
            patch("vpn", {
              splitTunnel: {
                ...draft.vpn.splitTunnel,
                mode: mode as Settings["vpn"]["splitTunnel"]["mode"],
              },
            })
          }
          options={[
            { value: "off", label: "off — route everything" },
            { value: "exclude", label: "exclude — bypass these networks" },
            { value: "include", label: "include — route only these networks" },
          ]}
        />
      </Field>
      <ListEditor
        label="Split-tunnel networks"
        hint="IPv4 CIDRs."
        values={draft.vpn.splitTunnel.networks}
        onChange={(networks) =>
          patch("vpn", { splitTunnel: { ...draft.vpn.splitTunnel, networks } })
        }
        placeholder="192.0.2.0/24"
      />

      <p className="text-[10px] leading-snug text-ink-dim">
        Real tunnel mutation requires the dedicated VPN helper. The console never invokes sudo; keep
        execution simulated until that helper is installed.
      </p>
      <p className="text-[10px] leading-snug text-ink-dim">
        Real tunnels use profiles imported on the VPN page — each carries its own keys. The built-in
        exit list is demo data with no servers behind it.
      </p>
    </Card>
  );
}
