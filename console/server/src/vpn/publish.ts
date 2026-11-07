import { broadcast } from "../bus.js";
import { getSettings } from "../settings.js";
import { getVpn, listVpnProfiles } from "../store.js";
import { listServers } from "./servers.js";

/**
 * The tunnel message carries the exit catalogue alongside the connection,
 * because its load and latency move on their own timer rather than with the
 * state the store holds. Publishing lives here so the store never has to reach
 * into the VPN feature to describe its own change.
 */
export function publishVpnState(): void {
  broadcast({
    type: "vpn",
    connection: getVpn(),
    servers: listServers(getSettings().site),
    profiles: listVpnProfiles(),
  });
}
