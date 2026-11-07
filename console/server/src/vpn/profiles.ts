import { randomUUID } from "node:crypto";
import type { VpnProfile } from "@aisoc/shared";
import { setSecret } from "../crypto.js";
import { addAudit, listVpnProfiles, setVpnProfiles } from "../store.js";
import { nameFromSource, parseWireGuardConfig } from "./config-parse.js";
import { publishVpnState } from "./publish.js";

/**
 * Imported provider profiles.
 *
 * The private key and any preshared key are moved into the encrypted secret
 * store the moment the config is parsed, and the profile object that gets
 * persisted and broadcast holds only references to them. That means key
 * material never reaches `state.json`, never reaches the websocket, and never
 * reaches the browser — the same contract the API keys already have.
 */

export function importProfile(input: {
  config: string;
  source: string;
  name: string;
  by: string;
}): { profile: VpnProfile; warnings: string[] } {
  const parsed = parseWireGuardConfig(input.config);
  const id = randomUUID();
  const privateKeySecret = `vpn.profile.${id}.privateKey`;
  const presharedKeySecret = parsed.presharedKey ? `vpn.profile.${id}.presharedKey` : null;

  setSecret(privateKeySecret, parsed.privateKey);
  if (presharedKeySecret && parsed.presharedKey) {
    setSecret(presharedKeySecret, parsed.presharedKey);
  }

  const profile: VpnProfile = {
    id,
    name: input.name.trim() || nameFromSource(input.source, parsed.endpointHost),
    host: parsed.endpointHost,
    port: parsed.endpointPort,
    peerPublicKey: parsed.peerPublicKey,
    addresses: parsed.addresses,
    dns: parsed.dns,
    mtu: parsed.mtu,
    allowedIps: parsed.allowedIps,
    persistentKeepalive: parsed.persistentKeepalive,
    hasPresharedKey: Boolean(parsed.presharedKey),
    privateKeySecret,
    presharedKeySecret,
    createdAt: new Date().toISOString(),
    source: input.source || "pasted config",
  };

  setVpnProfiles([...listVpnProfiles(), profile]);
  publishVpnState();
  addAudit(
    input.by,
    "vpn.profile.import",
    profile.name,
    `Imported a WireGuard profile for ${profile.host}:${profile.port}; key material stored encrypted.`,
  );
  return { profile, warnings: parsed.warnings };
}

export function removeProfile(id: string, by: string): VpnProfile | null {
  const profile = listVpnProfiles().find((entry) => entry.id === id);
  if (!profile) return null;

  // Clearing the secrets is the point of removal — a forgotten private key on
  // disk is worse than a stale profile row.
  setSecret(profile.privateKeySecret, "");
  if (profile.presharedKeySecret) setSecret(profile.presharedKeySecret, "");

  setVpnProfiles(listVpnProfiles().filter((entry) => entry.id !== id));
  publishVpnState();
  addAudit(by, "vpn.profile.remove", profile.name, "Profile deleted and its keys wiped.");
  return profile;
}

export function getProfile(id: string): VpnProfile | undefined {
  return listVpnProfiles().find((entry) => entry.id === id);
}
