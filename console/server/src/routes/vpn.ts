import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { broadcast } from "../bus.js";
import { describeError } from "../http.js";
import { getSettings } from "../settings.js";
import {
  preflight,
  previewConfig,
  connect as vpnConnect,
  disconnect as vpnDisconnect,
} from "../vpn/manager.js";
import { importProfile, removeProfile } from "../vpn/profiles.js";
import { listServers } from "../vpn/servers.js";

/** WireGuard tunnel lifecycle and profile import. */
export function registerVpnRoutes(app: FastifyInstance): void {
  // --- VPN --------------------------------------------------------------------

  app.get("/api/vpn/servers", async () => {
    const { site } = getSettings();
    return listServers({ lat: site.lat, lon: site.lon });
  });

  /** The exact WireGuard config the current settings produce, with the key redacted. */

  app.get<{ Querystring: { serverId?: string; profileId?: string } }>(
    "/api/vpn/config",
    async (request) => ({
      config: previewConfig({
        serverId: request.query.serverId ?? null,
        profileId: request.query.profileId ?? null,
      }),
    }),
  );

  /** Everything that must be true before a real tunnel can come up. */

  app.get("/api/vpn/preflight", async () => preflight());

  const importBody = z.object({
    config: z.string().min(1).max(20_000),
    source: z.string().max(200).default(""),
    name: z.string().max(120).default(""),
  });

  app.post("/api/vpn/profiles", async (request, reply) => {
    const parsed = importBody.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, error: describeError(parsed.error) });
    }
    try {
      const { profile, warnings } = importProfile({ ...parsed.data, by: request.actor });
      broadcast({
        type: "toast",
        level: "success",
        message: `Imported "${profile.name}" — ${profile.host}:${profile.port}`,
      });
      return { ok: true, profile, warnings };
    } catch (error) {
      return reply.code(400).send({ ok: false, error: describeError(error) });
    }
  });

  app.post<{ Params: { id: string } }>("/api/vpn/profiles/:id/remove", async (request, reply) => {
    if (!removeProfile(request.params.id, request.actor)) {
      return reply.code(404).send({ ok: false, error: "unknown profile" });
    }
    return { ok: true };
  });

  const vpnConnectBody = z.object({
    serverId: z.string().max(100).nullable().default(null),
    profileId: z.string().max(100).nullable().default(null),
  });

  app.post("/api/vpn/connect", async (request, reply) => {
    const parsed = vpnConnectBody.safeParse(request.body ?? {});
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, error: describeError(parsed.error) });
    }
    try {
      const connection = await vpnConnect(
        { serverId: parsed.data.serverId, profileId: parsed.data.profileId },
        request.actor,
      );
      if (connection.status === "error") {
        return reply.code(502).send({ ok: false, error: connection.error, connection });
      }
      return { ok: true, connection };
    } catch (error) {
      return reply.code(400).send({ ok: false, error: describeError(error) });
    }
  });

  app.post("/api/vpn/disconnect", async (request) => {
    return { ok: true, connection: await vpnDisconnect(request.actor) };
  });
}
