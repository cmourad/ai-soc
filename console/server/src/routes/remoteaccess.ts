import type { FastifyInstance } from "fastify";
import {
  preflightRemoteAccess,
  refreshRemoteAccess,
  setRemoteAccessWanted,
} from "../remoteaccess/manager.js";
import { addAudit } from "../store.js";

/** Tailnet reachability for the console itself. */
export function registerRemoteAccessRoutes(app: FastifyInstance): void {
  // --- Remote access (tailnet) -------------------------------------------------

  app.get("/api/remoteaccess", async () => ({
    state: await refreshRemoteAccess(),
  }));

  app.get("/api/remoteaccess/preflight", async () => preflightRemoteAccess());

  app.post("/api/remoteaccess/up", async (request) => {
    const { ok, state } = await setRemoteAccessWanted(true);
    addAudit(request.actor, "remoteaccess.up", "tailnet", "Remote access enabled.", ok);
    return { ok, state };
  });

  app.post("/api/remoteaccess/down", async (request) => {
    const { ok, state } = await setRemoteAccessWanted(false);
    addAudit(request.actor, "remoteaccess.down", "tailnet", "Remote access disabled.", ok);
    return { ok, state };
  });
}
