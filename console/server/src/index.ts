import type { ServerMessage } from "@aisoc/shared";
import { MITRE_TECHNIQUE_COUNT } from "@aisoc/shared";
import websocket from "@fastify/websocket";
import Fastify, { type FastifyInstance } from "fastify";
import { decayAllAssets, refreshAlertCounts, seedAssets } from "./assets.js";
import { installTrustBoundary, issueSession, originAllowed, remoteIdentity } from "./auth.js";
import { broadcast, subscribe } from "./bus.js";
import { PORT, REMOTE_PORT } from "./config.js";
import { startConsoleControlServer } from "./control.js";
import { defaultRulePacks } from "./detect/feeds.js";
import { RULE_COUNT } from "./detect/rules.js";
import {
  pollSensors,
  refreshLocalNetworkAddresses,
  syncClusterSource,
  syncSource,
} from "./ingest.js";
import { seedLists } from "./lists.js";
import { installNotificationDelivery } from "./notify/dispatch.js";
import { resumeIncidents } from "./notify/oncall.js";
import { attachPentestSocket } from "./pentest.js";
import { computeStats, snapshot } from "./projection.js";
import { configureRemoteAccess, refreshRemoteAccess } from "./remoteaccess/manager.js";
import { DEFAULT_PLAYBOOKS } from "./response/playbooks.js";
import { registerAlertRoutes } from "./routes/alerts.js";
import { registerAssetRoutes } from "./routes/assets.js";
import { registerAssistantRoutes } from "./routes/assistant.js";
import { registerCatalogRoutes } from "./routes/catalog.js";
import { registerCompassRoutes } from "./routes/compass.js";
import { registerControlRoutes } from "./routes/control.js";
import { registerCoreRoutes } from "./routes/core.js";
import { registerIncidentRoutes } from "./routes/incidents.js";
import { registerPentestRoutes } from "./routes/pentest.js";
import { registerRemoteAccessRoutes } from "./routes/remoteaccess.js";
import { registerReportRoutes } from "./routes/reports.js";
import { registerResponseRoutes } from "./routes/response.js";
import { registerVpnRoutes } from "./routes/vpn.js";
import { registerBuiltUi } from "./static.js";
import { getRemoteAccess, restore } from "./store.js";
import { attachPty } from "./terminal.js";
import { autoConnectIfConfigured, pollVpn } from "./vpn/manager.js";

restore({
  rulePacks: defaultRulePacks(RULE_COUNT, MITRE_TECHNIQUE_COUNT),
  playbooks: structuredClone(DEFAULT_PLAYBOOKS),
});
installNotificationDelivery();
seedAssets();
seedLists();
resumeIncidents();

/**
 * One route surface, two listeners. `remote: false` is the operator's own
 * console on loopback (CORS-allowlisted, actor is the local analyst). `remote:
 * true` is reachable only over the tailnet through tailscale serve, where the
 * trust boundary refuses anything without an allowlisted tailnet identity.
 */
async function buildApp(remote: boolean): Promise<FastifyInstance> {
  const app = Fastify({
    logger: false,
    bodyLimit: 64 * 1024,
    // requestTimeout limits how long a client may take to send its request,
    // not how long a route handler may work. Keep that slow-client guard short.
    // Model calls have their own configured AbortSignal timeout; disabling the
    // socket inactivity timeout prevents a legitimate 20–60s local inference
    // from being severed before the handler can reply.
    requestTimeout: 15_000,
    connectionTimeout: 0,
  });
  await app.register(websocket);
  installTrustBoundary(app, {
    remote,
    allowedHosts: remote ? remoteHosts : localHosts,
  });
  app.get("/api/session", async (request, reply) => issueSession(request, reply, remote));
  app.options("/*", async (_request, reply) => reply.code(204).send());

  app.get("/ws", { websocket: true }, (socket, request) => {
    // Remote: the onRequest hook already required a served tailnet identity.
    // Loopback: any web page could otherwise open this socket, so gate on origin.
    if (remote) {
      if (!remoteIdentity(request)) {
        socket.close(1008, "tailnet identity required");
        return;
      }
    } else if (!originAllowed(request.headers.origin)) {
      socket.close(1008, "origin not allowed");
      return;
    }
    socket.send(JSON.stringify(snapshot(!remote)));
    const unsubscribe = subscribe((message: ServerMessage) => {
      if (
        remote &&
        (message.type === "network-flow" ||
          message.type === "compass" ||
          message.type === "compass-review")
      ) {
        return;
      }
      // The review's and the chat's prompts carry the site list, so their LLM
      // records are as sensitive as the ledger they summarise.
      if (
        remote &&
        message.type === "llm" &&
        (message.call.stage === "compass_review" || message.call.stage === "compass_chat")
      ) {
        return;
      }
      if (remote && message.type === "audit" && message.entry.action.startsWith("compass.")) {
        return;
      }
      const outbound =
        remote && message.type === "settings"
          ? {
              ...message,
              settings: {
                ...message.settings,
                networkCompass: {
                  ...message.settings.networkCompass,
                  excludedDomains: [],
                  beaconSuppressions: [],
                },
              },
            }
          : message;
      if (socket.readyState === socket.OPEN) socket.send(JSON.stringify(outbound));
    });
    socket.on("close", unsubscribe);
  });

  app.get("/ws/terminal", { websocket: true }, (socket, request) => {
    if (remote) {
      if (!remoteIdentity(request)) {
        socket.close(1008, "tailnet identity required");
        return;
      }
    } else if (!originAllowed(request.headers.origin)) {
      socket.close(1008, "origin not allowed");
      return;
    }
    attachPty(socket);
  });

  app.get<{ Querystring: { runId?: string } }>(
    "/ws/pentest",
    { websocket: true },
    (socket, request) => {
      if (remote) {
        if (!remoteIdentity(request)) {
          socket.close(1008, "tailnet identity required");
          return;
        }
      } else if (!originAllowed(request.headers.origin)) {
        socket.close(1008, "origin not allowed");
        return;
      }
      const runId = request.query.runId;
      if (!runId) {
        socket.close(1008, "runId required");
        return;
      }
      attachPentestSocket(socket, runId);
    },
  );

  registerApi(app, remote);
  registerBuiltUi(app);
  return app;
}

function localHosts(): ReadonlySet<string> {
  return new Set([`127.0.0.1:${PORT}`, `localhost:${PORT}`]);
}

function remoteHosts(): ReadonlySet<string> {
  const configured = (process.env.AISOC_REMOTE_HOSTS ?? "")
    .split(",")
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean);
  const dnsName = getRemoteAccess().dnsName.replace(/\.$/, "").toLowerCase();
  if (dnsName) configured.push(`${dnsName}:${process.env.AISOC_SERVE_PORT ?? "8443"}`);
  return new Set(configured);
}

/**
 * Route registration, grouped by feature. The entrypoint composes the two
 * listeners and their trust boundaries; what each surface exposes lives beside
 * the feature it belongs to.
 */
function registerApi(app: FastifyInstance, remote: boolean): void {
  registerCoreRoutes(app, remote);
  registerCompassRoutes(app, remote);
  registerAssistantRoutes(app, remote);
  registerPentestRoutes(app, remote);
  registerAlertRoutes(app);
  registerResponseRoutes(app);
  registerIncidentRoutes(app);
  registerAssetRoutes(app);
  registerReportRoutes(app);
  registerCatalogRoutes(app);
  registerVpnRoutes(app);
  registerRemoteAccessRoutes(app);
  registerControlRoutes(app);
}

// --- Runtime -----------------------------------------------------------------

refreshLocalNetworkAddresses();
syncSource();
syncClusterSource();
pollSensors();
setInterval(pollSensors, 15_000);
setInterval(syncSource, 1_000);
setInterval(syncClusterSource, 1_000);
setInterval(() => broadcast({ type: "stats", stats: computeStats() }), 1_000);
setInterval(() => {
  decayAllAssets();
  refreshAlertCounts();
}, 60_000);
setInterval(() => void pollVpn(), 5_000);
setInterval(() => void refreshRemoteAccess(), 5_000);
setInterval(refreshLocalNetworkAddresses, 60_000);
autoConnectIfConfigured();
void configureRemoteAccess(REMOTE_PORT);

const app = await buildApp(false);
const remote = await buildApp(true);

await startConsoleControlServer();
await app.listen({ port: PORT, host: "127.0.0.1" });
await remote.listen({ port: REMOTE_PORT, host: "127.0.0.1" });
console.log(
  `aisoc console on http://127.0.0.1:${PORT} (local) and http://127.0.0.1:${REMOTE_PORT} (tailnet)`,
);
