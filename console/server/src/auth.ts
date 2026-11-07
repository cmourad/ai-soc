import { randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { PORT } from "./config.js";
import { getSettings } from "./settings.js";

// ---------------------------------------------------------------------------
// Trust boundary
//
// Loopback and tailnet membership are transport controls, not authorization.
// The boundary therefore layers exact Host validation, application sessions,
// CSRF, origin checks, rate limits and response hardening:
//
//  1. CORS is an allowlist, not `*`. That stops a random page *reading* our
//     responses — every alert, every secret's presence.
//  2. A same-origin gate on every mutating method. CORS does NOT stop the side
//     effect: a cross-origin form POST with no custom headers is a "simple
//     request", so it is delivered and executed, and only the response is
//     withheld from the attacker. Without this gate any page the operator
//     visits can fire POST /api/actions/:id/approve, /api/control/pause or
//     /api/quarantine/:id/delete — none of which need a body.
//  3. Every API/WS caller needs a short-lived application session; mutation
//     also needs the session's independent CSRF value.
//  4. Every request gets a resolved actor (request.actor) before any handler
//     trusts a body field, so the audit trail stops being self-asserted.
//
// Remote access opens a second loopback listener that tailscale serve proxies
// into. That listener never emits CORS headers (strictly same-origin) and
// refuses every request that does not carry a served tailnet identity that is
// on the `remoteAccess.allowedLogins` allowlist. The tailnet identity is
// injected by tailscale itself after authenticating the peer. Exact Host and
// application-session checks still apply; Funnel is refused so the reachable
// surface is tailnet-only. Loopback sessions map to the local operator.
// ---------------------------------------------------------------------------

// Origins allowed to call the API cross-origin from a browser. The dev UI runs
// on :5319 and talks to :4319 directly. The packaged desktop app loads the UI
// same-origin from :4319, plus itself sends Origin on the websocket handshake.
export const ALLOWED_ORIGINS = new Set([
  "http://127.0.0.1:5319",
  "http://localhost:5319",
  "http://127.0.0.1:4319",
  "http://localhost:4319",
  `http://127.0.0.1:${PORT}`,
  `http://localhost:${PORT}`,
]);

export const LOCAL_ACTOR = "analyst";

/** A non-browser client sends no Origin; a real browser page always does, and must be one of ours. */
export function originAllowed(origin: string | undefined): boolean {
  return origin === undefined || ALLOWED_ORIGINS.has(origin);
}

/**
 * Turn a tailnet identity header into an actor, or `null` when it is missing
 * or not allowlisted. The header is injected by tailscale serve after it has
 * authenticated the peer, so its presence means the request arrived over the
 * tailnet rather than from a loose browser.
 */
export function allowTailnetIdentity(login: unknown): string | null {
  if (typeof login !== "string" || login.length === 0) return null;
  return getSettings().remoteAccess.allowedLogins.includes(login) ? login : null;
}

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const RATE_WINDOW_MS = 60_000;
const RATE_READS = 240;
const RATE_MUTATIONS = 60;
const SESSION_COOKIE = "aisoc_session";
const SESSION_IDLE_MS = 30 * 60_000;
const SESSION_MAX_MS = 8 * 60 * 60_000;
const BOOTSTRAP_FILE = process.env.AISOC_BOOTSTRAP_FILE ?? "";

type Session = { actor: string; csrf: string; created: number; seen: number; remote: boolean };
const sessions = new Map<string, Session>();

type TrustOptions = {
  remote?: boolean;
  allowedHosts?: () => ReadonlySet<string>;
};

export function hostAllowed(host: unknown, allowed: ReadonlySet<string>): boolean {
  if (typeof host !== "string" || host.length === 0 || host.length > 255) return false;
  // Host is compared byte-for-byte after ASCII case folding. Whitespace,
  // comma-joined proxy values, userinfo and path syntax are never meaningful.
  if (/\s|,|@|\//.test(host)) return false;
  return allowed.has(host.toLowerCase());
}

/**
 * Is this a state-changing request driven by a page we did not serve?
 *
 * Fetch Metadata is the reliable signal — the browser sets `sec-fetch-site`
 * and script cannot forge it. `same-origin` and `none` (typed URL, non-browser
 * client) are ours; `cross-site` and `same-site` are not. Clients too old to
 * send it fall back to the Origin allowlist, and a request with no Origin at
 * all is a non-browser caller on loopback, which is the operator.
 */
export function isForgeableCrossOrigin(
  headers: Record<string, unknown>,
  { remote }: { remote: boolean },
): boolean {
  const site = headers["sec-fetch-site"];
  if (typeof site === "string") return site === "cross-site" || site === "same-site";

  const origin = headers.origin;
  if (typeof origin !== "string" || origin.length === 0) return false;
  if (!remote) return !ALLOWED_ORIGINS.has(origin);

  // Behind tailscale serve the public origin is not known at build time, so
  // require that the page's origin is the host it is talking to.
  const host = headers.host;
  return typeof host !== "string" || new URL(origin).host !== host;
}

declare module "fastify" {
  interface FastifyRequest {
    actor: string;
  }
}

export function resolveActor(_request: FastifyRequest): string {
  // Loopback is the operator at the console. The remote listener asserts its
  // own actor from the tailnet identity before this hook runs.
  return LOCAL_ACTOR;
}

export function installTrustBoundary(
  app: FastifyInstance,
  { remote = false, allowedHosts = () => ALLOWED_HOSTS }: TrustOptions = {},
): void {
  app.decorateRequest("actor", LOCAL_ACTOR);

  app.addHook("onRequest", async (request, reply) => {
    if (!hostAllowed(request.headers.host, allowedHosts())) {
      return reply.code(421).send({ ok: false, error: "unrecognized Host" });
    }
    return undefined;
  });

  // Runs before the remote identity check: a tailnet-authenticated browser is
  // exactly the browser a cross-site POST would ride on, and tailscale injects
  // the identity header regardless of which page issued the request.
  app.addHook("onRequest", async (request, reply) => {
    if (!MUTATING_METHODS.has(request.method)) return undefined;
    if (!isForgeableCrossOrigin(request.headers as Record<string, unknown>, { remote })) {
      return undefined;
    }
    return reply.code(403).send({ ok: false, error: "cross-origin request refused" });
  });

  if (remote) {
    // The remote boundary is fail-closed: no tailnet identity, no access.
    app.addHook("onRequest", async (request, reply) => {
      const actor = resolveRemoteActor(request);
      if (actor === null) {
        return reply.code(403).send({ ok: false, error: "tailnet identity not allowlisted" });
      }
      request.actor = actor;
      return undefined;
    });
  } else {
    app.addHook("onRequest", async (request) => {
      request.actor = resolveActor(request);
    });
  }

  installSessionBoundary(app, remote);

  installRateLimit(app);

  // Echo the origin only for our own surfaces, so a random page cannot read
  // responses or pass preflight. Same-origin callers need no CORS headers.
  app.addHook("onSend", async (request, reply) => {
    const origin = request.headers.origin;
    if (!remote && origin && ALLOWED_ORIGINS.has(origin)) {
      reply.header("access-control-allow-origin", origin);
      reply.header("vary", "origin");
      reply.header("access-control-allow-credentials", "true");
    }
    reply.header("access-control-allow-headers", "content-type,x-csrf-token,x-aisoc-bootstrap");
    reply.header("access-control-allow-methods", "GET,POST,OPTIONS");
    reply.header(
      "content-security-policy",
      `default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' http://127.0.0.1:4319 ws://127.0.0.1:4319 http://127.0.0.1:${PORT} ws://127.0.0.1:${PORT} wss:; form-action 'self'`,
    );
    reply.header("x-content-type-options", "nosniff");
    reply.header("referrer-policy", "no-referrer");
    reply.header("x-frame-options", "DENY");
    reply.header("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=()");
    if (request.url.startsWith("/api/")) reply.header("cache-control", "no-store");
    if (remote) reply.header("strict-transport-security", "max-age=31536000");
  });
}

function cookieValue(header: string | undefined, name: string): string | null {
  for (const part of (header ?? "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return null;
}

function sameSecret(left: string, right: unknown): boolean {
  if (typeof right !== "string") return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function localBootstrapAllowed(value: unknown): boolean {
  // Development stays usable without provisioning host state. Production is
  // fail-closed when the service credential is absent or unreadable.
  if (!BOOTSTRAP_FILE && process.env.NODE_ENV !== "production") return true;
  try {
    return sameSecret(readFileSync(BOOTSTRAP_FILE, "utf8").trim(), value);
  } catch {
    return false;
  }
}

function liveSession(request: FastifyRequest, remote: boolean): Session | null {
  const token = cookieValue(request.headers.cookie, SESSION_COOKIE);
  if (!token) return null;
  const session = sessions.get(token);
  const now = Date.now();
  if (
    !session ||
    session.remote !== remote ||
    session.actor !== request.actor ||
    now - session.seen > SESSION_IDLE_MS ||
    now - session.created > SESSION_MAX_MS
  ) {
    sessions.delete(token);
    return null;
  }
  session.seen = now;
  return session;
}

function installSessionBoundary(app: FastifyInstance, remote: boolean): void {
  app.addHook("onRequest", async (request, reply) => {
    if (
      request.method === "OPTIONS" ||
      request.url === "/api/health" ||
      request.url === "/api/session"
    ) {
      return undefined;
    }
    if (!request.url.startsWith("/api/") && !request.url.startsWith("/ws")) return undefined;
    const session = liveSession(request, remote);
    if (!session)
      return reply.code(401).send({ ok: false, error: "authenticated session required" });
    if (
      MUTATING_METHODS.has(request.method) &&
      !sameSecret(session.csrf, request.headers["x-csrf-token"])
    ) {
      return reply.code(403).send({ ok: false, error: "valid CSRF token required" });
    }
    return undefined;
  });
}

export function issueSession(
  request: FastifyRequest,
  reply: FastifyReply,
  remote: boolean,
): { ok: true; actor: string; csrf: string; expiresIn: number } | { ok: false; error: string } {
  if (!remote && !localBootstrapAllowed(request.headers["x-aisoc-bootstrap"])) {
    reply.code(403);
    return { ok: false, error: "valid local bootstrap credential required" };
  }
  const now = Date.now();
  const token = randomBytes(32).toString("base64url");
  const csrf = randomBytes(32).toString("base64url");
  sessions.set(token, { actor: request.actor, csrf, created: now, seen: now, remote });
  for (const [candidate, session] of sessions) {
    if (now - session.seen > SESSION_IDLE_MS || now - session.created > SESSION_MAX_MS) {
      sessions.delete(candidate);
    }
  }
  const secure = remote ? "; Secure" : "";
  reply.header(
    "set-cookie",
    `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_MAX_MS / 1_000}${secure}`,
  );
  return { ok: true, actor: request.actor, csrf, expiresIn: SESSION_MAX_MS / 1_000 };
}

const ALLOWED_HOSTS = new Set([
  "127.0.0.1:4319",
  "localhost:4319",
  "127.0.0.1:5319",
  "localhost:5319",
  `127.0.0.1:${PORT}`,
  `localhost:${PORT}`,
]);

type Bucket = { started: number; reads: number; mutations: number };
const buckets = new Map<string, Bucket>();

function installRateLimit(app: FastifyInstance): void {
  app.addHook("preHandler", async (request, reply) => {
    const now = Date.now();
    const key = `${request.actor}:${request.ip}`;
    let bucket = buckets.get(key);
    if (!bucket || now - bucket.started >= RATE_WINDOW_MS) {
      bucket = { started: now, reads: 0, mutations: 0 };
      buckets.set(key, bucket);
    }
    const mutation = MUTATING_METHODS.has(request.method);
    const count = mutation ? ++bucket.mutations : ++bucket.reads;
    const limit = mutation ? RATE_MUTATIONS : RATE_READS;
    if (count > limit) {
      reply.header(
        "retry-after",
        String(Math.max(1, Math.ceil((RATE_WINDOW_MS - (now - bucket.started)) / 1_000))),
      );
      return reply.code(429).send({ ok: false, error: "request rate limit exceeded" });
    }
    if (buckets.size > 1_000) {
      for (const [candidate, value] of buckets) {
        if (now - value.started >= RATE_WINDOW_MS) buckets.delete(candidate);
      }
    }
    return undefined;
  });
}

function resolveRemoteActor(request: FastifyRequest): string | null {
  const login = request.headers["tailscale-user-login"];
  return allowTailnetIdentity(login);
}

/** Does this websocket handshake carry a trusted tailnet identity? */
export function remoteIdentity(request: FastifyRequest): boolean {
  return allowTailnetIdentity(request.headers["tailscale-user-login"]) !== null;
}
