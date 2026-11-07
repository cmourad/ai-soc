import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { REPO_ROOT } from "./paths.js";

// Serves the built UI from the API process, so the packaged desktop app loads
// same-origin on :4319 and never needs CORS. The dist tree is small and hashed
// at build time, so it is cached in memory once at startup — no filesystem
// access at request time, which also removes any path-traversal surface.

const DIST = resolve(REPO_ROOT, "console", "ui", "dist");

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

const files = new Map<string, { body: Buffer; type: string }>();

function collect(dir: string, prefix: string): void {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const rel = prefix ? `${prefix}/${entry}` : entry;
    if (statSync(full).isDirectory()) {
      collect(full, rel);
    } else {
      const type = MIME[extname(entry).toLowerCase()] ?? "application/octet-stream";
      files.set(`/${rel}`, { body: readFileSync(full), type });
    }
  }
}

const distReady = existsSync(DIST);
if (distReady) collect(DIST, "");

/** Serves the built app; anything outside /api and /ws that isn't a dist file 404s. */
export async function serveBuiltUi(request: FastifyRequest, reply: FastifyReply): Promise<unknown> {
  const url = request.url.split("?")[0] ?? "/";
  if (url.startsWith("/api/") || url.startsWith("/ws")) {
    return reply.code(404).send({ error: "not found" });
  }
  const file = files.get(url) ?? (url === "/" ? files.get("/index.html") : undefined);
  if (!file) return reply.code(404).send({ error: "not found" });
  reply.header(
    "cache-control",
    url.startsWith("/assets/") ? "public, max-age=31536000, immutable" : "no-cache",
  );
  return reply.type(file.type).send(file.body);
}

export function registerBuiltUi(app: FastifyInstance): void {
  if (!distReady) return;
  app.get("/", serveBuiltUi);
  app.get("/*", serveBuiltUi);
}
