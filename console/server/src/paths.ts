import { chmodSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export const REPO_ROOT = resolve(here, "../../..");
export const DATA_DIR = process.env.AISOC_DATA_DIR ?? resolve(here, "../../data");

mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
chmodSync(DATA_DIR, 0o700);

export const SETTINGS_FILE = join(DATA_DIR, "settings.json");
export const SECRETS_FILE = join(DATA_DIR, "secrets.enc.json");
export const KEY_FILE = join(DATA_DIR, "secret.key");
export const STATE_FILE = join(DATA_DIR, "state.json");
export const COMPASS_DB_FILE = join(DATA_DIR, "network-compass.db");

/**
 * The agent owns this socket; the console is a client. Deployment injects the
 * override, and the fallback has to match what the agent binds or a client
 * silently talks to nothing.
 */
export const AGENT_CONTROL_SOCKET = process.env.AISOC_CONTROL_SOCKET ?? "/run/aisoc/control.sock";
