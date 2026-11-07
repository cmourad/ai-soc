import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import type { SecretPresence } from "@aisoc/shared";
import { writePrivateAtomic } from "./atomic.js";
import { KEY_FILE, SECRETS_FILE } from "./paths.js";

type Envelope = { iv: string; tag: string; data: string };

function loadKey(): Buffer {
  if (!existsSync(KEY_FILE)) {
    const key = randomBytes(32);
    writePrivateAtomic(KEY_FILE, key);
    return key;
  }
  const key = readFileSync(KEY_FILE);
  if (key.length !== 32) throw new Error(`secret key must be exactly 32 bytes, got ${key.length}`);
  return key;
}

const key = loadKey();

function seal(plaintext: string): Envelope {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: data.toString("base64"),
  };
}

function open(envelope: Envelope): string {
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64"));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(envelope.data, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

function readAll(): Record<string, Envelope> {
  if (!existsSync(SECRETS_FILE)) return {};
  const parsed: unknown = JSON.parse(readFileSync(SECRETS_FILE, "utf8"));
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("encrypted secret store must be a JSON object");
  }
  return parsed as Record<string, Envelope>;
}

function writeAll(all: Record<string, Envelope>): void {
  writePrivateAtomic(SECRETS_FILE, JSON.stringify(all, null, 2));
}

export function setSecret(name: string, value: string): void {
  const all = readAll();
  if (value === "") delete all[name];
  else all[name] = seal(value);
  writeAll(all);
}

export function getSecret(name: string): string | null {
  if (!name) return null;
  const envelope = readAll()[name];
  if (!envelope) return null;
  try {
    return open(envelope);
  } catch {
    return null;
  }
}

/** Which secrets hold a value — the only secret info that ever reaches the UI. */
export function secretPresence(): SecretPresence {
  return Object.fromEntries(Object.keys(readAll()).map((name) => [name, true]));
}
