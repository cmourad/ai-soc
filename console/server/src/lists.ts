import { randomUUID } from "node:crypto";
import type { IocType, ListEntry, ListName } from "@aisoc/shared";
import { addAudit, listListEntries, setListEntries } from "./store.js";

/**
 * The allow/blocklist is the operator's override of both the detection engine
 * and the model. Allowlisting suppresses scoring and hard-blocks every response
 * action against an indicator; blocklisting short-circuits triage entirely.
 * Both are checked deterministically, so neither can be argued out of by
 * anything an attacker writes into a hostname or user agent.
 */

const SEED: Omit<ListEntry, "id" | "addedAt">[] = [
  {
    list: "allow",
    kind: "domain",
    value: "api.telegram.org",
    note: "This console's own alerting path — blocking it would silence the alerts.",
    addedBy: "bootstrap",
    expiresAt: null,
  },
  {
    list: "allow",
    kind: "ip",
    value: "149.154.166.110",
    note: "Telegram API frontend.",
    addedBy: "bootstrap",
    expiresAt: null,
  },
  {
    list: "allow",
    kind: "domain",
    value: "cdn.jsdelivr.net",
    note: "Package CDN used by the console's own build.",
    addedBy: "bootstrap",
    expiresAt: null,
  },
  {
    list: "block",
    kind: "ip",
    value: "45.155.205.233",
    note: "Confirmed Cobalt Strike team server — blocked after INC review.",
    addedBy: "bootstrap",
    expiresAt: null,
  },
  {
    list: "block",
    kind: "domain",
    value: "cdn-telemetry-sync.net",
    note: "C2 domain, sinkholed at the resolver.",
    addedBy: "bootstrap",
    expiresAt: null,
  },
];

export function seedLists(): void {
  if (listListEntries().length > 0) return;
  setListEntries(
    SEED.map((entry) => ({ ...entry, id: randomUUID(), addedAt: new Date().toISOString() })),
  );
}

function active(): ListEntry[] {
  const now = Date.now();
  return listListEntries().filter((entry) => !entry.expiresAt || Date.parse(entry.expiresAt) > now);
}

function matches(entry: ListEntry, value: string): boolean {
  const needle = value.toLowerCase().replace(/\.$/, "");
  const target = entry.value.toLowerCase();
  if (needle === target) return true;
  // Domain entries cover their subdomains; nothing else does suffix matching.
  return entry.kind === "domain" && needle.endsWith(`.${target}`);
}

function on(list: ListName, value: string): ListEntry | undefined {
  return active().find((entry) => entry.list === list && matches(entry, value));
}

export function isAllowlisted(value: string): boolean {
  return Boolean(on("allow", value));
}

export function allowlistEntry(value: string): ListEntry | undefined {
  return on("allow", value);
}

export function blocklistEntry(value: string): ListEntry | undefined {
  return on("block", value);
}

export function addListEntry(input: {
  list: ListName;
  kind: IocType | "signature";
  value: string;
  note: string;
  addedBy: string;
  expiresAt: string | null;
}): ListEntry {
  const entry: ListEntry = { ...input, id: randomUUID(), addedAt: new Date().toISOString() };
  // The same indicator cannot be on both lists; the newer intent wins.
  const kept = listListEntries().filter(
    (existing) => existing.value.toLowerCase() !== entry.value.toLowerCase(),
  );
  setListEntries([...kept, entry]);
  addAudit(
    input.addedBy,
    `${input.list}list.add`,
    entry.value,
    `${entry.kind} added to the ${entry.list}list: ${entry.note || "no note"}`,
  );
  return entry;
}

export function removeListEntry(id: string, by: string): boolean {
  const entry = listListEntries().find((item) => item.id === id);
  if (!entry) return false;
  setListEntries(listListEntries().filter((item) => item.id !== id));
  addAudit(by, `${entry.list}list.remove`, entry.value, `Removed from the ${entry.list}list.`);
  return true;
}
