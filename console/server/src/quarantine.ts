import { randomUUID } from "node:crypto";
import type { QuarantineItem, QuarantineKind } from "@aisoc/shared";
import {
  addAudit,
  addNotification,
  getQuarantine,
  listQuarantine,
  upsertQuarantine,
} from "./store.js";

/**
 * The vault is the record of everything response has taken out of circulation.
 * Items are held, never destroyed on the way in — a false positive that cannot
 * be undone is worse than the malware it was aimed at.
 */

export function quarantineItem(input: {
  kind: QuarantineKind;
  value: string;
  sha256?: string | null;
  assetId?: string | null;
  alertId?: string | null;
  actionId?: string | null;
  reason: string;
  sizeBytes?: number | null;
}): QuarantineItem {
  const existing = listQuarantine().find(
    (item) => item.value === input.value && item.kind === input.kind && item.status === "held",
  );
  if (existing) return existing;

  const item: QuarantineItem = {
    id: randomUUID(),
    kind: input.kind,
    value: input.value,
    sha256: input.sha256 ?? null,
    assetId: input.assetId ?? null,
    alertId: input.alertId ?? null,
    actionId: input.actionId ?? null,
    reason: input.reason,
    status: "held",
    sizeBytes: input.sizeBytes ?? null,
    quarantinedAt: new Date().toISOString(),
    releasedAt: null,
    releasedBy: null,
  };
  upsertQuarantine(item);
  return item;
}

export function restoreItem(id: string, by: string): QuarantineItem | null {
  const item = getQuarantine(id);
  if (item?.status !== "held") return null;
  item.status = "restored";
  item.releasedAt = new Date().toISOString();
  item.releasedBy = by;
  upsertQuarantine(item);
  addAudit(by, "quarantine.restore", item.value, `Released from the vault: ${item.reason}`);
  addNotification({
    kind: "response",
    level: "info",
    title: "Item restored from quarantine",
    body: `${by} released ${item.value}.`,
    linkView: "quarantine",
    linkId: item.id,
  });
  return item;
}

export function deleteItem(id: string, by: string): QuarantineItem | null {
  const item = getQuarantine(id);
  if (item?.status !== "held") return null;
  item.status = "deleted";
  item.releasedAt = new Date().toISOString();
  item.releasedBy = by;
  upsertQuarantine(item);
  addAudit(by, "quarantine.delete", item.value, "Permanently removed from the vault.");
  return item;
}
