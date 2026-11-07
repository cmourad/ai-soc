import { getSettings } from "../settings.js";
import { registerNotificationSink } from "../store.js";
import { escapeHtml, inQuietHours, sendTelegram } from "./telegram.js";

/**
 * Out-of-band push for the kinds the operator chose. Fire-and-forget: a
 * Telegram outage must never stall the pipeline that produced the event.
 */
export function installNotificationDelivery(): void {
  registerNotificationSink((notification) => {
    const { telegram, notifications } = getSettings();
    if (!telegram.enabled) return;
    if (!notifications.telegramKinds.includes(notification.kind)) return;
    if (inQuietHours(notification.level === "critical" ? 1 : 2)) return;
    void sendTelegram(
      telegram.chatId,
      `<b>${escapeHtml(notification.title)}</b>\n${escapeHtml(notification.body)}`,
    );
  });
}
