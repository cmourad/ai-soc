import { getSecret } from "../crypto.js";
import { getSettings } from "../settings.js";

export type SendResult = { ok: true } | { ok: false; error: string };

/**
 * Telegram parses these messages as HTML, so every interpolated value — a
 * signature, a hostname, an operator's note — has to be inert first. One
 * implementation, because a correction that reached only one delivery path
 * would leave the other one accepting markup.
 */
export function escapeHtml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export async function sendTelegram(chatId: string, text: string): Promise<SendResult> {
  const { telegram } = getSettings();
  const token = getSecret(telegram.botTokenSecret);
  if (!token) return { ok: false, error: "no bot token stored" };
  if (!chatId) return { ok: false, error: "no chat id" };

  try {
    const response = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      signal: AbortSignal.timeout(10_000),
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: "HTML",
        disable_web_page_preview: true,
      }),
    });
    const body = (await response.json()) as { ok?: boolean; description?: string };
    if (!response.ok || !body.ok) {
      return { ok: false, error: body.description ?? `HTTP ${response.status}` };
    }
    return { ok: true };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

/**
 * Quiet hours mute everything except severity 1 — a critical alert at 3am is
 * exactly the one worth waking someone for.
 */
export function inQuietHours(severity: number, now = new Date()): boolean {
  const { quietHours } = getSettings().telegram;
  if (!quietHours.enabled || severity === 1) return false;
  const hour = now.getHours();
  const { startHour, endHour } = quietHours;
  return startHour <= endHour
    ? hour >= startHour && hour < endHour
    : hour >= startHour || hour < endHour;
}
