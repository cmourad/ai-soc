import nodemailer from "nodemailer";
import { getSecret } from "../crypto.js";
import { getSettings } from "../settings.js";
import type { SendResult } from "./telegram.js";

export async function sendEmail(to: string, subject: string, text: string): Promise<SendResult> {
  const { smtp } = getSettings();
  if (!smtp.host) return { ok: false, error: "no SMTP host configured" };
  if (!to) return { ok: false, error: "no recipient address" };

  const password = getSecret(smtp.passwordSecret);
  try {
    const transport = nodemailer.createTransport({
      host: smtp.host,
      port: smtp.port,
      secure: smtp.secure,
      auth: smtp.user ? { user: smtp.user, pass: password ?? "" } : undefined,
      connectionTimeout: 15_000,
      greetingTimeout: 15_000,
    });
    await transport.sendMail({ from: smtp.from || smtp.user, to, subject, text });
    return { ok: true };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}
