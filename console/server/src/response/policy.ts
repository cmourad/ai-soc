import type { Alert } from "@aisoc/shared";

export function automaticResponseOriginHold(alert: Pick<Alert, "origin"> | null): string | null {
  return alert?.origin === "compass_beacon"
    ? "Compass-derived alerts require explicit human confirmation"
    : null;
}
