/**
 * Listener ports. Two surfaces run the same routes: the operator's own console
 * on loopback, and the one tailscale serve proxies into for the tailnet.
 */
export const PORT = Number(process.env.AISOC_PORT ?? 4319);
export const REMOTE_PORT = Number(process.env.AISOC_REMOTE_PORT ?? 4320);
