import { statSync } from "node:fs";
import { basename, delimiter, resolve } from "node:path";
import type { WebSocket } from "@fastify/websocket";
import * as pty from "node-pty";

const DEFAULT_COLS = 80;
const DEFAULT_ROWS = 24;
const MAX_COLS = 1_000;
const MAX_ROWS = 500;

type TerminalFrame =
  | { type: "input"; data: string }
  | { type: "resize"; cols: number; rows: number };

function toText(data: string | Buffer | ArrayBuffer | Buffer[]): string {
  if (typeof data === "string") return data;
  const buffer = Array.isArray(data)
    ? Buffer.concat(data.map((part) => Buffer.from(part)))
    : Buffer.from(data as ArrayBuffer);
  return buffer.toString();
}

export function parseTerminalFrame(data: string): TerminalFrame | null {
  try {
    const frame = JSON.parse(data) as Record<string, unknown>;
    if (frame.type === "input" && typeof frame.data === "string") {
      return { type: "input", data: frame.data };
    }
    if (
      frame.type === "resize" &&
      Number.isInteger(frame.cols) &&
      Number.isInteger(frame.rows) &&
      (frame.cols as number) >= 2 &&
      (frame.cols as number) <= MAX_COLS &&
      (frame.rows as number) >= 2 &&
      (frame.rows as number) <= MAX_ROWS
    ) {
      return { type: "resize", cols: frame.cols as number, rows: frame.rows as number };
    }
  } catch {
    // Invalid frames are ignored rather than becoming shell input.
  }
  return null;
}

function terminalCwd(): string {
  const configured = process.env.AISOC_TERMINAL_CWD;
  const candidate = resolve(configured || process.cwd());
  try {
    if (statSync(candidate).isDirectory()) return candidate;
  } catch {
    // Fall back to the service working directory when configuration is stale.
  }
  return process.cwd();
}

export function attachPty(socket: WebSocket) {
  const shell = process.env.SHELL ?? (process.platform === "win32" ? "cmd.exe" : "/bin/bash");
  const shellArgs = basename(shell) === "bash" ? ["--noprofile", "--norc"] : [];
  const cliDir = resolve(process.env.AISOC_CLI_DIR ?? "console/bin");
  const ptyProcess = pty.spawn(shell, shellArgs, {
    name: "xterm-256color",
    cols: DEFAULT_COLS,
    rows: DEFAULT_ROWS,
    cwd: terminalCwd(),
    env: {
      ...process.env,
      HISTFILE: "/dev/null",
      PATH: `${cliDir}${delimiter}${process.env.PATH ?? "/usr/bin:/bin"}`,
      TERM: "xterm-256color",
      AISOC_CONSOLE_CONTROL_SOCKET:
        process.env.AISOC_CONSOLE_CONTROL_SOCKET ?? "/run/aisoc-console/control.sock",
    },
  });

  socket.send(
    "\x1b[36mAI SOC terminal\x1b[0m — run \x1b[1maisocctl help\x1b[0m for audited sensor, resolver, and incident operations.\r\n",
  );

  socket.on("message", (data) => {
    const decoded = toText(data as string | Buffer | ArrayBuffer | Buffer[]);
    const frame = parseTerminalFrame(decoded);
    if (frame?.type === "input") ptyProcess.write(frame.data);
    if (frame?.type === "resize") ptyProcess.resize(frame.cols, frame.rows);
  });

  let exited = false;
  const killPty = () => {
    if (exited) return;
    exited = true;
    ptyProcess.kill();
  };

  socket.on("error", killPty);
  socket.on("close", killPty);

  ptyProcess.onData((data) => {
    if (socket.readyState === socket.OPEN) {
      socket.send(data);
    }
  });

  ptyProcess.onExit(() => {
    exited = true;
    if (socket.readyState === socket.OPEN) {
      socket.close();
    }
  });
}
