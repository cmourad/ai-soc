import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { Terminal as XTerm } from "@xterm/xterm";
import { ChevronDown, Copy, RotateCcw, Terminal } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import "@xterm/xterm/css/xterm.css";

const WS_BASE =
  import.meta.env.VITE_AISOC_API ??
  (typeof window !== "undefined" && window.location.origin.startsWith("http")
    ? window.location.origin
    : "http://127.0.0.1:4319");

function wsUrl(): string {
  const url = new URL("/ws/terminal", WS_BASE);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
}

function sendResize(ws: WebSocket, term: XTerm): void {
  if (ws.readyState !== ws.OPEN) return;
  ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
}

type TerminalConnection = {
  socket: WebSocket;
  dispose: () => void;
};

function connectSocket(
  term: XTerm,
  setConnected: (connected: boolean) => void,
): TerminalConnection {
  const ws = new WebSocket(wsUrl());
  ws.binaryType = "arraybuffer";
  let disposed = false;

  ws.onopen = () => {
    setConnected(true);
    sendResize(ws, term);
  };

  ws.onmessage = (event) => {
    const data = typeof event.data === "string" ? event.data : new TextDecoder().decode(event.data);
    term.write(data);
  };

  ws.onclose = () => {
    if (disposed) return;
    setConnected(false);
    term.write("\r\n\x1b[31m[ disconnected ]\x1b[0m\r\n");
  };

  ws.onerror = () => ws.close();

  const inputSubscription = term.onData((data) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify({ type: "input", data }));
  });

  const resizeSubscription = term.onResize(({ cols, rows }) => {
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify({ type: "resize", cols, rows }));
    }
  });

  return {
    socket: ws,
    dispose: () => {
      if (disposed) return;
      disposed = true;
      inputSubscription.dispose();
      resizeSubscription.dispose();
      ws.onopen = null;
      ws.onmessage = null;
      ws.onclose = null;
      ws.onerror = null;
      ws.close();
    },
  };
}

export function ServiceTerminal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const connectionRef = useRef<TerminalConnection | null>(null);
  const restartTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [connected, setConnected] = useState(false);
  const _resizeDir = useRef<"up" | "down" | null>(null);
  const [height, setHeight] = useState(300);
  const isResizing = useRef(false);

  useEffect(() => {
    if (!open || !containerRef.current) return;

    const term = new XTerm({
      cursorBlink: true,
      fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      fontSize: 12,
      scrollback: 10000,
      allowProposedApi: true,
      theme: {
        background: "#1e1e1e",
        foreground: "#cccccc",
        cursor: "#007acc",
        selectionBackground: "#264f78",
        black: "#000000",
        red: "#c50f1f",
        green: "#13a10e",
        yellow: "#c19c00",
        blue: "#0037da",
        magenta: "#881798",
        cyan: "#3a96dd",
        white: "#cccccc",
        brightBlack: "#666666",
        brightRed: "#e35555",
        brightGreen: "#16c60c",
        brightYellow: "#f9f1a5",
        brightBlue: "#3b78ff",
        brightMagenta: "#b83bb9",
        brightCyan: "#61d6d6",
        brightWhite: "#f2f2f2",
      },
    });

    const fit = new FitAddon();
    const webLinks = new WebLinksAddon();
    term.loadAddon(fit);
    term.loadAddon(webLinks);
    term.open(containerRef.current);
    fit.fit();
    term.focus();

    termRef.current = term;
    fitRef.current = fit;

    connectionRef.current = connectSocket(term, setConnected);

    const onResize = () => {
      requestAnimationFrame(() => fit.fit());
    };
    window.addEventListener("resize", onResize);

    return () => {
      window.removeEventListener("resize", onResize);
      if (restartTimerRef.current) clearTimeout(restartTimerRef.current);
      restartTimerRef.current = null;
      connectionRef.current?.dispose();
      connectionRef.current = null;
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, [open]);

  useEffect(() => {
    if (open) {
      requestAnimationFrame(() => fitRef.current?.fit());
    }
  }, [open]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: height is the trigger for re-fitting xterm, not a read value
  useEffect(() => {
    requestAnimationFrame(() => fitRef.current?.fit());
  }, [height]);

  const restart = () => {
    if (restartTimerRef.current) clearTimeout(restartTimerRef.current);
    connectionRef.current?.dispose();
    connectionRef.current = null;
    setConnected(false);
    termRef.current?.clear();
    restartTimerRef.current = setTimeout(() => {
      restartTimerRef.current = null;
      const term = termRef.current;
      if (!term) return;
      connectionRef.current = connectSocket(term, setConnected);
    }, 100);
  };

  const handleMouseDown = (e: React.MouseEvent, dir: "up" | "down") => {
    e.preventDefault();
    isResizing.current = true;
    _resizeDir.current = dir;
    const startY = e.clientY;
    const startHeight = height;

    const onMouseMove = (me: MouseEvent) => {
      if (!isResizing.current) return;
      const currentDir = _resizeDir.current;
      const delta = currentDir === "up" ? startY - me.clientY : me.clientY - startY;
      const newHeight = Math.max(150, Math.min(600, startHeight + delta));
      setHeight(newHeight);
    };

    const onMouseUp = () => {
      isResizing.current = false;
      _resizeDir.current = null;
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
      requestAnimationFrame(() => fitRef.current?.fit());
    };

    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
  };

  if (!open) return null;

  return (
    <div
      className={cn(
        "flex shrink-0 flex-col border-t border-edge bg-panel shadow-[0_-8px_24px_rgba(0,0,0,0.22)]",
      )}
      style={{ height }}
    >
      {/* biome-ignore lint/a11y/noStaticElementInteractions: resize handle */}
      <div
        className="h-1 cursor-row-resize shrink-0 hover:bg-status/50"
        onMouseDown={(e) => handleMouseDown(e, "up")}
      />
      <div className="flex items-center justify-between border-b border-edge px-3 py-1.5">
        <div className="flex items-center gap-2 text-xs text-ink">
          <Terminal className="h-3.5 w-3.5 text-status" />
          <span className="font-semibold">Terminal</span>
          <span className="text-ink-dim">—</span>
          <span className={cn("h-2 w-2 rounded-full", connected ? "bg-[#4ec9b0]" : "bg-[#f14c4c]")}>
            <span
              className={cn("inline-block h-full w-full rounded-full", connected ? "pulse" : "")}
            />
          </span>
          <span className="text-ink-dim">{connected ? "connected" : "connecting"}</span>
        </div>
        <div className="flex items-center gap-1">
          <Button size="sm" variant="ghost" onClick={restart} title="Restart session">
            <RotateCcw className="h-3 w-3" />
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              const term = termRef.current;
              if (!term) return;
              term.selectAll();
              const text = term.getSelection();
              term.clearSelection();
              navigator.clipboard.writeText(text);
            }}
            title="Copy terminal contents"
          >
            <Copy className="h-3 w-3" />
          </Button>
          <Button size="sm" variant="ghost" onClick={onClose} title="Close terminal">
            <ChevronDown className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
      <div ref={containerRef} className="flex-1 overflow-hidden p-1" />
    </div>
  );
}
