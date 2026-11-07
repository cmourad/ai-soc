import type { AnalystChatModelOption, AssistanceChat, AssistanceSubjectKind } from "@aisoc/shared";
import { History, Loader2, MessageSquare, Plus, Send, Sparkles, Trash2, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Button, Input, Select, Textarea, Tooltip } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { cn, relativeTime } from "@/lib/utils";
import { type AssistantSubject, useStore } from "@/store";

const SUBJECT_EVIDENCE: Record<AssistanceSubjectKind, string> = {
  alert: "the alert evidence",
  incident: "the incident evidence",
  dns: "the resolver snapshot",
  compass: "the traffic review",
};

const SUBJECT_GROUP: Record<AssistanceSubjectKind, string> = {
  alert: "This alert",
  incident: "This incident",
  dns: "This resolver snapshot",
  compass: "This traffic review",
};

const SINGLETON_LABEL: Partial<Record<AssistanceSubjectKind, string>> = {
  dns: "dns · resolver snapshot",
  compass: "compass · traffic review",
};

function subjectLabel(kind: AssistanceSubjectKind, id: string): string {
  return SINGLETON_LABEL[kind] ?? `${kind} · ${id.slice(0, 8)}`;
}

function chatTitle(chat: AssistanceChat): string {
  const first = chat.messages.find((message) => message.role === "user")?.text;
  if (!first) return "New conversation";
  return first.length > 46 ? `${first.slice(0, 46)}…` : first;
}

function sameSubject(chat: AssistanceChat, subject: AssistantSubject | null): boolean {
  return chat.subjectKind === subject?.kind && chat.subjectId === subject.id;
}

function ConversationRow({
  chat,
  active,
  onOpen,
  onDelete,
}: {
  chat: AssistanceChat;
  active: boolean;
  onOpen: () => void;
  onDelete: () => void;
}) {
  return (
    <div
      className={cn(
        "group flex items-start gap-1 rounded-sm border-l-2 pr-1 transition-colors",
        active ? "border-l-accent bg-active" : "border-l-transparent hover:bg-hover",
      )}
    >
      <button
        type="button"
        onClick={onOpen}
        className="min-w-0 flex-1 px-2 py-1.5 text-left"
        title={chatTitle(chat)}
      >
        <span className="block truncate text-[11px] leading-4 text-ink">{chatTitle(chat)}</span>
        <span className="mt-0.5 flex items-center gap-1.5 text-[9px] text-ink-dim">
          <span className="truncate font-mono">
            {subjectLabel(chat.subjectKind, chat.subjectId)}
          </span>
          <span className="text-edge">·</span>
          <span className="shrink-0">{relativeTime(chat.updatedAt)}</span>
        </span>
      </button>
      <Button
        size="icon"
        variant="ghost"
        aria-label="Delete this conversation"
        title="Delete this conversation"
        className="mt-1 shrink-0 text-ink-dim opacity-0 group-hover:opacity-100 focus-visible:opacity-100 hover:text-block"
        onClick={onDelete}
      >
        <Trash2 className="h-3 w-3" />
      </Button>
    </div>
  );
}

export function AssistantPanel() {
  const subject = useStore((state) => state.assistantSubject);
  const activeChatId = useStore((state) => state.assistantChatId);
  const selectChat = useStore((state) => state.selectAssistantChat);
  const closeAssistant = useStore((state) => state.closeAssistant);
  const pushToast = useStore((state) => state.pushToast);

  const [chats, setChats] = useState<AssistanceChat[]>([]);
  const [models, setModels] = useState<AnalystChatModelOption[]>([]);
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [browsing, setBrowsing] = useState(false);
  const [model, setModel] = useState("secondTriage");
  const [customModel, setCustomModel] = useState("");
  const [question, setQuestion] = useState("");
  const questionRef = useRef<HTMLTextAreaElement>(null);
  const endRef = useRef<HTMLDivElement>(null);

  const activeChat = chats.find((chat) => chat.id === activeChatId) ?? null;
  const target: AssistantSubject | null = activeChat
    ? { kind: activeChat.subjectKind, id: activeChat.subjectId }
    : subject;

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [chatList, modelList] = await Promise.all([
          api.assistanceAllChats(),
          api.assistanceModels(),
        ]);
        if (cancelled) return;
        setChats(chatList.chats);
        setModels(modelList.models);
      } catch (error) {
        if (!cancelled) pushToast("error", error instanceof Error ? error.message : String(error));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [pushToast]);

  // Arriving with a subject means "ask about this now"; arriving without one
  // means the operator came to browse what they already asked.
  useEffect(() => {
    setBrowsing(!subject);
    if (subject) requestAnimationFrame(() => questionRef.current?.focus());
  }, [subject]);

  const messageCount = activeChat?.messages.length ?? 0;
  useEffect(() => {
    if (messageCount > 0) endRef.current?.scrollIntoView({ block: "nearest" });
  }, [messageCount]);

  const openChat = (id: string) => {
    selectChat(id);
    setBrowsing(false);
    requestAnimationFrame(() => questionRef.current?.focus());
  };

  const startNew = () => {
    selectChat(null);
    setBrowsing(false);
    setQuestion("");
    requestAnimationFrame(() => questionRef.current?.focus());
  };

  const send = async () => {
    const text = question.trim();
    if (!text || sending || !target) return;
    const selectedModel = model === "custom" ? customModel.trim() : model;
    if (!selectedModel) {
      pushToast("error", "Enter a model name first.");
      return;
    }
    setSending(true);
    setQuestion("");
    try {
      const result = await api.sendAssistanceMessage(
        activeChatId,
        target.kind,
        target.id,
        text,
        selectedModel,
      );
      setChats((current) => [result.chat, ...current.filter((chat) => chat.id !== result.chat.id)]);
      selectChat(result.chat.id);
    } catch (error) {
      setQuestion(text);
      pushToast("error", error instanceof Error ? error.message : String(error));
    } finally {
      setSending(false);
    }
  };

  const remove = async (id: string) => {
    if (!window.confirm("Delete this conversation? This cannot be undone.")) return;
    try {
      await api.deleteAssistanceChat(id);
      setChats((current) => current.filter((chat) => chat.id !== id));
      if (activeChatId === id) selectChat(null);
    } catch (error) {
      pushToast("error", error instanceof Error ? error.message : String(error));
    }
  };

  const forSubject = subject ? chats.filter((chat) => sameSubject(chat, subject)) : [];
  const others = chats.filter((chat) => !sameSubject(chat, subject));

  return (
    <aside className="flex w-[400px] shrink-0 flex-col border-l border-edge bg-panel">
      <header className="flex h-8 shrink-0 items-center gap-1 border-b border-edge px-2">
        <Sparkles className="h-3.5 w-3.5 text-accent" />
        <span className="text-[11px] uppercase tracking-wide text-ink-dim">Assistant</span>
        <div className="ml-auto flex items-center gap-0.5">
          <Button
            size="sm"
            variant={browsing ? "secondary" : "ghost"}
            className="gap-1 text-[10px] text-ink-dim"
            onClick={() => setBrowsing(!browsing)}
          >
            <History className="h-3 w-3" />
            Conversations
            {chats.length > 0 ? <span className="tabular-nums">{chats.length}</span> : null}
          </Button>
          <Tooltip label="New conversation">
            <Button size="icon" variant="ghost" onClick={startNew} aria-label="New conversation">
              <Plus className="h-3.5 w-3.5" />
            </Button>
          </Tooltip>
          <Tooltip label="Close assistant">
            <Button
              size="icon"
              variant="ghost"
              onClick={closeAssistant}
              aria-label="Close assistant"
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          </Tooltip>
        </div>
      </header>

      {target ? (
        <div className="shrink-0 border-b border-edge bg-shell/60 px-3 py-2">
          <span
            className="inline-flex max-w-full items-center gap-1.5 rounded-sm border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-[10px] text-ink"
            title={SINGLETON_LABEL[target.kind] ?? target.id}
          >
            <MessageSquare className="h-3 w-3 shrink-0 text-accent" />
            <span className="truncate">{subjectLabel(target.kind, target.id)}</span>
          </span>
          <p className="mt-1 text-[10px] leading-4 text-ink-dim">
            {activeChat
              ? "Continues an earlier conversation on the evidence it started from."
              : `Answers from ${SUBJECT_EVIDENCE[target.kind]}, frozen when the conversation starts. It cannot take action.`}
          </p>
        </div>
      ) : null}

      {loading ? (
        <p className="flex flex-1 items-center justify-center gap-2 text-[10px] text-ink-dim">
          <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading conversations…
        </p>
      ) : browsing ? (
        <div className="min-h-0 flex-1 overflow-y-auto p-2">
          {chats.length === 0 ? (
            <p className="px-1 py-3 text-[10px] leading-4 text-ink-dim">
              No saved conversations yet. Use “Ask assistant” on an alert, an incident narrative, a
              traffic review, or the DNS page to start one.
            </p>
          ) : null}
          {forSubject.length > 0 ? (
            <>
              <div className="px-2 pb-1 text-[9px] uppercase tracking-wide text-ink-dim">
                {SUBJECT_GROUP[subject?.kind ?? "alert"]}
              </div>
              {forSubject.map((chat) => (
                <ConversationRow
                  key={chat.id}
                  chat={chat}
                  active={chat.id === activeChatId}
                  onOpen={() => openChat(chat.id)}
                  onDelete={() => void remove(chat.id)}
                />
              ))}
            </>
          ) : null}
          {others.length > 0 ? (
            <>
              <div
                className={cn(
                  "px-2 pb-1 text-[9px] uppercase tracking-wide text-ink-dim",
                  forSubject.length > 0 && "mt-3 border-t border-edge/60 pt-2",
                )}
              >
                {forSubject.length > 0 ? "Everything else" : "All conversations"}
              </div>
              {others.map((chat) => (
                <ConversationRow
                  key={chat.id}
                  chat={chat}
                  active={chat.id === activeChatId}
                  onOpen={() => openChat(chat.id)}
                  onDelete={() => void remove(chat.id)}
                />
              ))}
            </>
          ) : null}
        </div>
      ) : (
        <div className="min-h-0 flex-1 space-y-2 overflow-y-auto p-3">
          {activeChat?.messages.length ? (
            activeChat.messages.map((message) => (
              <div
                key={message.id}
                className={cn("flex", message.role === "user" ? "justify-end" : "justify-start")}
              >
                <div
                  className={cn(
                    "max-w-[85%] rounded-sm border px-2.5 py-2 text-[11px] leading-5",
                    message.role === "user"
                      ? "border-accent/40 bg-accent/10 text-ink"
                      : message.error
                        ? "border-block/40 bg-block/10 text-block"
                        : "border-edge bg-shell text-ink",
                  )}
                >
                  <p className="whitespace-pre-wrap">{message.text}</p>
                  <p className="mt-1 text-[9px] text-ink-dim">
                    {message.role === "assistant" ? `${message.model} · ` : ""}
                    {relativeTime(message.createdAt)}
                  </p>
                </div>
              </div>
            ))
          ) : (
            <p className="text-[10px] leading-4 text-ink-dim">
              {target
                ? "Ask why the model reached its conclusion, what evidence matters, or what to check next."
                : "Open a saved conversation, or use “Ask assistant” anywhere it appears — an alert, an incident narrative, a traffic review, the DNS page."}
            </p>
          )}
          {sending ? (
            <p className="flex items-center gap-2 text-[10px] text-ink-dim">
              <Loader2 className="h-3.5 w-3.5 animate-spin" /> thinking…
            </p>
          ) : null}
          <div ref={endRef} />
        </div>
      )}

      <div className="shrink-0 border-t border-edge p-2">
        <div className="rounded-sm border border-edge bg-shell p-2">
          <Textarea
            ref={questionRef}
            value={question}
            onChange={(event) => setQuestion(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                void send();
              }
            }}
            placeholder={
              target ? "Ask a follow-up question…" : "Pick a subject to start a conversation"
            }
            disabled={sending || loading || !target}
            maxLength={2_000}
            rows={2}
            className="min-h-14 w-full resize-none border-0 bg-transparent"
          />
          <div className="mt-2 flex items-center gap-2 border-t border-edge/60 pt-2">
            <Select
              value={model}
              onValueChange={setModel}
              options={[
                ...models.map((entry) => ({ value: entry.id, label: entry.label })),
                { value: "custom", label: "Custom model…" },
              ]}
              className="min-w-0 flex-1"
            />
            <Button
              size="sm"
              variant="primary"
              disabled={sending || loading || !target || !question.trim()}
              onClick={() => void send()}
            >
              {sending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Send className="h-3.5 w-3.5" />
              )}
              send
            </Button>
          </div>
          {model === "custom" ? (
            <Input
              value={customModel}
              onChange={(event) => setCustomModel(event.target.value)}
              placeholder="Model name"
              className="mt-2"
            />
          ) : null}
        </div>
      </div>
    </aside>
  );
}
