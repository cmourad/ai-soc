import assert from "node:assert/strict";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import type { AssistanceChat, AssistanceSubjectKind } from "@aisoc/shared";
import { llmStage, useTemporaryDataDir } from "../testing/settings-fixture.js";

const dataDir = useTemporaryDataDir("aisoc-assistant-persist-test-", {
  secondTriage: llmStage("test-model-2"),
});

const CHATS_DIR = join(dataDir, "assistant-chats");
const MAX_CHATS = 40;
const SEEDED = 45;

mkdirSync(CHATS_DIR, { recursive: true, mode: 0o700 });

interface StoredChat {
  chat: AssistanceChat;
  systemPrompt: string;
  eventId: string | null;
}

function readStored(id: string): StoredChat {
  return JSON.parse(readFileSync(join(CHATS_DIR, `${id}.json`), "utf8")) as StoredChat;
}

/** Write a conversation the way an earlier run of the server would have left it. */
function seed(index: number, subjectKind: AssistanceSubjectKind): string {
  const id = `seeded-${String(index).padStart(2, "0")}`;
  const at = new Date(Date.UTC(2026, 7, 17, 12, index)).toISOString();
  const stored: StoredChat = {
    chat: {
      id,
      subjectKind,
      subjectId: `${subjectKind}-subject-${index}`,
      createdAt: at,
      updatedAt: at,
      model: "test-model-2",
      messages: [
        {
          id: `${id}-q`,
          role: "user",
          text: `Question ${index}`,
          model: "test-model-2",
          createdAt: at,
          error: null,
        },
        {
          id: `${id}-a`,
          role: "assistant",
          text: `Answer ${index}`,
          model: "test-model-2",
          createdAt: at,
          error: null,
        },
      ],
    },
    systemPrompt: `FROZEN EVIDENCE FOR ${id}`,
    eventId: null,
  };
  writeFileSync(join(CHATS_DIR, `${id}.json`), JSON.stringify(stored));
  return id;
}

const seeded: string[] = [];
for (let index = 0; index < SEEDED; index += 1) {
  seeded.push(seed(index, index === SEEDED - 1 ? "dns" : index % 2 === 0 ? "incident" : "alert"));
}
const newest = seeded[SEEDED - 1]!;
const survivor = seeded[SEEDED - 2]!;
const dropped = seeded.slice(0, SEEDED - MAX_CHATS);
writeFileSync(join(CHATS_DIR, "truncated.json"), "{ this was never valid");

const { deleteAssistanceChat, listAllAssistanceChats, listAssistanceChats, sendAssistanceMessage } =
  await import("./chat.js");
const { listLlmCalls } = await import("../store.js");

test("conversations from an earlier run are hydrated newest first", () => {
  const all = listAllAssistanceChats();
  assert.equal(all.length, MAX_CHATS);
  assert.equal(all[0]?.id, newest);
  assert.deepEqual(
    all.map((chat) => chat.updatedAt),
    [...all].map((chat) => chat.updatedAt).sort((a, b) => b.localeCompare(a)),
  );
  assert.ok(all.some((chat) => chat.subjectKind === "dns"));
  assert.ok(all.some((chat) => chat.subjectKind === "alert"));
});

test("hydration drops the oldest beyond the cap from disk, and unparseable files", () => {
  const files = readdirSync(CHATS_DIR).filter((file) => file.endsWith(".json"));
  assert.equal(files.length, MAX_CHATS);
  for (const id of dropped) assert.equal(existsSync(join(CHATS_DIR, `${id}.json`)), false);
  assert.equal(existsSync(join(CHATS_DIR, "truncated.json")), false);
});

test("the per-subject list still filters", () => {
  const chat = listAllAssistanceChats().find((entry) => entry.subjectKind === "alert");
  assert.ok(chat);
  const scoped = listAssistanceChats("alert", chat.subjectId);
  assert.deepEqual(
    scoped.map((entry) => entry.id),
    [chat.id],
  );
  assert.equal(listAssistanceChats("alert", "never-existed").length, 0);
});

test("a hydrated conversation continues on its frozen prompt after its subject is gone", async () => {
  const before = readStored(survivor);
  const chat = await sendAssistanceMessage({
    chatId: survivor,
    subjectKind: before.chat.subjectKind,
    subjectId: before.chat.subjectId,
    question: "Is this still explainable?",
    model: "secondTriage",
  });
  assert.equal(chat.messages.length, before.chat.messages.length + 2);

  const call = listLlmCalls().find((entry) => entry.stage === "assistant_chat");
  assert.equal(call?.systemPrompt, before.systemPrompt);

  const after = readStored(survivor);
  assert.equal(after.systemPrompt, before.systemPrompt);
  assert.equal(after.chat.messages.length, chat.messages.length);
  assert.ok(after.chat.updatedAt > before.chat.updatedAt);
});

test("deleting a conversation removes its file", () => {
  assert.equal(deleteAssistanceChat(survivor), true);
  assert.equal(existsSync(join(CHATS_DIR, `${survivor}.json`)), false);
  assert.equal(deleteAssistanceChat(survivor), false);
  assert.equal(
    listAllAssistanceChats().some((chat) => chat.id === survivor),
    false,
  );
});
