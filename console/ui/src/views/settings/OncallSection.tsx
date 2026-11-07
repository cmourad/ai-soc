import { Plus, Trash2 } from "lucide-react";
import {
  Button,
  Card,
  Field,
  Input,
  SectionTitle,
  Select,
  Switch,
} from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import type { SettingsSectionProps } from "./shared";
import { SEVERITY_OPTIONS, STAGE_OPTIONS } from "./shared";

export function OncallSection({ draft, patch }: SettingsSectionProps) {
  return (
    <Card className="flex flex-col gap-3">
      <SectionTitle>On-call routing</SectionTitle>
      <Switch
        label="Enable on-call paging"
        hint="Alerts page whoever is on shift, then escalate down the roster if nobody acknowledges."
        checked={draft.oncall.enabled}
        onCheckedChange={(enabled) => patch("oncall", { enabled })}
      />
      <div className="grid grid-cols-2 gap-3">
        <Field
          label="Ack timeout (minutes)"
          hint="No acknowledgement in this window escalates to the next person."
        >
          <Input
            type="number"
            step="0.5"
            min="0.1"
            value={draft.oncall.ackTimeoutMinutes}
            onChange={(event) => patch("oncall", { ackTimeoutMinutes: Number(event.target.value) })}
          />
        </Field>
        <Field label="Page at or below severity">
          <Select
            value={String(draft.oncall.minSeverity)}
            onValueChange={(value) => patch("oncall", { minSeverity: Number(value) })}
            options={SEVERITY_OPTIONS}
          />
        </Field>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11px] text-ink">Page when an alert reaches:</span>
        {STAGE_OPTIONS.map((stage) => {
          const on = draft.oncall.notifyOnStages.includes(stage);
          return (
            <button
              key={stage}
              type="button"
              onClick={() =>
                patch("oncall", {
                  notifyOnStages: on
                    ? draft.oncall.notifyOnStages.filter((s) => s !== stage)
                    : [...draft.oncall.notifyOnStages, stage],
                })
              }
              className={cn(
                "rounded-sm border px-2 py-0.5 font-mono text-[10px]",
                on ? "border-status bg-active text-ink" : "border-edge text-ink-dim",
              )}
            >
              {stage.replace(/_/g, " ")}
            </button>
          );
        })}
      </div>

      <div>
        <div className="mb-1 flex items-center justify-between">
          <span className="text-[11px] font-medium text-ink">Personnel</span>
          <Button
            size="sm"
            onClick={() =>
              patch("oncall", {
                people: [
                  ...draft.oncall.people,
                  {
                    id: crypto.randomUUID(),
                    name: "",
                    telegramId: "",
                    email: "",
                    active: true,
                  },
                ],
              })
            }
          >
            <Plus className="h-3 w-3" />
            add person
          </Button>
        </div>
        <div className="flex flex-col gap-1.5">
          {draft.oncall.people.length === 0 ? (
            <p className="text-[11px] text-ink-dim">
              No personnel yet. Alerts cannot page anyone until you add at least one.
            </p>
          ) : null}
          {draft.oncall.people.map((person, index) => (
            <div
              key={person.id}
              className="grid grid-cols-[1fr_1fr_1fr_auto_auto] items-center gap-1.5"
            >
              <Input
                value={person.name}
                placeholder="name"
                onChange={(event) => {
                  const people = draft.oncall.people.slice();
                  people[index] = { ...person, name: event.target.value };
                  patch("oncall", { people });
                }}
              />
              <Input
                value={person.telegramId}
                placeholder="telegram chat id"
                onChange={(event) => {
                  const people = draft.oncall.people.slice();
                  people[index] = { ...person, telegramId: event.target.value };
                  patch("oncall", { people });
                }}
              />
              <Input
                value={person.email}
                placeholder="email"
                onChange={(event) => {
                  const people = draft.oncall.people.slice();
                  people[index] = { ...person, email: event.target.value };
                  patch("oncall", { people });
                }}
              />
              <button
                type="button"
                title={person.active ? "Active in rotation" : "Skipped"}
                onClick={() => {
                  const people = draft.oncall.people.slice();
                  people[index] = { ...person, active: !person.active };
                  patch("oncall", { people });
                }}
                className={cn(
                  "rounded-sm border px-2 py-1 text-[10px]",
                  person.active ? "border-status bg-active text-ink" : "border-edge text-ink-dim",
                )}
              >
                {person.active ? "active" : "paused"}
              </button>
              <Button
                size="icon"
                variant="ghost"
                aria-label="Remove person"
                onClick={() =>
                  patch("oncall", {
                    people: draft.oncall.people.filter((p) => p.id !== person.id),
                    shifts: draft.oncall.shifts.filter((s) => s.personId !== person.id),
                  })
                }
              >
                <Trash2 className="h-3 w-3" />
              </Button>
            </div>
          ))}
        </div>
      </div>

      <div>
        <div className="mb-1 flex items-center justify-between">
          <span className="text-[11px] font-medium text-ink">Weekly shifts</span>
          <Button
            size="sm"
            disabled={draft.oncall.people.length === 0}
            onClick={() =>
              patch("oncall", {
                shifts: [
                  ...draft.oncall.shifts,
                  {
                    id: crypto.randomUUID(),
                    personId: draft.oncall.people[0]?.id ?? "",
                    days: [1, 2, 3, 4, 5],
                    startHour: 9,
                    endHour: 18,
                  },
                ],
              })
            }
          >
            <Plus className="h-3 w-3" />
            add shift
          </Button>
        </div>
        <p className="mb-1.5 text-[10px] text-ink-dim">
          Whoever is on shift is paged first; everyone else forms the escalation order behind them,
          so a page always has somewhere to go.
        </p>
        <div className="flex flex-col gap-1.5">
          {draft.oncall.shifts.map((shift, index) => (
            <div
              key={shift.id}
              className="grid grid-cols-[1fr_auto_70px_70px_auto] items-center gap-1.5"
            >
              <Select
                value={shift.personId}
                onValueChange={(personId) => {
                  const shifts = draft.oncall.shifts.slice();
                  shifts[index] = { ...shift, personId };
                  patch("oncall", { shifts });
                }}
                options={draft.oncall.people.map((person) => ({
                  value: person.id,
                  label: person.name || "unnamed",
                }))}
              />
              <div className="flex gap-0.5">
                {["S", "M", "T", "W", "T", "F", "S"].map((letter, day) => {
                  const on = shift.days.includes(day);
                  return (
                    <button
                      // biome-ignore lint/suspicious/noArrayIndexKey: day index is the identity
                      key={day}
                      type="button"
                      onClick={() => {
                        const shifts = draft.oncall.shifts.slice();
                        shifts[index] = {
                          ...shift,
                          days: on
                            ? shift.days.filter((d) => d !== day)
                            : [...shift.days, day].sort(),
                        };
                        patch("oncall", { shifts });
                      }}
                      className={cn(
                        "h-6 w-6 rounded-sm border text-[10px]",
                        on ? "border-status bg-active text-ink" : "border-edge text-ink-dim",
                      )}
                    >
                      {letter}
                    </button>
                  );
                })}
              </div>
              <Input
                type="number"
                min="0"
                max="23"
                value={shift.startHour}
                onChange={(event) => {
                  const shifts = draft.oncall.shifts.slice();
                  shifts[index] = { ...shift, startHour: Number(event.target.value) };
                  patch("oncall", { shifts });
                }}
              />
              <Input
                type="number"
                min="0"
                max="23"
                value={shift.endHour}
                onChange={(event) => {
                  const shifts = draft.oncall.shifts.slice();
                  shifts[index] = { ...shift, endHour: Number(event.target.value) };
                  patch("oncall", { shifts });
                }}
              />
              <Button
                size="icon"
                variant="ghost"
                aria-label="Remove shift"
                onClick={() =>
                  patch("oncall", {
                    shifts: draft.oncall.shifts.filter((s) => s.id !== shift.id),
                  })
                }
              >
                <Trash2 className="h-3 w-3" />
              </Button>
            </div>
          ))}
        </div>
      </div>
    </Card>
  );
}
