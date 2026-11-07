import * as SelectPrimitive from "@radix-ui/react-select";
import * as SwitchPrimitive from "@radix-ui/react-switch";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { cva, type VariantProps } from "class-variance-authority";
import { Check, ChevronDown, Copy, X } from "lucide-react";
import { type ComponentProps, type ReactNode, useEffect, useRef, useState } from "react";
import { cn, copyText } from "@/lib/utils";

const buttonStyles = cva(
  "inline-flex items-center justify-center gap-1.5 rounded-sm whitespace-nowrap transition-colors disabled:opacity-40 disabled:pointer-events-none focus-visible:outline-1 focus-visible:outline-status",
  {
    variants: {
      variant: {
        primary: "bg-accent hover:bg-accent-bright text-white",
        secondary: "bg-[#3a3d41] hover:bg-[#45494e] text-ink",
        ghost: "hover:bg-hover text-ink",
        danger: "bg-[#5a1d1d] hover:bg-[#7a2626] text-[#f5b8b8]",
        outline: "border border-edge hover:bg-hover text-ink",
      },
      size: {
        sm: "h-6 px-2 text-[11px]",
        md: "h-7 px-3 text-xs",
        icon: "h-6 w-6",
      },
    },
    defaultVariants: { variant: "secondary", size: "md" },
  },
);

export function Button({
  className,
  variant,
  size,
  ...props
}: ComponentProps<"button"> & VariantProps<typeof buttonStyles>) {
  return (
    <button type="button" className={cn(buttonStyles({ variant, size }), className)} {...props} />
  );
}

/**
 * `text` is a thunk so a large serialisation is only built on click, not on
 * every render of the panel holding the button.
 */
export function CopyButton({
  text,
  label,
  title,
  className,
  icon = Copy,
  variant = "outline",
  size = "sm",
}: {
  text: () => string;
  label?: string;
  title: string;
  className?: string;
  icon?: typeof Copy;
} & VariantProps<typeof buttonStyles>) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => () => clearTimeout(timer.current), []);

  const copy = async () => {
    const ok = await copyText(text());
    setState(ok ? "copied" : "failed");
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setState("idle"), 1600);
  };

  const Icon = state === "copied" ? Check : state === "failed" ? X : icon;

  return (
    <Button
      variant={variant}
      size={label ? size : "icon"}
      title={title}
      aria-label={title}
      onClick={copy}
      className={cn(
        state === "copied" && "text-ignore",
        state === "failed" && "text-block",
        className,
      )}
    >
      <Icon className="h-3 w-3 shrink-0" />
      {label ? <span>{state === "copied" ? "copied" : label}</span> : null}
      <span className="sr-only" aria-live="polite">
        {state === "copied" ? "Copied to clipboard" : state === "failed" ? "Copy failed" : ""}
      </span>
    </Button>
  );
}

export function Input({ className, ...props }: ComponentProps<"input">) {
  return (
    <input
      className={cn(
        "h-7 w-full rounded-sm border border-edge bg-[#3c3c3c] px-2 text-xs text-ink placeholder:text-ink-dim",
        "focus:border-status focus:outline-none",
        className,
      )}
      {...props}
    />
  );
}

export function Textarea({ className, ...props }: ComponentProps<"textarea">) {
  return (
    <textarea
      className={cn(
        "w-full rounded-sm border border-edge bg-[#3c3c3c] px-2 py-1.5 text-xs text-ink placeholder:text-ink-dim",
        "focus:border-status focus:outline-none resize-y",
        className,
      )}
      {...props}
    />
  );
}

export function Field({
  label,
  hint,
  children,
  className,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    // biome-ignore lint/a11y/noLabelWithoutControl: the control is the wrapped child, which the rule cannot see through
    <label className={cn("flex flex-col gap-1", className)}>
      <span className="text-[11px] font-medium text-ink">{label}</span>
      {children}
      {hint ? <span className="text-[10px] leading-snug text-ink-dim">{hint}</span> : null}
    </label>
  );
}

export function Switch({
  checked,
  onCheckedChange,
  label,
  hint,
}: {
  checked: boolean;
  onCheckedChange: (value: boolean) => void;
  label: string;
  hint?: string;
}) {
  return (
    <div className="flex items-start justify-between gap-4 py-1">
      <div className="flex flex-col">
        <span className="text-[11px] font-medium text-ink">{label}</span>
        {hint ? <span className="text-[10px] leading-snug text-ink-dim">{hint}</span> : null}
      </div>
      <SwitchPrimitive.Root
        checked={checked}
        onCheckedChange={onCheckedChange}
        className={cn(
          "relative h-4 w-8 shrink-0 rounded-full transition-colors",
          checked ? "bg-status" : "bg-[#4a4a4a]",
        )}
      >
        <SwitchPrimitive.Thumb className="block h-3 w-3 translate-x-0.5 rounded-full bg-white transition-transform data-[state=checked]:translate-x-4" />
      </SwitchPrimitive.Root>
    </div>
  );
}

export function Select({
  value,
  onValueChange,
  options,
  className,
}: {
  value: string;
  onValueChange: (value: string) => void;
  options: { value: string; label: string }[];
  className?: string;
}) {
  return (
    <SelectPrimitive.Root value={value} onValueChange={onValueChange}>
      <SelectPrimitive.Trigger
        className={cn(
          "flex h-7 items-center justify-between gap-2 rounded-sm border border-edge bg-[#3c3c3c] px-2 text-xs",
          "focus:border-status focus:outline-none",
          className,
        )}
      >
        <SelectPrimitive.Value />
        <ChevronDown className="h-3 w-3 text-ink-dim" />
      </SelectPrimitive.Trigger>
      <SelectPrimitive.Portal>
        <SelectPrimitive.Content
          position="popper"
          sideOffset={4}
          className="z-50 min-w-[var(--radix-select-trigger-width)] overflow-hidden rounded-sm border border-edge bg-panel shadow-lg"
        >
          <SelectPrimitive.Viewport className="p-1">
            {options.map((option) => (
              <SelectPrimitive.Item
                key={option.value}
                value={option.value}
                className="flex cursor-default items-center gap-2 rounded-sm px-2 py-1 text-xs outline-none data-[highlighted]:bg-accent data-[highlighted]:text-white"
              >
                <SelectPrimitive.ItemIndicator>
                  <Check className="h-3 w-3" />
                </SelectPrimitive.ItemIndicator>
                <SelectPrimitive.ItemText>{option.label}</SelectPrimitive.ItemText>
              </SelectPrimitive.Item>
            ))}
          </SelectPrimitive.Viewport>
        </SelectPrimitive.Content>
      </SelectPrimitive.Portal>
    </SelectPrimitive.Root>
  );
}

export function Tooltip({ label, children }: { label: string; children: ReactNode }) {
  return (
    <TooltipPrimitive.Provider delayDuration={400}>
      <TooltipPrimitive.Root>
        <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
        <TooltipPrimitive.Portal>
          <TooltipPrimitive.Content
            side="right"
            sideOffset={6}
            className="z-50 rounded-sm border border-edge bg-panel px-2 py-1 text-[11px] text-ink shadow-lg"
          >
            {label}
          </TooltipPrimitive.Content>
        </TooltipPrimitive.Portal>
      </TooltipPrimitive.Root>
    </TooltipPrimitive.Provider>
  );
}

export function Badge({
  children,
  className,
  title,
}: {
  children: ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center rounded-sm border border-edge px-1.5 py-px text-[10px] uppercase tracking-wide",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function SectionTitle({ children }: { children: ReactNode }) {
  return (
    <h2 className="mb-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-ink-dim">
      {children}
    </h2>
  );
}

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <section className={cn("rounded-sm border border-edge bg-panel p-3", className)}>
      {children}
    </section>
  );
}

/** Free-text set editor: type-and-enter to add, × to remove. Used for every allowlist in Settings. */
export function ListEditor({
  label,
  hint,
  values,
  onChange,
  placeholder,
}: {
  label: string;
  hint?: string;
  values: string[];
  onChange: (values: string[]) => void;
  placeholder: string;
}) {
  const [draft, setDraft] = useState("");
  const add = () => {
    onChange([...values, draft.trim()]);
    setDraft("");
  };
  return (
    <Field label={label} hint={hint}>
      <div className="flex flex-wrap gap-1">
        {values.map((value) => (
          <Badge key={value} className="gap-1 text-ink">
            <span className="font-mono normal-case">{value}</span>
            <button
              type="button"
              onClick={() => onChange(values.filter((v) => v !== value))}
              className="text-ink-dim hover:text-block"
              aria-label={`Remove ${value}`}
            >
              ×
            </button>
          </Badge>
        ))}
      </div>
      <div className="mt-1 flex gap-1.5">
        <Input
          value={draft}
          placeholder={placeholder}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && draft.trim()) add();
          }}
        />
        <Button size="md" disabled={!draft.trim()} onClick={add}>
          add
        </Button>
      </div>
    </Field>
  );
}
