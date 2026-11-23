import { AlertTriangle, ChevronLeft, ChevronRight, Inbox, LoaderCircle, X } from "lucide-react";
import { useEffect, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";

import type { Severity } from "../types/api";
import { SEVERITY_COLOR, SEVERITY_LABEL, severityForScore, titleCase } from "../utils/format";

export function cx(...classes: (string | false | null | undefined)[]) {
  return classes.filter(Boolean).join(" ");
}

// ---- layout -------------------------------------------------------------------------------------
export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-sm text-ink-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Card({ title, actions, children, className, bodyClassName }: {
  title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClassName?: string;
}) {
  return (
    <section className={cx("rounded-lg border border-line bg-surface", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-2 border-b border-line px-4 py-3">
          <h2 className="text-sm font-medium text-ink">{title}</h2>
          {actions}
        </header>
      )}
      <div className={cx("p-4", bodyClassName)}>{children}</div>
    </section>
  );
}

// ---- buttons & inputs ---------------------------------------------------------------------------
type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";
const BUTTON: Record<ButtonVariant, string> = {
  primary: "bg-accent-strong text-white hover:bg-sky-500 border-transparent",
  secondary: "bg-surface-2 text-ink border-line-strong hover:border-ink-faint",
  ghost: "bg-transparent text-ink-muted border-transparent hover:text-ink hover:bg-surface-2",
  danger: "bg-red-600/90 text-white border-transparent hover:bg-red-500",
};

export function Button({ variant = "secondary", busy, icon, children, className, disabled, ...props }:
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; busy?: boolean; icon?: ReactNode }) {
  return (
    <button
      type="button"
      className={cx("inline-flex h-9 items-center justify-center gap-2 rounded-md border px-3 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50", BUTTON[variant], className)}
      disabled={disabled || busy}
      {...props}
    >
      {busy ? <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden /> : icon}
      {children}
    </button>
  );
}

const FIELD = "h-9 rounded-md border border-line-strong bg-canvas px-3 text-sm text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none";

// Full width unless the caller sets its own width class.
const width = (className?: string) => (/(^|\s)(max-)?w-/.test(className ?? "") ? "" : "w-full");

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cx(FIELD, width(props.className), props.className)} />;
}

export function Select({ children, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={cx(FIELD, width(props.className), "pr-8", props.className)}>{children}</select>;
}

export function TextArea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={cx(FIELD, width(props.className), "h-auto min-h-[88px] py-2", props.className)} />;
}

export function Field({ label, hint, children, htmlFor }: { label: string; hint?: string; children: ReactNode; htmlFor?: string }) {
  return (
    <label className="block text-sm" htmlFor={htmlFor}>
      <span className="mb-1 block font-medium text-ink-muted">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-ink-faint">{hint}</span>}
    </label>
  );
}

// ---- badges -------------------------------------------------------------------------------------
export function SeverityBadge({ severity }: { severity: Severity }) {
  const color = SEVERITY_COLOR[severity] ?? SEVERITY_COLOR.informational;
  return (
    <span className="inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-xs font-medium"
      style={{ color, borderColor: `${color}55`, backgroundColor: `${color}14` }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} aria-hidden />
      {SEVERITY_LABEL[severity] ?? severity}
    </span>
  );
}

export function RiskScore({ score }: { score: number | null }) {
  if (score == null) return <span className="text-ink-faint">-</span>;
  const color = SEVERITY_COLOR[severityForScore(score)];
  return (
    <span className="inline-flex items-center gap-2" title={`Risk score ${score} of 100`}>
      <span className="w-7 text-right font-mono text-sm tabular-nums" style={{ color }}>{Math.round(score)}</span>
      <span className="h-1.5 w-14 overflow-hidden rounded-full bg-line" aria-hidden>
        <span className="block h-full rounded-full" style={{ width: `${Math.min(100, score)}%`, backgroundColor: color }} />
      </span>
    </span>
  );
}

const STATUS_STYLE: Record<string, string> = {
  new: "text-sky-300 border-sky-400/40 bg-sky-400/10",
  open: "text-sky-300 border-sky-400/40 bg-sky-400/10",
  acknowledged: "text-violet-300 border-violet-400/40 bg-violet-400/10",
  investigating: "text-amber-300 border-amber-400/40 bg-amber-400/10",
  contained: "text-orange-300 border-orange-400/40 bg-orange-400/10",
  resolved: "text-emerald-300 border-emerald-400/40 bg-emerald-400/10",
  closed: "text-slate-300 border-slate-500/40 bg-slate-500/10",
  false_positive: "text-slate-300 border-slate-500/40 bg-slate-500/10",
  completed: "text-emerald-300 border-emerald-400/40 bg-emerald-400/10",
  failed: "text-red-300 border-red-400/40 bg-red-400/10",
  success: "text-emerald-300 border-emerald-400/40 bg-emerald-400/10",
  failure: "text-red-300 border-red-400/40 bg-red-400/10",
  denied: "text-orange-300 border-orange-400/40 bg-orange-400/10",
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={cx("inline-flex rounded border px-1.5 py-0.5 text-xs font-medium", STATUS_STYLE[status] ?? "border-line-strong text-ink-muted")}>
      {titleCase(status)}
    </span>
  );
}

export function SyntheticTag() {
  return (
    <span className="inline-flex rounded border border-dashed border-ink-faint px-1.5 py-0.5 text-[11px] text-ink-muted" title="Synthetic demonstration data">
      Demo data
    </span>
  );
}

// ---- states -------------------------------------------------------------------------------------
export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-10 text-sm text-ink-muted" role="status">
      <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden /> {label}...
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-md border border-red-500/30 bg-red-500/5 px-4 py-6 text-center text-sm" role="alert">
      <AlertTriangle className="h-5 w-5 text-red-400" aria-hidden />
      <p className="text-red-200">{message}</p>
      {onRetry && <Button onClick={onRetry}>Try again</Button>}
    </div>
  );
}

export function InlineError({ message }: { message: string | null }) {
  if (!message) return null;
  return <p className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200" role="alert">{message}</p>;
}

export function EmptyState({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 py-10 text-center">
      <Inbox className="h-6 w-6 text-ink-faint" aria-hidden />
      <p className="text-sm font-medium text-ink">{title}</p>
      {description && <p className="max-w-md text-sm text-ink-muted">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

// ---- table & pagination -------------------------------------------------------------------------
export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[720px] border-collapse text-left text-sm">{children}</table>
    </div>
  );
}

export function Th({ children, className, onClick, active, order }: {
  children?: ReactNode; className?: string; onClick?: () => void; active?: boolean; order?: "asc" | "desc";
}) {
  return (
    <th className={cx("border-b border-line px-3 py-2 text-xs font-medium uppercase tracking-wide text-ink-faint", className)}
      aria-sort={active ? (order === "asc" ? "ascending" : "descending") : undefined}>
      {onClick ? (
        <button type="button" onClick={onClick} className={cx("inline-flex items-center gap-1 uppercase hover:text-ink", active && "text-ink")}>
          {children}{active ? (order === "asc" ? " ↑" : " ↓") : ""}
        </button>
      ) : children}
    </th>
  );
}

export function Td({ children, className }: { children?: ReactNode; className?: string }) {
  return <td className={cx("border-b border-line/60 px-3 py-2 align-top", className)}>{children}</td>;
}

export function Pagination({ page, pages, total, onPage }: { page: number; pages: number; total: number; onPage: (p: number) => void }) {
  return (
    <div className="flex items-center justify-between gap-2 pt-3 text-sm text-ink-muted">
      <span>{total.toLocaleString()} result{total === 1 ? "" : "s"}</span>
      <div className="flex items-center gap-2">
        <Button variant="ghost" aria-label="Previous page" disabled={page <= 1} onClick={() => onPage(page - 1)} icon={<ChevronLeft className="h-4 w-4" />} />
        <span>Page {page} of {pages}</span>
        <Button variant="ghost" aria-label="Next page" disabled={page >= pages} onClick={() => onPage(page + 1)} icon={<ChevronRight className="h-4 w-4" />} />
      </div>
    </div>
  );
}

// ---- modal --------------------------------------------------------------------------------------
export function Modal({ title, open, onClose, children, footer, wide }: {
  title: string; open: boolean; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 pt-[8vh]" onMouseDown={onClose}>
      <div role="dialog" aria-modal="true" aria-label={title} onMouseDown={(e) => e.stopPropagation()}
        className={cx("w-full rounded-lg border border-line-strong bg-surface shadow-xl", wide ? "max-w-3xl" : "max-w-lg")}>
        <header className="flex items-center justify-between border-b border-line px-4 py-3">
          <h2 className="text-sm font-semibold">{title}</h2>
          <Button variant="ghost" aria-label="Close" onClick={onClose} icon={<X className="h-4 w-4" />} className="h-8 px-2" />
        </header>
        <div className="space-y-4 p-4">{children}</div>
        {footer && <footer className="flex justify-end gap-2 border-t border-line px-4 py-3">{footer}</footer>}
      </div>
    </div>
  );
}

export function KeyValue({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
      {items.map(([k, v]) => (
        <div key={k} className="min-w-0">
          <dt className="text-xs uppercase tracking-wide text-ink-faint">{k}</dt>
          <dd className="mt-0.5 break-words text-ink">{v ?? "-"}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="mb-4 flex gap-1 border-b border-line" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} type="button" role="tab" aria-selected={value === t.id} onClick={() => onChange(t.id)}
          className={cx("-mb-px border-b-2 px-3 py-2 text-sm", value === t.id ? "border-accent text-ink" : "border-transparent text-ink-muted hover:text-ink")}>
          {t.label}
        </button>
      ))}
    </div>
  );
}
