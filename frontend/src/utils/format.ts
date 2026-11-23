import type { Severity } from "../types/api";

export const SEVERITIES: Severity[] = ["informational", "low", "medium", "high", "critical"];

// One mapping used everywhere: badges, charts and score bars.
export const SEVERITY_COLOR: Record<Severity, string> = {
  informational: "#60a5fa",
  low: "#4ade80",
  medium: "#fbbf24",
  high: "#fb923c",
  critical: "#f87171",
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  informational: "Info",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

export function severityForScore(score: number | null | undefined): Severity {
  if (score == null) return "informational";
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "informational";
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: "UTC",
  }) + " UTC";
}

export function formatShort(value: string | null | undefined): string {
  if (!value) return "-";
  const date = new Date(value);
  return date.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false, timeZone: "UTC" });
}

export function formatRelative(value: string): string {
  const seconds = (Date.now() - new Date(value).getTime()) / 1000;
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86400)} d ago`;
}

export function titleCase(value: string): string {
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function formatNumber(value: number | null | undefined): string {
  return value == null ? "-" : value.toLocaleString();
}

/** Convert a UTC ISO string to the value a <input type="datetime-local"> expects (in UTC). */
export function toInputValue(iso: string | null | undefined): string {
  return iso ? iso.slice(0, 16) : "";
}

export function fromInputValue(value: string): string | undefined {
  return value ? `${value}:00Z` : undefined;
}
