import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";

import type { DashboardAnalytics, Severity } from "../types/api";
import { SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL, titleCase } from "../utils/format";

const AXIS = { stroke: "#64748b", fontSize: 11, tickLine: false, axisLine: false };
const GRID = <CartesianGrid stroke="#1f2a3d" strokeDasharray="3 3" vertical={false} />;
const TOOLTIP = {
  contentStyle: { background: "#111827", border: "1px solid #2b3a52", borderRadius: 6, fontSize: 12 },
  labelStyle: { color: "#e5e9f0" },
  itemStyle: { color: "#cbd5e1" },
  cursor: { fill: "rgba(148,163,184,0.08)" },
};
const ACCENT = "#38bdf8";

function bucketLabel(bucket: string, unit: "hour" | "day") {
  const d = new Date(bucket);
  const day = d.toLocaleDateString(undefined, { month: "short", day: "2-digit", timeZone: "UTC" });
  return unit === "hour" ? `${day} ${String(d.getUTCHours()).padStart(2, "0")}:00` : day;
}

export function EventsOverTime({ data }: { data: DashboardAnalytics }) {
  const rows = data.events_over_time.map((r) => ({ ...r, label: bucketLabel(r.bucket, data.range.bucket) }));
  return (
    <ResponsiveContainer width="100%" height={240}>
      <AreaChart data={rows} margin={{ top: 4, right: 8, left: -12, bottom: 0 }}>
        {GRID}
        <XAxis dataKey="label" {...AXIS} minTickGap={24} />
        <YAxis {...AXIS} allowDecimals={false} />
        <Tooltip {...TOOLTIP} />
        <Legend wrapperStyle={{ fontSize: 11, color: "#94a3b8" }} iconSize={8} />
        {SEVERITIES.map((s) => (
          <Area key={s} type="monotone" dataKey={s} name={SEVERITY_LABEL[s]} stackId="1"
            stroke={SEVERITY_COLOR[s]} fill={SEVERITY_COLOR[s]} fillOpacity={0.25} strokeWidth={1.2} isAnimationActive={false} />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function AuthTrend({ data }: { data: DashboardAnalytics }) {
  const rows = data.auth_activity.map((r) => ({ ...r, label: bucketLabel(r.bucket, data.range.bucket) }));
  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart data={rows} margin={{ top: 4, right: 8, left: -12, bottom: 0 }}>
        {GRID}
        <XAxis dataKey="label" {...AXIS} minTickGap={24} />
        <YAxis {...AXIS} allowDecimals={false} />
        <Tooltip {...TOOLTIP} />
        <Legend wrapperStyle={{ fontSize: 11 }} iconSize={8} />
        <Line type="monotone" dataKey="success" name="Successful" stroke="#4ade80" dot={false} strokeWidth={1.5} isAnimationActive={false} />
        <Line type="monotone" dataKey="failure" name="Failed" stroke="#f87171" dot={false} strokeWidth={1.5} isAnimationActive={false} />
      </LineChart>
    </ResponsiveContainer>
  );
}

export function SeverityBars({ rows }: { rows: { severity: Severity; count: number }[] }) {
  const data = rows.map((r) => ({ ...r, label: SEVERITY_LABEL[r.severity] }));
  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
        {GRID}
        <XAxis dataKey="label" {...AXIS} />
        <YAxis {...AXIS} allowDecimals={false} />
        <Tooltip {...TOOLTIP} />
        <Bar dataKey="count" name="Alerts" radius={[3, 3, 0, 0]} isAnimationActive={false}>
          {data.map((r) => <Cell key={r.severity} fill={SEVERITY_COLOR[r.severity]} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function HorizontalBars({ rows, label = "Events", color = ACCENT, height = 220 }: {
  rows: { name: string; count: number }[]; label?: string; color?: string; height?: number;
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 16, left: 8, bottom: 0 }}>
        <CartesianGrid stroke="#1f2a3d" strokeDasharray="3 3" horizontal={false} />
        <XAxis type="number" {...AXIS} allowDecimals={false} />
        <YAxis type="category" dataKey="name" {...AXIS} width={150} tick={{ fill: "#94a3b8", fontSize: 11 }} />
        <Tooltip {...TOOLTIP} />
        <Bar dataKey="count" name={label} fill={color} radius={[0, 3, 3, 0]} barSize={14} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  );
}

const BAND_COLOR: Record<string, string> = {
  "0-19": SEVERITY_COLOR.informational, "20-39": SEVERITY_COLOR.low, "40-59": SEVERITY_COLOR.medium,
  "60-79": SEVERITY_COLOR.high, "80-100": SEVERITY_COLOR.critical,
};

export function RiskDistribution({ rows }: { rows: { band: string; count: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={rows} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
        {GRID}
        <XAxis dataKey="band" {...AXIS} />
        <YAxis {...AXIS} allowDecimals={false} />
        <Tooltip {...TOOLTIP} />
        <Bar dataKey="count" name="Alerts" radius={[3, 3, 0, 0]} isAnimationActive={false}>
          {rows.map((r) => <Cell key={r.band} fill={BAND_COLOR[r.band]} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function IncidentStatusBars({ rows }: { rows: { status: string; count: number }[] }) {
  return <HorizontalBars rows={rows.map((r) => ({ name: titleCase(r.status), count: r.count }))} label="Incidents" color="#a78bfa" height={190} />;
}
