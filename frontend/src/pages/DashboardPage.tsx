import { Activity, AlertTriangle, Database, KeyRound, RefreshCw, Search, ShieldAlert, Siren, Target } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";

import { AuthTrend, EventsOverTime, HorizontalBars, IncidentStatusBars, RiskDistribution, SeverityBars } from "../components/charts";
import {
  Button, Card, EmptyState, ErrorState, Input, PageHeader, Pagination, RiskScore, Select, SeverityBadge, Spinner,
  StatusBadge, Table, Td, Th, cx,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { DashboardAnalytics, DashboardSummary, Page, SecurityEvent } from "../types/api";
import { SEVERITIES, SEVERITY_LABEL, formatDateTime, formatShort, fromInputValue, titleCase, toInputValue } from "../utils/format";

type Preset = "default" | "1" | "7" | "30" | "custom";

function Stat({ label, value, icon, tone, to, hint }: { label: string; value: ReactNode; icon: ReactNode; tone?: string; to?: string; hint?: string }) {
  const body = (
    <div className={cx("h-full rounded-lg border border-line bg-surface p-4 transition-colors", to && "hover:border-line-strong")}>
      <div className="flex items-center justify-between text-ink-faint">
        <span className="text-xs font-medium uppercase tracking-wide">{label}</span>
        {icon}
      </div>
      <div className={cx("mt-2 text-2xl font-semibold tabular-nums", tone)}>{value}</div>
      {hint && <div className="mt-1 truncate text-xs text-ink-faint">{hint}</div>}
    </div>
  );
  return to ? <Link to={to} className="block">{body}</Link> : body;
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const [preset, setPreset] = useState<Preset>("default");
  const [range, setRange] = useState<{ start?: string; end?: string }>({});
  // recent activity table controls
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [sort, setSort] = useState<{ field: string; order: "asc" | "desc" }>({ field: "timestamp", order: "desc" });
  const [page, setPage] = useState(1);

  const summary = useApi(() => api.get<DashboardSummary>("/dashboard/summary", range), [range.start, range.end], { pollMs: 60_000 });
  const analytics = useApi(() => api.get<DashboardAnalytics>("/dashboard/analytics", range), [range.start, range.end], { pollMs: 60_000 });
  const activeRange = summary.data?.range;
  const events = useApi(
    () => api.get<Page<SecurityEvent>>("/events", {
      q, severity: severity || undefined, category: category || undefined, sort: sort.field, order: sort.order,
      page, page_size: 10, start: activeRange?.start, end: activeRange?.end,
    }),
    [q, severity, category, sort.field, sort.order, page, activeRange?.start, activeRange?.end],
    { pollMs: 60_000 },
  );

  function applyPreset(next: Preset) {
    setPreset(next);
    setPage(1);
    if (next === "default") return setRange({});
    if (next === "custom") return;
    const end = activeRange ? new Date(activeRange.end) : new Date();
    const start = new Date(end.getTime() - Number(next) * 86_400_000);
    setRange({ start: start.toISOString(), end: end.toISOString() });
  }

  function refreshAll() {
    summary.reload();
    analytics.reload();
    events.reload();
  }

  function toggleSort(field: string) {
    setSort((s) => ({ field, order: s.field === field && s.order === "desc" ? "asc" : "desc" }));
  }

  const categories = useMemo(() => analytics.data?.event_categories.map((c) => c.category) ?? [], [analytics.data]);
  const s = summary.data;
  const lastJob = s?.ingestion.last_job;

  return (
    <div>
      <PageHeader
        title="Security overview"
        description={activeRange ? `Showing ${formatDateTime(activeRange.start)} to ${formatDateTime(activeRange.end)}. All figures are calculated from stored records.` : undefined}
        actions={
          <>
            <Select aria-label="Date range" value={preset} onChange={(e) => applyPreset(e.target.value as Preset)} className="w-60">
              <option value="default">Latest 7 days of data</option>
              <option value="1">Last 24 hours of data</option>
              <option value="7">Last 7 days</option>
              <option value="30">Last 30 days</option>
              <option value="custom">Custom range</option>
            </Select>
            <Button onClick={refreshAll} icon={<RefreshCw className={cx("h-4 w-4", (summary.loading || analytics.loading) && "animate-spin")} />}>Refresh</Button>
          </>
        }
      />
      {preset === "custom" && (
        <div className="mb-4 flex flex-wrap items-end gap-3 rounded-lg border border-line bg-surface p-3 text-sm">
          <label className="flex flex-col gap-1">From (UTC)
            <Input type="datetime-local" value={toInputValue(range.start ?? activeRange?.start)} onChange={(e) => setRange((r) => ({ ...r, start: fromInputValue(e.target.value) }))} />
          </label>
          <label className="flex flex-col gap-1">To (UTC)
            <Input type="datetime-local" value={toInputValue(range.end ?? activeRange?.end)} onChange={(e) => setRange((r) => ({ ...r, end: fromInputValue(e.target.value) }))} />
          </label>
        </div>
      )}

      {summary.error ? <ErrorState message={summary.error} onRetry={summary.reload} /> : !s ? <Spinner /> : (
        <>
          {s.synthetic_events > 0 && (
            <p className="mb-4 rounded-md border border-dashed border-line-strong px-3 py-2 text-xs text-ink-muted">
              {s.synthetic_events.toLocaleString()} of the events in this range are synthetic demonstration data.
            </p>
          )}
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label="Security events" value={s.total_events.toLocaleString()} icon={<Activity className="h-4 w-4" />} to="/events" />
            <Stat label="Alerts" value={s.total_alerts} hint={`${s.open_alerts} open`} icon={<ShieldAlert className="h-4 w-4" />} to="/alerts" />
            <Stat label="Open incidents" value={s.open_incidents} icon={<Siren className="h-4 w-4" />} to="/incidents?status=open&status=investigating&status=contained" />
            <Stat label="Critical incidents" value={s.critical_incidents} tone={s.critical_incidents ? "text-sev-critical" : undefined} icon={<AlertTriangle className="h-4 w-4" />} to="/incidents?severity=critical" />
            <Stat label="High-risk events" value={s.high_risk_events} tone={s.high_risk_events ? "text-sev-high" : undefined} hint="Risk score 60 or more" icon={<Target className="h-4 w-4" />} to="/events?min_risk=60" />
            <Stat label="Need investigation" value={s.events_requiring_investigation} hint="Evidence of open alerts" icon={<Search className="h-4 w-4" />} to="/alerts?status=new&status=acknowledged&status=investigating" />
            <Stat label="Auth failures" value={s.auth_failures} icon={<KeyRound className="h-4 w-4" />} to="/events?category=authentication&q=fail" />
            <Stat label="Ingestion" icon={<Database className="h-4 w-4" />}
              value={<span className={cx("text-base", s.ingestion.failed_jobs_24h ? "text-sev-high" : "text-sev-low")}>{s.ingestion.failed_jobs_24h ? `${s.ingestion.failed_jobs_24h} failed (24h)` : lastJob ? "Healthy" : "No jobs yet"}</span>}
              hint={lastJob ? `Last: ${lastJob.filename ?? "job " + lastJob.id} · ${lastJob.processed} stored, ${lastJob.rejected} rejected` : "Upload logs from Security Events"} />
          </div>
        </>
      )}

      {analytics.error ? <div className="mt-4"><ErrorState message={analytics.error} onRetry={analytics.reload} /></div> : analytics.data && (
        <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
          <Card title="Security events over time" className="xl:col-span-2">
            {analytics.data.events_over_time.length ? <EventsOverTime data={analytics.data} /> : <EmptyState title="No events in this range" />}
          </Card>
          <Card title="Alerts by severity">
            {analytics.data.alerts_by_severity.some((r) => r.count) ? <SeverityBars rows={analytics.data.alerts_by_severity} /> : <EmptyState title="No alerts in this range" />}
          </Card>
          <Card title="Authentication activity" className="xl:col-span-2">
            {analytics.data.auth_activity.length ? <AuthTrend data={analytics.data} /> : <EmptyState title="No authentication events" />}
          </Card>
          <Card title="Risk score distribution">
            <RiskDistribution rows={analytics.data.risk_distribution} />
          </Card>
          <Card title="Event categories">
            <HorizontalBars rows={analytics.data.event_categories.map((c) => ({ name: titleCase(c.category), count: c.count }))} />
          </Card>
          <Card title="Top event sources">
            <HorizontalBars rows={analytics.data.top_sources.map((c) => ({ name: c.source, count: c.count }))} color="#818cf8" />
          </Card>
          <Card title="Incident status">
            <IncidentStatusBars rows={analytics.data.incident_status} />
          </Card>
          <Card title="Detection rule performance" className="xl:col-span-3" bodyClassName="p-0">
            <Table>
              <thead><tr><Th>Rule</Th><Th>Name</Th><Th>Status</Th><Th className="text-right">Alerts</Th><Th className="text-right">Open</Th><Th className="text-right">False positives</Th><Th className="text-right">Avg score</Th></tr></thead>
              <tbody>
                {analytics.data.rule_performance.map((r) => (
                  <tr key={r.rule_id} className="hover:bg-surface-2/50">
                    <Td className="font-mono text-xs">{r.rule_id}</Td>
                    <Td><Link className="hover:text-accent" to={`/alerts?rule_id=${r.rule_id}`}>{r.name}</Link></Td>
                    <Td><StatusBadge status={r.enabled ? "enabled" : "disabled"} /></Td>
                    <Td className="text-right tabular-nums">{r.alerts}</Td>
                    <Td className="text-right tabular-nums">{r.open}</Td>
                    <Td className="text-right tabular-nums">{r.false_positives}</Td>
                    <Td className="text-right tabular-nums">{r.avg_score ?? "-"}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </Card>
        </div>
      )}

      <Card title="Recent activity" className="mt-4"
        actions={<span className="text-xs text-ink-faint">Refreshes every minute</span>}>
        <div className="mb-3 flex flex-wrap gap-2">
          <div className="relative min-w-[220px] flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-ink-faint" aria-hidden />
            <Input aria-label="Search events" placeholder="Search description, user, host, IP..." value={q} className="pl-8"
              onChange={(e) => { setQ(e.target.value); setPage(1); }} />
          </div>
          <Select aria-label="Severity filter" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }} className="w-40">
            <option value="">All severities</option>
            {SEVERITIES.map((sv) => <option key={sv} value={sv}>{SEVERITY_LABEL[sv]}</option>)}
          </Select>
          <Select aria-label="Category filter" value={category} onChange={(e) => { setCategory(e.target.value); setPage(1); }} className="w-44">
            <option value="">All categories</option>
            {categories.map((c) => <option key={c} value={c}>{titleCase(c)}</option>)}
          </Select>
        </div>
        {events.error ? <ErrorState message={events.error} onRetry={events.reload} /> : !events.data ? <Spinner /> :
          events.data.items.length === 0 ? <EmptyState title="No matching events" description="Adjust the filters, or upload logs from the Security Events page." /> : (
            <>
              <Table>
                <thead>
                  <tr>
                    <Th onClick={() => toggleSort("timestamp")} active={sort.field === "timestamp"} order={sort.order}>Timestamp</Th>
                    <Th onClick={() => toggleSort("event_category")} active={sort.field === "event_category"} order={sort.order}>Category</Th>
                    <Th onClick={() => toggleSort("source_system")} active={sort.field === "source_system"} order={sort.order}>Source</Th>
                    <Th>Description</Th>
                    <Th onClick={() => toggleSort("severity")} active={sort.field === "severity"} order={sort.order}>Severity</Th>
                    <Th onClick={() => toggleSort("risk_score")} active={sort.field === "risk_score"} order={sort.order}>Risk</Th>
                    <Th>Status</Th>
                  </tr>
                </thead>
                <tbody>
                  {events.data.items.map((e) => (
                    <tr key={e.id} className="cursor-pointer hover:bg-surface-2/60" onClick={() => navigate(`/events/${e.id}`)}>
                      <Td className="whitespace-nowrap font-mono text-xs text-ink-muted">{formatShort(e.timestamp)}</Td>
                      <Td>{titleCase(e.event_category)}</Td>
                      <Td className="max-w-[180px] truncate">{e.source_system}</Td>
                      <Td className="max-w-[360px]"><span className="line-clamp-1">{e.event_type}: {e.description || "-"}</span></Td>
                      <Td><SeverityBadge severity={e.severity} /></Td>
                      <Td><RiskScore score={e.risk_score} /></Td>
                      <Td>{e.risk_score != null ? <StatusBadge status="flagged" /> : <span className="text-xs text-ink-faint">Not flagged</span>}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
              <Pagination page={events.data.page} pages={events.data.pages} total={events.data.total} onPage={setPage} />
            </>
          )}
      </Card>
    </div>
  );
}
