import { Download, RefreshCw, Search } from "lucide-react";
import { useNavigate, useSearchParams } from "react-router-dom";

import {
  Button, Card, EmptyState, ErrorState, InlineError, Input, PageHeader, Pagination, RiskScore, Select, SeverityBadge,
  Spinner, StatusBadge, SyntheticTag, Table, Td, Th,
} from "../components/ui";
import { useAuth } from "../contexts/AuthContext";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { Alert, Page, Rule, UserRef } from "../types/api";
import { SEVERITIES, SEVERITY_LABEL, formatShort, titleCase } from "../utils/format";

const STATUSES = ["new", "acknowledged", "investigating", "resolved", "false_positive"];

export default function AlertsPage() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const key = params.toString();
  const statuses = params.getAll("status");
  const page = Number(params.get("page") ?? 1);
  const sort = params.get("sort") ?? "last_seen";
  const order = (params.get("order") as "asc" | "desc") ?? "desc";
  const exportAction = useAction();

  const rules = useApi(() => api.get<Rule[]>("/rules"), []);
  const assignees = useApi(() => api.get<UserRef[]>("/users/assignable"), []);
  const query = {
    q: params.get("q") ?? undefined, severity: params.getAll("severity"), status: statuses, rule_id: params.get("rule_id") ?? undefined,
    assigned_to: params.get("assigned_to") ?? undefined, has_incident: params.get("has_incident") ?? undefined,
  };
  const alerts = useApi(() => api.get<Page<Alert>>("/alerts", { ...query, sort, order, page, page_size: 25 }), [key], { pollMs: 60_000 });

  function update(changes: Record<string, string | string[] | undefined>, resetPage = true) {
    const next = new URLSearchParams(params);
    Object.entries(changes).forEach(([k, v]) => {
      next.delete(k);
      if (Array.isArray(v)) v.forEach((x) => next.append(k, x));
      else if (v) next.set(k, v);
    });
    if (resetPage) next.delete("page");
    setParams(next, { replace: true });
  }

  const toggleSort = (field: string) => update({ sort: field, order: sort === field && order === "desc" ? "asc" : "desc" }, false);

  return (
    <div>
      <PageHeader title="Alerts" description="Raised by deterministic detection rules from stored events. An alert means suspicious activity that needs review, not a confirmed attack." />
      <Card bodyClassName="p-3">
        <div key={key} className="mb-3 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-6">
          <div className="relative lg:col-span-2">
            <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-ink-faint" aria-hidden />
            <Input aria-label="Search alerts" placeholder="Search title, account, host" className="pl-8" defaultValue={query.q ?? ""}
              onKeyDown={(e) => e.key === "Enter" && update({ q: (e.target as HTMLInputElement).value })}
              onBlur={(e) => e.target.value !== (query.q ?? "") && update({ q: e.target.value })} />
          </div>
          <Select aria-label="Status" value={statuses.length === 1 ? statuses[0] : statuses.length ? "open" : ""}
            onChange={(e) => update({ status: e.target.value === "open" ? ["new", "acknowledged", "investigating"] : e.target.value ? [e.target.value] : undefined })}>
            <option value="">All statuses</option>
            <option value="open">Open (new, acknowledged, investigating)</option>
            {STATUSES.map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
          </Select>
          <Select aria-label="Severity" value={params.get("severity") ?? ""} onChange={(e) => update({ severity: e.target.value })}>
            <option value="">All severities</option>{SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
          </Select>
          <Select aria-label="Rule" value={query.rule_id ?? ""} onChange={(e) => update({ rule_id: e.target.value })}>
            <option value="">All rules</option>{rules.data?.map((r) => <option key={r.id} value={r.id}>{r.id} {r.name}</option>)}
          </Select>
          <Select aria-label="Assignee" value={query.assigned_to ?? ""} onChange={(e) => update({ assigned_to: e.target.value })}>
            <option value="">Any assignee</option>{assignees.data?.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
          </Select>
        </div>
        <div className="mb-3 flex items-center gap-2">
          {key && <Button variant="ghost" onClick={() => setParams({}, { replace: true })}>Clear filters</Button>}
          <div className="flex-1" />
          <Button variant="ghost" onClick={alerts.reload} icon={<RefreshCw className="h-4 w-4" />}>Refresh</Button>
          {can("events:export") && <Button busy={exportAction.busy} icon={<Download className="h-4 w-4" />}
            onClick={() => exportAction.run(() => api.download("/alerts/export", { ...query, format: "csv" }, "sentinel-alerts.csv"))}>Export CSV</Button>}
        </div>
        <InlineError message={exportAction.error} />
        {alerts.error ? <ErrorState message={alerts.error} onRetry={alerts.reload} /> : !alerts.data ? <Spinner /> :
          alerts.data.items.length === 0 ? <EmptyState title="No alerts" description="No alerts match these filters. Alerts appear when detection rules match ingested events." /> : (
            <>
              <Table>
                <thead><tr>
                  <Th>ID</Th><Th>Alert</Th>
                  <Th onClick={() => toggleSort("risk_score")} active={sort === "risk_score"} order={order}>Risk</Th>
                  <Th onClick={() => toggleSort("severity")} active={sort === "severity"} order={order}>Severity</Th>
                  <Th onClick={() => toggleSort("status")} active={sort === "status"} order={order}>Status</Th>
                  <Th onClick={() => toggleSort("event_count")} active={sort === "event_count"} order={order}>Events</Th>
                  <Th onClick={() => toggleSort("last_seen")} active={sort === "last_seen"} order={order}>Last seen</Th>
                  <Th>Assignee</Th><Th>Incident</Th>
                </tr></thead>
                <tbody>
                  {alerts.data.items.map((a) => (
                    <tr key={a.id} className="cursor-pointer hover:bg-surface-2/60" onClick={() => navigate(`/alerts/${a.id}`)}>
                      <Td className="font-mono text-xs text-ink-muted">#{a.id}</Td>
                      <Td><div className="font-medium">{a.title}</div>
                        <div className="flex items-center gap-2 text-xs text-ink-faint"><span className="font-mono">{a.rule_id}</span>{a.is_synthetic && <SyntheticTag />}</div></Td>
                      <Td><RiskScore score={a.risk_score} /></Td>
                      <Td><SeverityBadge severity={a.severity} /></Td>
                      <Td><StatusBadge status={a.status} /></Td>
                      <Td className="tabular-nums">{a.event_count}</Td>
                      <Td className="whitespace-nowrap font-mono text-xs">{formatShort(a.last_seen)}</Td>
                      <Td>{a.assigned_to?.username ?? <span className="text-ink-faint">Unassigned</span>}</Td>
                      <Td className="font-mono text-xs">{a.incident_reference ?? "-"}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
              <Pagination page={alerts.data.page} pages={alerts.data.pages} total={alerts.data.total} onPage={(p) => update({ page: String(p) }, false)} />
            </>
          )}
      </Card>
    </div>
  );
}
