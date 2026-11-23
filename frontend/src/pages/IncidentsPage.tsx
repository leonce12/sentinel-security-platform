import { Download, Plus, RefreshCw, Search } from "lucide-react";
import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import {
  Button, Card, EmptyState, ErrorState, Field, InlineError, Input, Modal, PageHeader, Pagination, RiskScore, Select,
  SeverityBadge, Spinner, StatusBadge, SyntheticTag, Table, Td, TextArea, Th,
} from "../components/ui";
import { useAuth } from "../contexts/AuthContext";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { Incident, Page, Severity } from "../types/api";
import { SEVERITIES, SEVERITY_LABEL, formatShort, titleCase } from "../utils/format";

const STATUSES = ["open", "investigating", "contained", "resolved", "closed"];

function CreateIncidentModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");
  const action = useAction();
  async function submit() {
    if (title.trim().length < 5) return action.setError("Title must be at least 5 characters.");
    const incident = await action.run(() => api.post<Incident>("/incidents", { title, description, severity }));
    if (incident) navigate(`/incidents/${incident.id}`);
  }
  return (
    <Modal title="Create incident" open={open} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" busy={action.busy} onClick={submit}>Create</Button></>}>
      <Field label="Title"><Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Suspicious email reported by finance" /></Field>
      <Field label="Severity"><Select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
        {SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}</Select></Field>
      <Field label="Description"><TextArea value={description} onChange={(e) => setDescription(e.target.value)} /></Field>
      <InlineError message={action.error} />
    </Modal>
  );
}

export default function IncidentsPage() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const [createOpen, setCreateOpen] = useState(false);
  const exportAction = useAction();
  const key = params.toString();
  const status = params.getAll("status");
  const page = Number(params.get("page") ?? 1);
  const sort = params.get("sort") ?? "risk_score";
  const order = (params.get("order") as "asc" | "desc") ?? "desc";
  const query = { q: params.get("q") ?? undefined, status, severity: params.getAll("severity") };
  const incidents = useApi(() => api.get<Page<Incident>>("/incidents", { ...query, sort, order, page }), [key]);

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
      <PageHeader title="Incidents" description="Investigations that group related alerts. Incidents are never deleted; they are resolved and closed with documented findings."
        actions={can("incidents:manage") && <Button variant="primary" onClick={() => setCreateOpen(true)} icon={<Plus className="h-4 w-4" />}>New incident</Button>} />
      <Card bodyClassName="p-3">
        <div key={key} className="mb-3 flex flex-wrap gap-2">
          <div className="relative min-w-[240px] flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-ink-faint" aria-hidden />
            <Input aria-label="Search incidents" placeholder="Search reference, title, description" className="pl-8" defaultValue={query.q ?? ""}
              onKeyDown={(e) => e.key === "Enter" && update({ q: (e.target as HTMLInputElement).value })}
              onBlur={(e) => e.target.value !== (query.q ?? "") && update({ q: e.target.value })} />
          </div>
          <Select aria-label="Status" className="w-56" value={status.length > 1 ? "active" : status[0] ?? ""}
            onChange={(e) => update({ status: e.target.value === "active" ? ["open", "investigating", "contained"] : e.target.value ? [e.target.value] : undefined })}>
            <option value="">All statuses</option><option value="active">Active (open, investigating, contained)</option>
            {STATUSES.map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
          </Select>
          <Select aria-label="Severity" className="w-40" value={params.get("severity") ?? ""} onChange={(e) => update({ severity: e.target.value })}>
            <option value="">All severities</option>{SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
          </Select>
          <Button variant="ghost" onClick={incidents.reload} icon={<RefreshCw className="h-4 w-4" />}>Refresh</Button>
          {can("events:export") && <Button busy={exportAction.busy} icon={<Download className="h-4 w-4" />}
            onClick={() => exportAction.run(() => api.download("/incidents/export", { ...query, format: "csv" }, "sentinel-incidents.csv"))}>Export CSV</Button>}
        </div>
        <InlineError message={exportAction.error} />
        {incidents.error ? <ErrorState message={incidents.error} onRetry={incidents.reload} /> : !incidents.data ? <Spinner /> :
          incidents.data.items.length === 0 ? <EmptyState title="No incidents" description="Incidents are created automatically for high-risk alerts, or by converting an alert." /> : (
            <>
              <Table>
                <thead><tr><Th>Reference</Th><Th>Title</Th>
                  <Th onClick={() => toggleSort("risk_score")} active={sort === "risk_score"} order={order}>Risk</Th>
                  <Th onClick={() => toggleSort("severity")} active={sort === "severity"} order={order}>Severity</Th>
                  <Th onClick={() => toggleSort("status")} active={sort === "status"} order={order}>Status</Th>
                  <Th>Alerts</Th><Th>Assignee</Th>
                  <Th onClick={() => toggleSort("detected_at")} active={sort === "detected_at"} order={order}>Detected</Th></tr></thead>
                <tbody>
                  {incidents.data.items.map((i) => (
                    <tr key={i.id} className="cursor-pointer hover:bg-surface-2/60" onClick={() => navigate(`/incidents/${i.id}`)}>
                      <Td className="whitespace-nowrap font-mono text-xs">{i.reference}</Td>
                      <Td><div className="font-medium">{i.title}</div>
                        <div className="flex gap-2 text-xs text-ink-faint">{i.auto_created ? "Created by detection" : "Created by analyst"}{i.is_synthetic && <SyntheticTag />}</div></Td>
                      <Td><RiskScore score={i.risk_score} /></Td><Td><SeverityBadge severity={i.severity} /></Td><Td><StatusBadge status={i.status} /></Td>
                      <Td className="tabular-nums">{i.alert_count}</Td>
                      <Td>{i.assigned_to?.username ?? <span className="text-ink-faint">Unassigned</span>}</Td>
                      <Td className="whitespace-nowrap font-mono text-xs">{formatShort(i.detected_at)}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
              <Pagination page={incidents.data.page} pages={incidents.data.pages} total={incidents.data.total} onPage={(p) => update({ page: String(p) }, false)} />
            </>
          )}
      </Card>
      <CreateIncidentModal open={createOpen} onClose={() => setCreateOpen(false)} />
    </div>
  );
}
