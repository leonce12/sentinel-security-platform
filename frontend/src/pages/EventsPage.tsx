import { Download, FilePlus2, RefreshCw, Search, Upload } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { IngestionSummary } from "../components/IngestionSummary";
import {
  Button, Card, EmptyState, ErrorState, Field, InlineError, Input, Modal, PageHeader, Pagination, RiskScore, Select,
  SeverityBadge, Spinner, StatusBadge, SyntheticTag, Table, Tabs, Td, TextArea, Th,
} from "../components/ui";
import { useAuth } from "../contexts/AuthContext";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { IngestionJob, Page, SecurityEvent } from "../types/api";
import { SEVERITIES, SEVERITY_LABEL, formatShort, fromInputValue, titleCase, toInputValue } from "../utils/format";

const FILTER_KEYS = ["q", "severity", "category", "source_system", "event_type", "username", "ip", "start", "end", "min_risk", "job_id", "synthetic", "flagged"];

function UploadModal({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [synthetic, setSynthetic] = useState(false);
  const [detect, setDetect] = useState(true);
  const [job, setJob] = useState<IngestionJob | null>(null);
  const action = useAction();

  async function submit() {
    if (!file) return action.setError("Choose a CSV or JSON file first.");
    const form = new FormData();
    form.append("file", file);
    form.append("mark_synthetic", String(synthetic));
    form.append("run_detection", String(detect));
    const result = await action.run(() => api.upload<IngestionJob>("/ingest/upload", form));
    if (result) {
      setJob(result);
      onDone();
    }
  }

  function close() {
    setJob(null);
    setFile(null);
    action.setError(null);
    onClose();
  }

  return (
    <Modal title="Upload security logs" open={open} onClose={close} wide
      footer={job ? <Button variant="primary" onClick={close}>Done</Button> : (
        <><Button onClick={close}>Cancel</Button><Button variant="primary" onClick={submit} busy={action.busy} icon={<Upload className="h-4 w-4" />}>Upload and process</Button></>
      )}>
      {job ? <IngestionSummary job={job} /> : (
        <>
          <p className="text-sm text-ink-muted">
            Upload a CSV file, a JSON array, an object with an <code className="font-mono">events</code> array, or NDJSON. Required fields are
            timestamp and event type. Files are parsed as data only; nothing in them is executed.
          </p>
          <Field label="Log file" hint="Accepted: .csv, .json, .jsonl, .ndjson. Size limit is set by the server (10 MB by default).">
            <input type="file" accept=".csv,.json,.jsonl,.ndjson" aria-label="Log file"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="block w-full text-sm text-ink-muted file:mr-3 file:rounded-md file:border file:border-line-strong file:bg-surface-2 file:px-3 file:py-1.5 file:text-ink" />
          </Field>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={synthetic} onChange={(e) => setSynthetic(e.target.checked)} /> Mark these records as synthetic demonstration data
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={detect} onChange={(e) => setDetect(e.target.checked)} /> Run the detection engine after ingestion
          </label>
          <InlineError message={action.error} />
        </>
      )}
    </Modal>
  );
}

const EMPTY_EVENT = { timestamp: new Date().toISOString().slice(0, 19) + "Z", source_system: "", event_category: "authentication",
  event_type: "", severity: "informational", username: "", source_ip: "", destination_ip: "", action: "", outcome: "", resource: "", description: "" };

function ManualEventModal({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [form, setForm] = useState({ ...EMPTY_EVENT });
  const [job, setJob] = useState<IngestionJob | null>(null);
  const action = useAction();
  const set = (k: keyof typeof EMPTY_EVENT) => (e: { target: { value: string } }) => setForm((f) => ({ ...f, [k]: e.target.value }));

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!form.source_system.trim() || !form.event_type.trim()) return action.setError("Source system and event type are required.");
    const body = Object.fromEntries(Object.entries(form).filter(([, v]) => v !== ""));
    const result = await action.run(() => api.post<IngestionJob>("/events", body));
    if (result) {
      setJob(result);
      onDone();
    }
  }

  function close() {
    setJob(null);
    setForm({ ...EMPTY_EVENT, timestamp: new Date().toISOString().slice(0, 19) + "Z" });
    action.setError(null);
    onClose();
  }

  return (
    <Modal title="Submit a single event" open={open} onClose={close} wide
      footer={job ? <Button variant="primary" onClick={close}>Done</Button> : (
        <><Button onClick={close}>Cancel</Button><Button variant="primary" type="submit" form="manual-event" busy={action.busy}>Submit event</Button></>
      )}>
      {job ? <IngestionSummary job={job} /> : (
        <form id="manual-event" onSubmit={submit} className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Timestamp (ISO 8601)"><Input value={form.timestamp} onChange={set("timestamp")} required /></Field>
          <Field label="Source system"><Input value={form.source_system} onChange={set("source_system")} placeholder="vpn-gw-01.corp.example" required /></Field>
          <Field label="Category">
            <Select value={form.event_category} onChange={set("event_category")}>
              {["authentication", "access", "privilege", "configuration", "network", "system", "endpoint", "data", "other"].map((c) =>
                <option key={c} value={c}>{titleCase(c)}</option>)}
            </Select>
          </Field>
          <Field label="Event type"><Input value={form.event_type} onChange={set("event_type")} placeholder="login_failure" required /></Field>
          <Field label="Severity">
            <Select value={form.severity} onChange={set("severity")}>{SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}</Select>
          </Field>
          <Field label="Outcome">
            <Select value={form.outcome} onChange={set("outcome")}><option value="">Not recorded</option><option value="success">Success</option><option value="failure">Failure</option></Select>
          </Field>
          <Field label="Username"><Input value={form.username} onChange={set("username")} /></Field>
          <Field label="Action"><Input value={form.action} onChange={set("action")} placeholder="login" /></Field>
          <Field label="Source IP"><Input value={form.source_ip} onChange={set("source_ip")} placeholder="203.0.113.10" /></Field>
          <Field label="Destination IP"><Input value={form.destination_ip} onChange={set("destination_ip")} /></Field>
          <div className="sm:col-span-2"><Field label="Resource"><Input value={form.resource} onChange={set("resource")} placeholder="/admin/users" /></Field></div>
          <div className="sm:col-span-2"><Field label="Description"><TextArea value={form.description} onChange={set("description")} /></Field></div>
          <div className="sm:col-span-2"><InlineError message={action.error} /></div>
        </form>
      )}
    </Modal>
  );
}

function JobsTable() {
  const [page, setPage] = useState(1);
  const navigate = useNavigate();
  const jobs = useApi(() => api.get<Page<IngestionJob>>("/ingest/jobs", { page }), [page]);
  const [selected, setSelected] = useState<IngestionJob | null>(null);
  if (jobs.error) return <ErrorState message={jobs.error} onRetry={jobs.reload} />;
  if (!jobs.data) return <Spinner />;
  if (!jobs.data.items.length) return <EmptyState title="No ingestion jobs yet" description="Upload a log file to create the first job." />;
  return (
    <>
      <Table>
        <thead><tr><Th>Job</Th><Th>Created</Th><Th>Source</Th><Th>Status</Th><Th className="text-right">Received</Th><Th className="text-right">Stored</Th><Th className="text-right">Rejected</Th><Th className="text-right">Duplicates</Th><Th /></tr></thead>
        <tbody>
          {jobs.data.items.map((j) => (
            <tr key={j.id} className="hover:bg-surface-2/50">
              <Td className="font-mono text-xs">#{j.id}</Td>
              <Td className="whitespace-nowrap text-xs">{formatShort(j.created_at)}</Td>
              <Td>{j.filename ?? titleCase(j.source_type)} {j.is_synthetic && <SyntheticTag />}</Td>
              <Td><StatusBadge status={j.status} /></Td>
              <Td className="text-right tabular-nums">{j.total_records}</Td>
              <Td className="text-right tabular-nums">{j.processed_records}</Td>
              <Td className="text-right tabular-nums">{j.rejected_records}</Td>
              <Td className="text-right tabular-nums">{j.duplicate_records}</Td>
              <Td className="whitespace-nowrap text-right">
                <Button variant="ghost" onClick={() => setSelected(j)}>Summary</Button>
                <Button variant="ghost" onClick={() => navigate(`/events?job_id=${j.id}`)}>Events</Button>
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
      <Pagination page={jobs.data.page} pages={jobs.data.pages} total={jobs.data.total} onPage={setPage} />
      <Modal title={`Ingestion job #${selected?.id ?? ""}`} open={!!selected} onClose={() => setSelected(null)} wide>
        {selected && <IngestionSummary job={selected} />}
      </Modal>
    </>
  );
}

export default function EventsPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [tab, setTab] = useState<"events" | "jobs">("events");
  const [uploadOpen, setUploadOpen] = useState(false);
  const [manualOpen, setManualOpen] = useState(false);
  const exportAction = useAction();

  const filters: Record<string, string> = {};
  FILTER_KEYS.forEach((k) => { const v = params.get(k); if (v) filters[k] = v; });
  const page = Number(params.get("page") ?? 1);
  const sort = params.get("sort") ?? "timestamp";
  const order = (params.get("order") as "asc" | "desc") ?? "desc";
  const key = params.toString();

  const facets = useApi(() => api.get<{ source_systems: string[]; event_types: string[]; categories: string[] }>("/events/facets"), []);
  const events = useApi(() => api.get<Page<SecurityEvent>>("/events", { ...filters, sort, order, page, page_size: 25 }), [key]);

  function update(changes: Record<string, string | undefined>, resetPage = true) {
    const next = new URLSearchParams(params);
    Object.entries(changes).forEach(([k, v]) => (v ? next.set(k, v) : next.delete(k)));
    if (resetPage) next.delete("page");
    setParams(next, { replace: true });
  }

  function toggleSort(field: string) {
    update({ sort: field, order: sort === field && order === "desc" ? "asc" : "desc" }, false);
  }

  async function exportData(format: "csv" | "json") {
    await exportAction.run(() => api.download("/events/export", { ...filters, format }, `sentinel-events.${format}`));
  }

  const refreshAll = () => { events.reload(); facets.reload(); };

  return (
    <div>
      <PageHeader title="Security events" description="Every normalized event stored by Sentinel. Filters apply to the table and to exports."
        actions={<>
          {can("events:ingest") && <Button onClick={() => setManualOpen(true)} icon={<FilePlus2 className="h-4 w-4" />}>Submit event</Button>}
          {can("events:ingest") && <Button variant="primary" onClick={() => setUploadOpen(true)} icon={<Upload className="h-4 w-4" />}>Upload logs</Button>}
        </>} />
      <Tabs tabs={[{ id: "events", label: "Events" }, { id: "jobs", label: "Ingestion jobs" }]} value={tab} onChange={setTab} />

      {tab === "jobs" ? <Card bodyClassName="p-3"><JobsTable key={String(uploadOpen) + String(manualOpen)} /></Card> : (
        <Card bodyClassName="p-3">
          <div key={key} className="mb-3 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-6">
            <div className="relative lg:col-span-2">
              <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-ink-faint" aria-hidden />
              <Input aria-label="Search" placeholder="Search text, ID, user, host, IP" className="pl-8" defaultValue={filters.q ?? ""}
                onKeyDown={(e) => e.key === "Enter" && update({ q: (e.target as HTMLInputElement).value })}
                onBlur={(e) => e.target.value !== (filters.q ?? "") && update({ q: e.target.value })} />
            </div>
            <Select aria-label="Severity" value={filters.severity ?? ""} onChange={(e) => update({ severity: e.target.value })}>
              <option value="">All severities</option>{SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
            </Select>
            <Select aria-label="Category" value={filters.category ?? ""} onChange={(e) => update({ category: e.target.value })}>
              <option value="">All categories</option>{facets.data?.categories.map((c) => <option key={c} value={c}>{titleCase(c)}</option>)}
            </Select>
            <Select aria-label="Source" value={filters.source_system ?? ""} onChange={(e) => update({ source_system: e.target.value })}>
              <option value="">All sources</option>{facets.data?.source_systems.map((c) => <option key={c} value={c}>{c}</option>)}
            </Select>
            <Select aria-label="Event type" value={filters.event_type ?? ""} onChange={(e) => update({ event_type: e.target.value })}>
              <option value="">All event types</option>{facets.data?.event_types.map((c) => <option key={c} value={c}>{c}</option>)}
            </Select>
            <Input aria-label="From" type="datetime-local" value={toInputValue(filters.start)} onChange={(e) => update({ start: fromInputValue(e.target.value) })} title="From (UTC)" />
            <Input aria-label="To" type="datetime-local" value={toInputValue(filters.end)} onChange={(e) => update({ end: fromInputValue(e.target.value) })} title="To (UTC)" />
            <Input aria-label="Username" placeholder="Username" defaultValue={filters.username ?? ""} onBlur={(e) => update({ username: e.target.value })} />
            <Input aria-label="IP address" placeholder="IP address" defaultValue={filters.ip ?? ""} onBlur={(e) => update({ ip: e.target.value })} />
            <Select aria-label="Minimum risk" value={filters.min_risk ?? ""} onChange={(e) => update({ min_risk: e.target.value })}>
              <option value="">Any risk</option><option value="20">Risk 20+</option><option value="40">Risk 40+</option><option value="60">Risk 60+</option><option value="80">Risk 80+</option>
            </Select>
            <Select aria-label="Flagged" value={filters.flagged ?? ""} onChange={(e) => update({ flagged: e.target.value })}>
              <option value="">All events</option><option value="true">Alert evidence only</option>
            </Select>
          </div>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            {filters.job_id && <span className="rounded bg-surface-2 px-2 py-1 text-xs">Ingestion job #{filters.job_id}</span>}
            {Object.keys(filters).length > 0 && <Button variant="ghost" onClick={() => setParams({}, { replace: true })}>Clear filters</Button>}
            <div className="flex-1" />
            <Button variant="ghost" onClick={refreshAll} icon={<RefreshCw className="h-4 w-4" />}>Refresh</Button>
            {can("events:export") && <>
              <Button onClick={() => exportData("csv")} busy={exportAction.busy} icon={<Download className="h-4 w-4" />}>Export CSV</Button>
              <Button onClick={() => exportData("json")} busy={exportAction.busy} icon={<Download className="h-4 w-4" />}>Export JSON</Button>
            </>}
          </div>
          <InlineError message={exportAction.error} />
          {events.error ? <ErrorState message={events.error} onRetry={events.reload} /> : !events.data ? <Spinner /> :
            events.data.items.length === 0 ? (
              <EmptyState title="No events found" description={Object.keys(filters).length ? "No stored events match these filters." : "Upload a CSV or JSON log file to get started."}
                action={can("events:ingest") && !Object.keys(filters).length ? <Button variant="primary" onClick={() => setUploadOpen(true)}>Upload logs</Button> : undefined} />
            ) : (
              <>
                <Table>
                  <thead>
                    <tr>
                      <Th onClick={() => toggleSort("timestamp")} active={sort === "timestamp"} order={order}>Timestamp</Th>
                      <Th onClick={() => toggleSort("event_type")} active={sort === "event_type"} order={order}>Event</Th>
                      <Th onClick={() => toggleSort("source_system")} active={sort === "source_system"} order={order}>Source</Th>
                      <Th onClick={() => toggleSort("username")} active={sort === "username"} order={order}>User</Th>
                      <Th>Source IP</Th>
                      <Th>Outcome</Th>
                      <Th onClick={() => toggleSort("severity")} active={sort === "severity"} order={order}>Severity</Th>
                      <Th onClick={() => toggleSort("risk_score")} active={sort === "risk_score"} order={order}>Risk</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.data.items.map((e) => (
                      <tr key={e.id} className="cursor-pointer hover:bg-surface-2/60" onClick={() => navigate(`/events/${e.id}`)}>
                        <Td className="whitespace-nowrap font-mono text-xs text-ink-muted">{formatShort(e.timestamp)}</Td>
                        <Td><div className="font-medium">{e.event_type}</div><div className="line-clamp-1 max-w-[320px] text-xs text-ink-faint">{e.description}</div></Td>
                        <Td className="max-w-[180px] truncate">{e.source_system}</Td>
                        <Td>{e.username ?? "-"}</Td>
                        <Td className="font-mono text-xs">{e.source_ip ?? "-"}</Td>
                        <Td>{e.outcome ? titleCase(e.outcome) : "-"}</Td>
                        <Td><SeverityBadge severity={e.severity} /></Td>
                        <Td><RiskScore score={e.risk_score} /></Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
                <Pagination page={events.data.page} pages={events.data.pages} total={events.data.total} onPage={(p) => update({ page: String(p) }, false)} />
              </>
            )}
        </Card>
      )}
      <UploadModal open={uploadOpen} onClose={() => setUploadOpen(false)} onDone={refreshAll} />
      <ManualEventModal open={manualOpen} onClose={() => setManualOpen(false)} onDone={refreshAll} />
    </div>
  );
}
