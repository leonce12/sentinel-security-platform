import { ArrowLeft, CheckCheck, RefreshCw, Siren, UserPlus } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { AiPanel } from "../components/AiPanel";
import {
  Button, Card, ErrorState, Field, InlineError, KeyValue, Modal, PageHeader, Pagination, RiskScore, Select, SeverityBadge,
  Spinner, StatusBadge, SyntheticTag, Table, Td, TextArea, Th,
} from "../components/ui";
import { useAuth } from "../contexts/AuthContext";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { AlertDetail, Incident, Page, UserRef } from "../types/api";
import { formatDateTime, formatShort, titleCase } from "../utils/format";

const NEXT_STATUS: Record<string, string[]> = {
  new: ["investigating", "resolved", "false_positive"],
  acknowledged: ["investigating", "resolved", "false_positive"],
  investigating: ["resolved", "false_positive"],
  resolved: ["investigating"],
  false_positive: ["investigating"],
};

export default function AlertDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { can } = useAuth();
  const [eventsPage, setEventsPage] = useState(1);
  const alert = useApi(() => api.get<AlertDetail>(`/alerts/${id}`, { events_page: eventsPage, events_page_size: 25 }), [id, eventsPage]);
  const assignees = useApi(() => api.get<UserRef[]>("/users/assignable"), []);
  const action = useAction();
  const [note, setNote] = useState("");
  const [statusModal, setStatusModal] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [convertOpen, setConvertOpen] = useState(false);
  const [targetIncident, setTargetIncident] = useState("");
  const openIncidents = useApi(
    () => (convertOpen ? api.get<Page<Incident>>("/incidents", { status: ["open", "investigating", "contained"], page_size: 100 }) : Promise.resolve(null)),
    [convertOpen],
  );

  if (alert.error) return <ErrorState message={alert.error} onRetry={alert.reload} />;
  if (!alert.data) return <Spinner />;
  const a = alert.data;
  const manage = can("alerts:manage");
  const triage = can("alerts:triage");

  async function act(fn: () => Promise<unknown>) {
    const ok = await action.run(fn);
    if (ok !== undefined) alert.reload();
    return ok;
  }

  async function submitStatus() {
    const ok = await act(() => api.post(`/alerts/${a.id}/status`, { status: statusModal, reason }));
    if (ok !== undefined) { setStatusModal(null); setReason(""); }
  }

  async function convert() {
    const incident = await action.run(() => api.post<Incident>(`/alerts/${a.id}/incident`, targetIncident ? { incident_id: Number(targetIncident) } : {}));
    if (incident) navigate(`/incidents/${incident.id}`);
  }

  const evidence = Object.entries(a.evidence_summary).filter(([, v]) => v !== null && v !== "" && !(Array.isArray(v) && !v.length));
  const subtotal = a.score_breakdown.filter((f) => f.factor !== "Detection confidence").reduce((s, f) => s + f.points, 0);

  return (
    <div>
      <Button variant="ghost" onClick={() => navigate(-1)} icon={<ArrowLeft className="h-4 w-4" />} className="mb-2 -ml-2">Back</Button>
      <PageHeader title={a.title} description={a.description}
        actions={<>{a.is_synthetic && <SyntheticTag />}<StatusBadge status={a.status} /><SeverityBadge severity={a.severity} /><RiskScore score={a.risk_score} /></>} />
      <InlineError message={action.error} />

      {(triage || manage) && (
        <div className="mb-4 flex flex-wrap items-center gap-2 rounded-lg border border-line bg-surface p-3">
          {triage && a.status === "new" && <Button busy={action.busy} onClick={() => act(() => api.post(`/alerts/${a.id}/acknowledge`))} icon={<CheckCheck className="h-4 w-4" />}>Acknowledge</Button>}
          {manage && NEXT_STATUS[a.status]?.map((s) => (
            <Button key={s} onClick={() => { setStatusModal(s); setReason(""); }}>
              {s === "false_positive" ? "Mark false positive" : s === "investigating" && ["resolved", "false_positive"].includes(a.status) ? "Reopen" : `Set ${titleCase(s).toLowerCase()}`}
            </Button>
          ))}
          {manage && (
            <label className="flex items-center gap-2 text-sm"><UserPlus className="h-4 w-4 text-ink-muted" aria-hidden />
              <Select aria-label="Assign alert" value={a.assigned_to?.id ?? ""} className="w-44"
                onChange={(e) => act(() => api.post(`/alerts/${a.id}/assign`, { user_id: e.target.value ? Number(e.target.value) : null }))}>
                <option value="">Unassigned</option>{assignees.data?.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
              </Select>
            </label>
          )}
          {manage && <Button variant="ghost" onClick={() => act(() => api.post(`/alerts/${a.id}/rescore`))} icon={<RefreshCw className="h-4 w-4" />}>Recalculate score</Button>}
          <div className="flex-1" />
          {a.incident_id ? <Link to={`/incidents/${a.incident_id}`} className="text-sm text-accent">Part of {a.incident_reference}</Link> :
            can("incidents:manage") && <Button variant="primary" onClick={() => setConvertOpen(true)} icon={<Siren className="h-4 w-4" />}>Convert to incident</Button>}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Card title="Overview">
            <KeyValue items={[
              ["Rule", <Link to="/rules" className="text-accent">{a.rule_id} · {a.rule_name}</Link>], ["Group", <span className="font-mono text-xs">{a.group_key}</span>],
              ["First seen", formatDateTime(a.first_seen)], ["Last seen", formatDateTime(a.last_seen)],
              ["Evidence events", a.event_count], ["Assigned to", a.assigned_to?.username ?? "Unassigned"],
              ["Created", formatDateTime(a.created_at)], ["Acknowledged", formatDateTime(a.acknowledged_at)],
            ]} />
          </Card>
          <Card title="Why this score" actions={<span className="text-xs text-ink-faint">Deterministic and documented. No AI involved.</span>} bodyClassName="p-0">
            <Table>
              <thead><tr><Th>Factor</Th><Th className="text-right">Points</Th><Th>Explanation</Th></tr></thead>
              <tbody>
                {a.score_breakdown.map((f, i) => (
                  <tr key={i}><Td className="whitespace-nowrap font-medium">{f.factor}</Td>
                    <Td className={`text-right font-mono tabular-nums ${f.points < 0 ? "text-ink-muted" : ""}`}>{f.points > 0 ? `+${f.points}` : f.points}</Td>
                    <Td className="text-ink-muted">{f.explanation}</Td></tr>
                ))}
                <tr><Td className="font-semibold">Final score</Td><Td className="text-right font-mono font-semibold">{a.risk_score}</Td>
                  <Td className="text-ink-muted">Subtotal {subtotal}, adjusted by rule confidence, capped at 100</Td></tr>
              </tbody>
            </Table>
          </Card>
          <Card title={`Evidence (${a.events_total} stored events)`} bodyClassName="p-3">
            {evidence.length > 0 && (
              <div className="mb-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
                {evidence.map(([k, v]) => (
                  <div key={k} className="rounded-md border border-line bg-canvas px-3 py-2 text-xs">
                    <div className="uppercase tracking-wide text-ink-faint">{titleCase(k)}</div>
                    <div className="mt-0.5 break-words font-mono text-ink-muted">{typeof v === "object" ? JSON.stringify(v) : String(v)}</div>
                  </div>
                ))}
              </div>
            )}
            <Table>
              <thead><tr><Th>Time</Th><Th>Event</Th><Th>User</Th><Th>Source IP</Th><Th>Outcome</Th><Th>Resource</Th></tr></thead>
              <tbody>
                {a.events.map((e) => (
                  <tr key={e.id} className="cursor-pointer hover:bg-surface-2/60" onClick={() => navigate(`/events/${e.id}`)}>
                    <Td className="whitespace-nowrap font-mono text-xs">{formatShort(e.timestamp)}</Td>
                    <Td>{e.event_type}</Td><Td>{e.username ?? "-"}</Td><Td className="font-mono text-xs">{e.source_ip ?? "-"}</Td>
                    <Td>{e.outcome ?? "-"}</Td><Td className="max-w-[220px] truncate font-mono text-xs">{e.resource ?? "-"}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Pagination page={eventsPage} pages={Math.max(1, Math.ceil(a.events_total / 25))} total={a.events_total} onPage={setEventsPage} />
          </Card>
          {can("ai:use") && <AiPanel path={`/ai/explain/alert/${a.id}`} title="AI security analyst" />}
        </div>

        <div className="space-y-4">
          <Card title="Investigation guidance">
            <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-ink-faint">Recommended steps</h3>
            <ol className="mb-3 list-decimal space-y-1 pl-5 text-sm text-ink-muted">{a.rule.investigation_steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
            <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-ink-faint">False-positive considerations</h3>
            <p className="text-sm text-ink-muted">{a.rule.false_positive_notes}</p>
          </Card>
          <Card title="History and notes">
            {triage && (
              <div className="mb-4 space-y-2">
                <TextArea aria-label="Add a note" placeholder="Add an investigation note" value={note} onChange={(e) => setNote(e.target.value)} />
                <Button disabled={!note.trim()} busy={action.busy}
                  onClick={async () => { const ok = await act(() => api.post(`/alerts/${a.id}/notes`, { body: note })); if (ok) setNote(""); }}>Add note</Button>
              </div>
            )}
            <ol className="space-y-3">
              {[...a.activity].reverse().map((item) => (
                <li key={item.id} className="border-l-2 border-line-strong pl-3 text-sm">
                  <div className="flex flex-wrap items-center gap-x-2 text-xs text-ink-faint">
                    <span className="font-medium text-ink-muted">{titleCase(item.activity_type)}</span>
                    {item.from_value || item.to_value ? <span>{item.from_value ? `${item.from_value} → ` : ""}{item.to_value ?? "none"}</span> : null}
                    <span>· {item.actor?.username ?? "system"} · {formatShort(item.created_at)}</span>
                  </div>
                  {item.note && <p className="mt-0.5 whitespace-pre-wrap text-ink">{item.note}</p>}
                </li>
              ))}
            </ol>
          </Card>
        </div>
      </div>

      <Modal title={statusModal === "false_positive" ? "Mark as false positive" : `Change status to ${titleCase(statusModal ?? "")}`}
        open={!!statusModal} onClose={() => setStatusModal(null)}
        footer={<><Button onClick={() => setStatusModal(null)}>Cancel</Button><Button variant="primary" busy={action.busy} onClick={submitStatus}>Confirm</Button></>}>
        <Field label="Reason and supporting evidence" hint={statusModal === "false_positive" || statusModal === "resolved" ? "Required (at least 10 characters). Recorded in the alert history and the audit log." : "Recorded in the alert history."}>
          <TextArea value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Confirmed with the user: change ticket CHG-1043 approved this." />
        </Field>
        {statusModal === "false_positive" && (
          <p className="text-xs text-ink-faint">Marking a false positive does not suppress future alerts. New evidence for the same activity reopens the alert.</p>
        )}
        <InlineError message={action.error} />
      </Modal>

      <Modal title="Convert alert to incident" open={convertOpen} onClose={() => setConvertOpen(false)}
        footer={<><Button onClick={() => setConvertOpen(false)}>Cancel</Button><Button variant="primary" busy={action.busy} onClick={convert}>Convert</Button></>}>
        <Field label="Incident" hint="Create a new incident, or add this alert to an open one.">
          <Select value={targetIncident} onChange={(e) => setTargetIncident(e.target.value)}>
            <option value="">Create a new incident</option>
            {openIncidents.data?.items.map((i) => <option key={i.id} value={i.id}>{i.reference} · {i.title}</option>)}
          </Select>
        </Field>
        <InlineError message={action.error} />
      </Modal>
    </div>
  );
}
