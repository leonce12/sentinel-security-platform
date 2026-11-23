import { ArrowLeft, FileDown, UserPlus } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { AiPanel } from "../components/AiPanel";
import {
  Button, Card, EmptyState, ErrorState, Field, InlineError, KeyValue, Modal, PageHeader, RiskScore, Select, SeverityBadge,
  Spinner, StatusBadge, SyntheticTag, TextArea,
} from "../components/ui";
import { useAuth } from "../contexts/AuthContext";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { IncidentDetail, Report, UserRef } from "../types/api";
import { formatDateTime, formatShort, titleCase } from "../utils/format";

const TRANSITIONS: Record<string, string[]> = {
  open: ["investigating", "contained", "resolved"],
  investigating: ["contained", "resolved", "open"],
  contained: ["investigating", "resolved"],
  resolved: ["closed", "investigating"],
  closed: ["investigating"],
};

export default function IncidentDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { can } = useAuth();
  const incident = useApi(() => api.get<IncidentDetail>(`/incidents/${id}`), [id]);
  const assignees = useApi(() => api.get<UserRef[]>("/users/assignable"), []);
  const action = useAction();
  const [note, setNote] = useState("");
  const [target, setTarget] = useState<string | null>(null);
  const [statusNote, setStatusNote] = useState("");
  const [resolution, setResolution] = useState("");

  if (incident.error) return <ErrorState message={incident.error} onRetry={incident.reload} />;
  if (!incident.data) return <Spinner />;
  const inc = incident.data;
  const manage = can("incidents:manage");

  async function act(fn: () => Promise<unknown>) {
    const result = await action.run(fn);
    if (result !== undefined) incident.reload();
    return result;
  }

  async function submitStatus() {
    const ok = await act(() => api.post(`/incidents/${inc.id}/status`, { status: target, note: statusNote, resolution: resolution || undefined }));
    if (ok) setTarget(null);
  }

  async function generateReport() {
    const report = await action.run(() => api.post<Report>("/reports", { report_type: "incident", incident_id: inc.id }));
    if (report) await action.run(() => api.download(`/reports/${report.id}/download`, undefined, `incident-${inc.reference}.pdf`));
  }

  const entities = inc.affected_entities ?? {};
  const needsResolution = target === "resolved" || target === "closed";

  return (
    <div>
      <Button variant="ghost" onClick={() => navigate(-1)} icon={<ArrowLeft className="h-4 w-4" />} className="mb-2 -ml-2">Back</Button>
      <PageHeader title={`${inc.reference} · ${inc.title}`}
        actions={<>{inc.is_synthetic && <SyntheticTag />}<StatusBadge status={inc.status} /><SeverityBadge severity={inc.severity} /><RiskScore score={inc.risk_score} /></>} />
      <InlineError message={action.error} />

      <div className="mb-4 flex flex-wrap items-center gap-2 rounded-lg border border-line bg-surface p-3">
        {manage && TRANSITIONS[inc.status].map((s) => (
          <Button key={s} onClick={() => { setTarget(s); setStatusNote(""); setResolution(inc.resolution ?? ""); }}>
            {inc.status === "closed" || (s === "investigating" && inc.status === "resolved") ? "Reopen" : `Mark ${titleCase(s).toLowerCase()}`}
          </Button>
        ))}
        {manage && (
          <label className="flex items-center gap-2 text-sm"><UserPlus className="h-4 w-4 text-ink-muted" aria-hidden />
            <Select aria-label="Assign incident" value={inc.assigned_to?.id ?? ""} className="w-48"
              onChange={(e) => act(() => api.post(`/incidents/${inc.id}/assign`, { user_id: e.target.value ? Number(e.target.value) : null }))}>
              <option value="">Unassigned</option>{assignees.data?.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
            </Select>
          </label>
        )}
        <div className="flex-1" />
        {can("reports:generate") && <Button onClick={generateReport} busy={action.busy} icon={<FileDown className="h-4 w-4" />}>Incident report (PDF)</Button>}
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Card title="Overview">
            <p className="mb-4 whitespace-pre-wrap text-sm text-ink-muted">{inc.description || "No description."}</p>
            <KeyValue items={[
              ["Detected", formatDateTime(inc.detected_at)], ["Assigned analyst", inc.assigned_to?.username ?? "Unassigned"],
              ["Origin", inc.auto_created ? "Created automatically by detection" : "Created by an analyst"], ["Closed", formatDateTime(inc.closed_at)],
              ["Affected accounts", entities.accounts?.join(", ") || "-"], ["Affected systems", entities.systems?.join(", ") || "-"],
              ["Source IPs", entities.ips?.join(", ") || "-"], ["Resolution", inc.resolution || "-"],
            ]} />
          </Card>
          <Card title={`Associated alerts (${inc.alerts.length})`} bodyClassName="p-0">
            {inc.alerts.length === 0 ? <EmptyState title="No alerts linked" description="Convert an alert from its detail page to add it here." /> : (
              <ul className="divide-y divide-line">
                {inc.alerts.map((a) => (
                  <li key={a.id}><Link to={`/alerts/${a.id}`} className="flex items-center gap-3 px-4 py-3 hover:bg-surface-2/60">
                    <span className="font-mono text-xs text-ink-faint">#{a.id}</span>
                    <span className="flex-1 text-sm">{a.title}<span className="ml-2 font-mono text-xs text-ink-faint">{a.rule_id}</span></span>
                    <StatusBadge status={a.status} /><RiskScore score={a.risk_score} />
                  </Link></li>
                ))}
              </ul>
            )}
          </Card>
          {can("ai:use") && <AiPanel path={`/ai/summarize/incident/${inc.id}`} title="AI incident summary" />}
        </div>
        <div className="space-y-4">
          <Card title="Investigation notes">
            {manage && (
              <div className="mb-4 space-y-2">
                <TextArea aria-label="New note" placeholder="Document findings, actions taken and evidence reviewed" value={note} onChange={(e) => setNote(e.target.value)} />
                <Button disabled={!note.trim()} busy={action.busy}
                  onClick={async () => { const ok = await act(() => api.post(`/incidents/${inc.id}/notes`, { body: note })); if (ok) setNote(""); }}>Add note</Button>
              </div>
            )}
            {inc.notes.length === 0 ? <p className="text-sm text-ink-faint">No notes yet.</p> : (
              <ul className="space-y-3">
                {[...inc.notes].reverse().map((n) => (
                  <li key={n.id} className="rounded-md border border-line bg-canvas p-3 text-sm">
                    <div className="mb-1 text-xs text-ink-faint">{n.author?.username ?? "unknown"} · {formatShort(n.created_at)}</div>
                    <p className="whitespace-pre-wrap">{n.body}</p>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card title="Timeline">
            <ol className="space-y-3">
              {[...inc.history].reverse().map((h) => (
                <li key={h.id} className="border-l-2 border-line-strong pl-3 text-sm">
                  <div className="text-xs text-ink-faint">{formatShort(h.created_at)} · {h.actor?.username ?? "system"}</div>
                  <div><span className="font-medium">{titleCase(h.change_type)}</span>
                    {(h.from_value || h.to_value) && <span className="text-ink-muted"> {h.from_value ? `${h.from_value} → ` : ""}{h.to_value ?? "none"}</span>}</div>
                  {h.details && <p className="text-xs text-ink-muted">{h.details}</p>}
                </li>
              ))}
            </ol>
          </Card>
        </div>
      </div>

      <Modal title={`Change status to ${titleCase(target ?? "")}`} open={!!target} onClose={() => setTarget(null)}
        footer={<><Button onClick={() => setTarget(null)}>Cancel</Button><Button variant="primary" busy={action.busy} onClick={submitStatus}>Confirm</Button></>}>
        {needsResolution && (
          <Field label="Resolution details" hint="Required to resolve or close: what was found and what was done.">
            <TextArea value={resolution} onChange={(e) => setResolution(e.target.value)} />
          </Field>
        )}
        <Field label="Note" hint={inc.status === "closed" ? "Required when reopening a closed incident." : "Optional, recorded in the timeline."}>
          <TextArea value={statusNote} onChange={(e) => setStatusNote(e.target.value)} />
        </Field>
        <InlineError message={action.error} />
      </Modal>
    </div>
  );
}
