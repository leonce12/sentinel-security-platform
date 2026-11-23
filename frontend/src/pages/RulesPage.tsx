import { FlaskConical, Pencil, Play } from "lucide-react";
import { Fragment, useState } from "react";
import { Link } from "react-router-dom";

import {
  Button, Card, EmptyState, ErrorState, Field, InlineError, Input, Modal, PageHeader, Pagination, Select, SeverityBadge,
  Spinner, StatusBadge, SyntheticTag, Table, Tabs, Td, TextArea, Th,
} from "../components/ui";
import { useAuth } from "../contexts/AuthContext";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { AnomalyResult, DetectionSummary, Page, Rule, Severity } from "../types/api";
import { SEVERITIES, SEVERITY_LABEL, formatDateTime, formatShort, titleCase } from "../utils/format";

function RuleEditor({ rule, onClose, onSaved }: { rule: Rule; onClose: () => void; onSaved: () => void }) {
  const [enabled, setEnabled] = useState(rule.enabled);
  const [severity, setSeverity] = useState<Severity>(rule.severity);
  const [baseScore, setBaseScore] = useState(String(rule.base_score));
  const [confidence, setConfidence] = useState(String(rule.confidence));
  const [params, setParams] = useState<Record<string, string | boolean>>(
    Object.fromEntries(Object.entries(rule.parameters).map(([k, v]) => [k, Array.isArray(v) ? v.join("\n") : typeof v === "boolean" ? v : String(v)])),
  );
  const action = useAction();

  async function save() {
    const parameters: Record<string, unknown> = {};
    for (const [k, original] of Object.entries(rule.parameters)) {
      const v = params[k];
      if (Array.isArray(original)) parameters[k] = String(v).split("\n").map((s) => s.trim()).filter(Boolean);
      else if (typeof original === "boolean") parameters[k] = v;
      else parameters[k] = Number(v);
    }
    const ok = await action.run(() => api.patch(`/rules/${rule.id}`, {
      enabled, severity, base_score: Number(baseScore), confidence: Number(confidence), parameters,
    }));
    if (ok) { onSaved(); onClose(); }
  }

  return (
    <Modal title={`Configure ${rule.id}`} open onClose={onClose} wide
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" busy={action.busy} onClick={save}>Save changes</Button></>}>
      <p className="text-sm text-ink-muted">{rule.description}</p>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-4">
        <Field label="Status"><Select value={enabled ? "on" : "off"} onChange={(e) => setEnabled(e.target.value === "on")}><option value="on">Enabled</option><option value="off">Disabled</option></Select></Field>
        <Field label="Severity"><Select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>{SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}</Select></Field>
        <Field label="Base score (0-100)"><Input type="number" min={0} max={100} value={baseScore} onChange={(e) => setBaseScore(e.target.value)} /></Field>
        <Field label="Confidence (0.1-1)"><Input type="number" min={0.1} max={1} step={0.05} value={confidence} onChange={(e) => setConfidence(e.target.value)} /></Field>
      </div>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {Object.entries(rule.parameters).map(([k, original]) => (
          <Field key={k} label={titleCase(k)} hint={Array.isArray(original) ? "One value per line" : undefined}>
            {Array.isArray(original) ? <TextArea value={String(params[k])} onChange={(e) => setParams({ ...params, [k]: e.target.value })} className="font-mono text-xs" />
              : typeof original === "boolean" ? <Select value={params[k] ? "yes" : "no"} onChange={(e) => setParams({ ...params, [k]: e.target.value === "yes" })}><option value="yes">Yes</option><option value="no">No</option></Select>
              : <Input type="number" value={String(params[k])} onChange={(e) => setParams({ ...params, [k]: e.target.value })} />}
          </Field>
        ))}
      </div>
      <p className="text-xs text-ink-faint">Changes apply to future detection runs and are recorded in the audit log. Existing alerts are not deleted.</p>
      <InlineError message={action.error} />
    </Modal>
  );
}

function RulesTab() {
  const { can } = useAuth();
  const rules = useApi(() => api.get<Rule[]>("/rules"), []);
  const [editing, setEditing] = useState<Rule | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [summary, setSummary] = useState<DetectionSummary | null>(null);
  const action = useAction();

  async function runDetection() {
    const r = await action.run(() => api.post<DetectionSummary>("/detection/run", {}));
    if (r) setSummary(r);
  }

  if (rules.error) return <ErrorState message={rules.error} onRetry={rules.reload} />;
  if (!rules.data) return <Spinner />;
  return (
    <>
      {can("detection:run") && (
        <Card className="mb-4" title="Run detection" actions={<Button variant="primary" busy={action.busy} onClick={runDetection} icon={<Play className="h-4 w-4" />}>Run on all stored events</Button>}>
          <p className="text-sm text-ink-muted">Detection runs automatically after each ingestion. Running it again is safe: evidence that already backs an alert is never alerted twice.</p>
          <InlineError message={action.error} />
          {summary && (
            <p className="mt-3 rounded-md border border-line bg-canvas px-3 py-2 text-sm">
              Evaluated {summary.rules_evaluated} rules over {summary.events_considered.toLocaleString()} relevant events in {summary.duration_ms} ms:{" "}
              {summary.findings} findings, <strong>{summary.alerts_created} new alerts</strong>, {summary.alerts_updated} updated, {summary.unchanged} already known.
            </p>
          )}
        </Card>
      )}
      <Card bodyClassName="p-0">
        <Table>
          <thead><tr><Th>Rule</Th><Th>Category</Th><Th>Severity</Th><Th>Base score</Th><Th>Confidence</Th><Th>Status</Th><Th>Updated</Th><Th /></tr></thead>
          <tbody>
            {rules.data.map((r) => (
              <Fragment key={r.id}>
                <tr className="cursor-pointer hover:bg-surface-2/50" onClick={() => setExpanded(expanded === r.id ? null : r.id)}>
                  <Td><div className="font-medium">{r.name}</div><div className="font-mono text-xs text-ink-faint">{r.id}</div></Td>
                  <Td>{titleCase(r.category)}</Td><Td><SeverityBadge severity={r.severity} /></Td>
                  <Td className="tabular-nums">{r.base_score}</Td><Td className="tabular-nums">{Math.round(r.confidence * 100)}%</Td>
                  <Td><StatusBadge status={r.enabled ? "enabled" : "disabled"} /></Td>
                  <Td className="whitespace-nowrap text-xs">{formatShort(r.updated_at)}</Td>
                  <Td className="text-right">{can("rules:manage") && <Button variant="ghost" onClick={(e) => { e.stopPropagation(); setEditing(r); }} icon={<Pencil className="h-4 w-4" />}>Configure</Button>}</Td>
                </tr>
                {expanded === r.id && (
                  <tr><td colSpan={8} className="border-b border-line bg-canvas/60 px-4 py-4 text-sm">
                    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
                      <div><h4 className="mb-1 text-xs uppercase tracking-wide text-ink-faint">Detection conditions</h4><p className="text-ink-muted">{r.description}</p>
                        <h4 className="mb-1 mt-3 text-xs uppercase tracking-wide text-ink-faint">Why it exists</h4><p className="text-ink-muted">{r.rationale}</p>
                        <h4 className="mb-1 mt-3 text-xs uppercase tracking-wide text-ink-faint">Required fields</h4><p className="font-mono text-xs text-ink-muted">{r.required_fields.join(", ")}</p></div>
                      <div><h4 className="mb-1 text-xs uppercase tracking-wide text-ink-faint">Parameters</h4>
                        <dl className="space-y-1 font-mono text-xs">{Object.entries(r.parameters).map(([k, v]) => (
                          <div key={k}><dt className="inline text-ink-faint">{k}: </dt><dd className="inline text-ink-muted">{Array.isArray(v) ? v.join(", ") || "(empty)" : String(v)}</dd></div>))}</dl></div>
                      <div><h4 className="mb-1 text-xs uppercase tracking-wide text-ink-faint">Investigation steps</h4>
                        <ol className="list-decimal space-y-1 pl-5 text-ink-muted">{r.investigation_steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
                        <h4 className="mb-1 mt-3 text-xs uppercase tracking-wide text-ink-faint">False positives</h4><p className="text-ink-muted">{r.false_positive_notes}</p>
                        <Link to={`/alerts?rule_id=${r.id}`} className="mt-3 inline-block text-accent">View alerts from this rule</Link></div>
                    </div>
                  </td></tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </Table>
      </Card>
      {editing && <RuleEditor rule={editing} onClose={() => setEditing(null)} onSaved={rules.reload} />}
    </>
  );
}

function AnomalyTab() {
  const { can } = useAuth();
  const [page, setPage] = useState(1);
  const [filter, setFilter] = useState("");
  const status = useApi(() => api.get<{ enabled: boolean; features: string[]; min_rows: number; contamination: number; model_version: string }>("/anomaly/status"), []);
  const results = useApi(() => api.get<Page<AnomalyResult>>("/anomaly/results", { page, review_status: filter || undefined }), [page, filter]);
  const action = useAction();
  const [summary, setSummary] = useState<Record<string, unknown> | null>(null);
  const [review, setReview] = useState<AnomalyResult | null>(null);
  const [reviewStatus, setReviewStatus] = useState("needs_follow_up");
  const [note, setNote] = useState("");

  async function run() {
    const r = await action.run(() => api.post<Record<string, unknown>>("/anomaly/run"));
    if (r) { setSummary(r); results.reload(); }
  }
  async function saveReview() {
    const r = await action.run(() => api.post(`/anomaly/results/${review!.id}/review`, { status: reviewStatus, note }));
    if (r) { setReview(null); results.reload(); }
  }

  return (
    <>
      <Card className="mb-4" title={<span className="inline-flex items-center gap-2"><FlaskConical className="h-4 w-4 text-accent" />Experimental anomaly detection</span>}
        actions={can("anomaly:run") && <Button variant="primary" onClick={run} busy={action.busy} disabled={!status.data?.enabled} icon={<Play className="h-4 w-4" />}>Run model</Button>}>
        <p className="text-sm text-ink-muted">
          An Isolation Forest scores each account-hour by how different it is from the rest of the stored history.
          Results are advisory: they never create alerts or incidents and must be reviewed by an analyst. Unusual does not mean malicious.
        </p>
        {status.data && (
          <p className="mt-2 text-xs text-ink-faint">
            Status: {status.data.enabled ? "enabled" : "disabled (an administrator can enable it in Settings)"} · Model {status.data.model_version} ·
            Features: {status.data.features.join(", ")} · Expected unusual share {status.data.contamination} · Needs at least {status.data.min_rows} account-hours
          </p>
        )}
        <InlineError message={action.error} />
        {summary && <p className="mt-2 rounded-md border border-line bg-canvas px-3 py-2 text-sm">Scored {String(summary.rows_scored)} account-hours; {String(summary.anomalies)} flagged, {String(summary.stored)} stored for review.</p>}
      </Card>
      <Card bodyClassName="p-3">
        <div className="mb-3 flex gap-2">
          <Select aria-label="Review status" value={filter} onChange={(e) => { setFilter(e.target.value); setPage(1); }} className="w-56">
            <option value="">All results</option><option value="unreviewed">Unreviewed</option><option value="needs_follow_up">Needs follow-up</option><option value="false_positive">False positive</option>
          </Select>
        </div>
        {results.error ? <ErrorState message={results.error} /> : !results.data ? <Spinner /> : results.data.items.length === 0 ? (
          <EmptyState title="No anomaly results" description="Enable anomaly detection in Settings, then run the model." />
        ) : (
          <>
            <Table>
              <thead><tr><Th>Entity</Th><Th>Hour (UTC)</Th><Th>Score</Th><Th>Why it stands out</Th><Th>Review</Th><Th /></tr></thead>
              <tbody>{results.data.items.map((r) => (
                <tr key={r.id}>
                  <Td className="font-mono text-xs">{r.entity} {r.is_synthetic && <SyntheticTag />}</Td>
                  <Td className="whitespace-nowrap text-xs">{formatDateTime(r.window_start)}</Td>
                  <Td className="font-mono tabular-nums">{r.anomaly_score.toFixed(2)}</Td>
                  <Td className="text-xs text-ink-muted">{r.contributing_features.length ? r.contributing_features.map((c) => `${titleCase(c.feature)} ${c.value} (typical ${c.baseline_mean})`).join("; ") : "Combination of features; no single feature stands out"}</Td>
                  <Td><StatusBadge status={r.review_status} />{r.review_note && <div className="mt-1 text-xs text-ink-faint">{r.review_note}</div>}</Td>
                  <Td>{can("anomaly:run") && <Button variant="ghost" onClick={() => { setReview(r); setReviewStatus(r.review_status === "unreviewed" ? "needs_follow_up" : r.review_status); setNote(r.review_note); }}>Review</Button>}</Td>
                </tr>
              ))}</tbody>
            </Table>
            <Pagination page={results.data.page} pages={results.data.pages} total={results.data.total} onPage={setPage} />
          </>
        )}
      </Card>
      <Modal title="Review anomaly" open={!!review} onClose={() => setReview(null)}
        footer={<><Button onClick={() => setReview(null)}>Cancel</Button><Button variant="primary" onClick={saveReview} busy={action.busy}>Save review</Button></>}>
        <Field label="Outcome"><Select value={reviewStatus} onChange={(e) => setReviewStatus(e.target.value)}>
          <option value="needs_follow_up">Needs follow-up</option><option value="false_positive">False positive</option><option value="unreviewed">Unreviewed</option></Select></Field>
        <Field label="Note"><TextArea value={note} onChange={(e) => setNote(e.target.value)} placeholder="What did you check?" /></Field>
        <InlineError message={action.error} />
      </Modal>
    </>
  );
}

export default function RulesPage() {
  const [tab, setTab] = useState<"rules" | "anomaly">("rules");
  return (
    <div>
      <PageHeader title="Detection rules" description="Transparent, deterministic rules are the foundation of Sentinel. Each rule documents its conditions, thresholds, investigation steps and known false positives." />
      <Tabs tabs={[{ id: "rules", label: "Rules" }, { id: "anomaly", label: "Anomaly detection (experimental)" }]} value={tab} onChange={setTab} />
      {tab === "rules" ? <RulesTab /> : <AnomalyTab />}
    </div>
  );
}
