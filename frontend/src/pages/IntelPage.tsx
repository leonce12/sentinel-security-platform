import { Globe, Plus, Search } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";

import {
  Button, Card, EmptyState, ErrorState, Field, InlineError, Input, Modal, PageHeader, Pagination, Select, Spinner,
  SyntheticTag, Table, Tabs, Td, TextArea, Th, cx,
} from "../components/ui";
import { useAuth } from "../contexts/AuthContext";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { Indicator, Lookup, Page } from "../types/api";
import { formatShort } from "../utils/format";

const VERDICT: Record<string, { label: string; className: string; note: string }> = {
  malicious: { label: "Malicious", className: "text-sev-critical border-sev-critical/40 bg-sev-critical/10", note: "Reported as malicious by this source. Context for investigation, not proof." },
  suspicious: { label: "Suspicious", className: "text-sev-medium border-sev-medium/40 bg-sev-medium/10", note: "Some reports of suspicious activity." },
  no_detections: { label: "No detections", className: "text-ink-muted border-line-strong", note: "The source knows this address and reports no detections. This does not mean it is safe." },
  no_information: { label: "No information", className: "text-ink-muted border-line-strong", note: "The source has no data about this address. Absence of data is not evidence of safety." },
  unavailable: { label: "Unavailable", className: "text-ink-faint border-dashed border-line-strong", note: "The source could not be queried." },
};

function VerdictBadge({ verdict }: { verdict: string }) {
  const v = VERDICT[verdict] ?? VERDICT.unavailable;
  return <span className={cx("inline-flex rounded border px-1.5 py-0.5 text-xs font-medium", v.className)}>{v.label}</span>;
}

function LookupPanel() {
  const [params] = useSearchParams();
  const [ip, setIp] = useState(params.get("ip") ?? "");
  const [results, setResults] = useState<Lookup[] | null>(null);
  const action = useAction();
  const status = useApi(() => api.get<{ local_indicators: number; external_enabled: boolean; virustotal_configured: boolean; cache_hours: number; privacy_note: string }>("/intel/status"), []);

  async function lookup(e?: FormEvent) {
    e?.preventDefault();
    if (!ip.trim()) return;
    const r = await action.run(() => api.post<Lookup[]>("/intel/lookup", { indicator: ip.trim() }));
    if (r) setResults(r);
  }
  useEffect(() => { if (params.get("ip")) lookup(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
      <Card title="Check an IP address" className="xl:col-span-2">
        <form onSubmit={lookup} className="mb-4 flex gap-2">
          <Input aria-label="IP address" placeholder="203.0.113.45" value={ip} onChange={(e) => setIp(e.target.value)} className="max-w-sm font-mono" />
          <Button type="submit" variant="primary" busy={action.busy} icon={<Search className="h-4 w-4" />}>Look up</Button>
        </form>
        <InlineError message={action.error} />
        {results && (
          <div className="space-y-3">
            {results.map((r, i) => (
              <div key={i} className="rounded-md border border-line bg-canvas p-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{r.provider === "local" ? "Local dataset" : r.provider === "virustotal" ? "VirusTotal" : r.provider}</span>
                  <VerdictBadge verdict={r.verdict} />
                  {r.confidence != null && <span className="text-xs text-ink-muted">Confidence {(r.confidence * 100).toFixed(0)}%</span>}
                  <span className="text-xs text-ink-faint">Checked {formatShort(r.looked_up_at)}{r.details?.cached ? " (cached)" : ""}</span>
                </div>
                <p className="mt-1 text-xs text-ink-muted">{VERDICT[r.verdict]?.note}</p>
                {typeof r.details?.reason === "string" && <p className="mt-1 text-xs text-ink-faint">{r.details.reason as string}</p>}
                {Array.isArray(r.details?.entries) && (
                  <ul className="mt-2 space-y-1 text-xs">
                    {(r.details.entries as { source: string; verdict: string; description: string; synthetic: boolean }[]).map((e, j) => (
                      <li key={j} className="text-ink-muted">{e.source}: {e.verdict}. {e.description} {e.synthetic && <SyntheticTag />}</li>
                    ))}
                  </ul>
                )}
                {r.details?.analysis_stats != null && (
                  <p className="mt-2 font-mono text-xs text-ink-muted">{JSON.stringify(r.details.analysis_stats)}</p>
                )}
                {r.limitations && <p className="mt-2 text-xs text-ink-faint">Limitations: {r.limitations}</p>}
              </div>
            ))}
          </div>
        )}
      </Card>
      <Card title="Sources">
        {status.error ? <ErrorState message={status.error} /> : !status.data ? <Spinner /> : (
          <ul className="space-y-3 text-sm">
            <li><div className="font-medium">Local dataset</div><div className="text-ink-muted">{status.data.local_indicators} indicators. Works offline.</div></li>
            <li><div className="font-medium">VirusTotal</div>
              <div className="text-ink-muted">{!status.data.virustotal_configured ? "Not configured (no API key)." : status.data.external_enabled ? `Enabled. Results cached for ${status.data.cache_hours} h.` : "Configured but disabled in Settings."}</div></li>
            <li className="rounded-md border border-line bg-canvas p-3 text-xs text-ink-muted">{status.data.privacy_note}</li>
          </ul>
        )}
      </Card>
    </div>
  );
}

function IndicatorsPanel() {
  const { can } = useAuth();
  const [page, setPage] = useState(1);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ indicator: "", verdict: "suspicious", confidence: "0.5", source: "analyst", description: "" });
  const indicators = useApi(() => api.get<Page<Indicator>>("/intel/indicators", { q, page }), [q, page]);
  const action = useAction();

  async function add() {
    const r = await action.run(() => api.post("/intel/indicators", { ...form, confidence: Number(form.confidence) }));
    if (r) { setOpen(false); indicators.reload(); }
  }

  return (
    <Card bodyClassName="p-3">
      <div className="mb-3 flex gap-2">
        <Input aria-label="Filter indicators" placeholder="Filter by IP" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} className="max-w-xs" />
        <div className="flex-1" />
        {can("intel:manage") && <Button onClick={() => setOpen(true)} icon={<Plus className="h-4 w-4" />}>Add indicator</Button>}
      </div>
      {indicators.error ? <ErrorState message={indicators.error} /> : !indicators.data ? <Spinner /> : indicators.data.items.length === 0 ? (
        <EmptyState title="No local indicators" description="Load the demo dataset or add indicators manually." />
      ) : (
        <>
          <Table>
            <thead><tr><Th>Indicator</Th><Th>Verdict</Th><Th>Confidence</Th><Th>Source</Th><Th>Description</Th><Th>Added</Th></tr></thead>
            <tbody>{indicators.data.items.map((i) => (
              <tr key={i.id}><Td className="font-mono text-xs">{i.indicator}</Td><Td><VerdictBadge verdict={i.verdict} /></Td>
                <Td>{(i.confidence * 100).toFixed(0)}%</Td><Td>{i.source} {i.is_synthetic && <SyntheticTag />}</Td>
                <Td className="text-ink-muted">{i.description}</Td><Td className="whitespace-nowrap text-xs">{formatShort(i.added_at)}</Td></tr>
            ))}</tbody>
          </Table>
          <Pagination page={indicators.data.page} pages={indicators.data.pages} total={indicators.data.total} onPage={setPage} />
        </>
      )}
      <Modal title="Add local indicator" open={open} onClose={() => setOpen(false)}
        footer={<><Button onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" busy={action.busy} onClick={add}>Add</Button></>}>
        <Field label="IP address"><Input value={form.indicator} onChange={(e) => setForm({ ...form, indicator: e.target.value })} /></Field>
        <Field label="Verdict"><Select value={form.verdict} onChange={(e) => setForm({ ...form, verdict: e.target.value })}><option value="suspicious">Suspicious</option><option value="malicious">Malicious</option></Select></Field>
        <Field label="Confidence (0 to 1)"><Input type="number" min="0" max="1" step="0.05" value={form.confidence} onChange={(e) => setForm({ ...form, confidence: e.target.value })} /></Field>
        <Field label="Source"><Input value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })} /></Field>
        <Field label="Description"><TextArea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        <InlineError message={action.error} />
      </Modal>
    </Card>
  );
}

function HistoryPanel() {
  const [page, setPage] = useState(1);
  const history = useApi(() => api.get<Page<Lookup>>("/intel/lookups", { page }), [page]);
  if (history.error) return <ErrorState message={history.error} />;
  if (!history.data) return <Spinner />;
  if (!history.data.items.length) return <EmptyState title="No lookups yet" />;
  return (
    <Card bodyClassName="p-3">
      <Table>
        <thead><tr><Th>Time</Th><Th>Indicator</Th><Th>Provider</Th><Th>Verdict</Th><Th>Confidence</Th></tr></thead>
        <tbody>{history.data.items.map((l) => (
          <tr key={l.id}><Td className="whitespace-nowrap text-xs">{formatShort(l.looked_up_at)}</Td><Td className="font-mono text-xs">{l.indicator}</Td>
            <Td>{l.provider}</Td><Td><VerdictBadge verdict={l.verdict} /></Td><Td>{l.confidence != null ? `${(l.confidence * 100).toFixed(0)}%` : "-"}</Td></tr>
        ))}</tbody>
      </Table>
      <Pagination page={history.data.page} pages={history.data.pages} total={history.data.total} onPage={setPage} />
    </Card>
  );
}

export default function IntelPage() {
  const [tab, setTab] = useState<"lookup" | "indicators" | "history">("lookup");
  return (
    <div>
      <PageHeader title="Threat intelligence" description="Reputation context for IP addresses. A bad reputation is a lead for investigation; missing information never means an address is safe." />
      <Tabs tabs={[{ id: "lookup", label: "Lookup" }, { id: "indicators", label: "Local indicators" }, { id: "history", label: "Lookup history" }]} value={tab} onChange={setTab} />
      {tab === "lookup" && <LookupPanel />}
      {tab === "indicators" && <IndicatorsPanel />}
      {tab === "history" && <HistoryPanel />}
      <p className="mt-4 flex items-center gap-2 text-xs text-ink-faint"><Globe className="h-3.5 w-3.5" /> External lookups are off by default and send only the single public IP being checked.</p>
    </div>
  );
}
