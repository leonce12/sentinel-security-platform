import { FileDown, FileText } from "lucide-react";
import { useState } from "react";

import {
  Button, Card, EmptyState, ErrorState, Field, InlineError, Input, PageHeader, Pagination, Select, Spinner, Table, Td, Th,
} from "../components/ui";
import { useAuth } from "../contexts/AuthContext";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { Incident, Page, Report } from "../types/api";
import { formatShort, titleCase } from "../utils/format";

export default function ReportsPage() {
  const { can } = useAuth();
  const [page, setPage] = useState(1);
  const reports = useApi(() => api.get<Page<Report>>("/reports", { page }), [page]);
  const incidents = useApi(() => (can("reports:generate") ? api.get<Page<Incident>>("/incidents", { page_size: 100, sort: "detected_at" }) : Promise.resolve(null)), []);
  const summary = useApi(() => api.get<{ range: { end: string } }>("/dashboard/summary"), []);
  const latest = summary.data?.range.end.slice(0, 10);
  const [type, setType] = useState<"daily" | "weekly" | "incident">("daily");
  const [day, setDay] = useState("");
  const [incidentId, setIncidentId] = useState("");
  const action = useAction();

  async function generate() {
    const chosenDay = day || latest || new Date().toISOString().slice(0, 10);
    const body = type === "daily" ? { report_type: "daily", date: chosenDay }
      : type === "weekly" ? { report_type: "weekly", start_date: day || new Date(new Date(chosenDay).getTime() - 6 * 86_400_000).toISOString().slice(0, 10) }
      : { report_type: "incident", incident_id: Number(incidentId) };
    if (type === "incident" && !incidentId) return action.setError("Choose an incident.");
    const report = await action.run(() => api.post<Report>("/reports", body));
    if (report) {
      reports.reload();
      await action.run(() => api.download(`/reports/${report.id}/download`, undefined, `sentinel-${report.report_type}-report.pdf`));
    }
  }

  return (
    <div>
      <PageHeader title="Reports" description="PDF reports are generated from database records at the moment you request them, and stored with a SHA-256 hash." />
      {can("reports:generate") && (
        <Card title="Generate a report" className="mb-4">
          <div className="grid grid-cols-1 items-end gap-3 sm:grid-cols-4">
            <Field label="Report type">
              <Select value={type} onChange={(e) => { setType(e.target.value as typeof type); setDay(""); }}>
                <option value="daily">Daily security report</option><option value="weekly">Weekly security report</option><option value="incident">Incident report</option>
              </Select>
            </Field>
            {type !== "incident" ? (
              <Field label={type === "daily" ? "Day (UTC)" : "Week starting (UTC)"} hint={latest ? `Latest data: ${latest}` : undefined}>
                <Input type="date" value={day} onChange={(e) => setDay(e.target.value)} />
              </Field>
            ) : (
              <div className="sm:col-span-2"><Field label="Incident">
                <Select value={incidentId} onChange={(e) => setIncidentId(e.target.value)}>
                  <option value="">Choose an incident</option>
                  {incidents.data?.items.map((i) => <option key={i.id} value={i.id}>{i.reference} · {i.title}</option>)}
                </Select>
              </Field></div>
            )}
            <Button variant="primary" busy={action.busy} onClick={generate} icon={<FileText className="h-4 w-4" />}>Generate PDF</Button>
          </div>
          <div className="mt-3"><InlineError message={action.error} /></div>
        </Card>
      )}
      <Card title="Generated reports" bodyClassName="p-3">
        {reports.error ? <ErrorState message={reports.error} onRetry={reports.reload} /> : !reports.data ? <Spinner /> : reports.data.items.length === 0 ? (
          <EmptyState title="No reports yet" description="Generated reports appear here for download." />
        ) : (
          <>
            <Table>
              <thead><tr><Th>Report</Th><Th>Type</Th><Th>Generated</Th><Th>By</Th><Th>Size</Th><Th>SHA-256</Th><Th /></tr></thead>
              <tbody>{reports.data.items.map((r) => (
                <tr key={r.id}>
                  <Td className="font-medium">{r.title}</Td><Td>{titleCase(r.report_type)}</Td>
                  <Td className="whitespace-nowrap text-xs">{formatShort(r.generated_at)}</Td><Td>{r.generated_by?.username ?? "-"}</Td>
                  <Td className="tabular-nums text-xs">{(r.size_bytes / 1024).toFixed(1)} KB</Td>
                  <Td className="font-mono text-xs text-ink-faint" >{r.sha256.slice(0, 16)}...</Td>
                  <Td className="text-right"><Button variant="ghost" icon={<FileDown className="h-4 w-4" />}
                    onClick={() => action.run(() => api.download(`/reports/${r.id}/download`, undefined, `report-${r.id}.pdf`))}>Download</Button></Td>
                </tr>
              ))}</tbody>
            </Table>
            <Pagination page={reports.data.page} pages={reports.data.pages} total={reports.data.total} onPage={setPage} />
          </>
        )}
      </Card>
    </div>
  );
}
