import { ArrowLeft, Globe } from "lucide-react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { Button, Card, EmptyState, ErrorState, KeyValue, PageHeader, RiskScore, SeverityBadge, Spinner, StatusBadge, SyntheticTag } from "../components/ui";
import { useAuth } from "../contexts/AuthContext";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { EventDetail } from "../types/api";
import { formatDateTime, titleCase } from "../utils/format";

export default function EventDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { can } = useAuth();
  const event = useApi(() => api.get<EventDetail>(`/events/${id}`), [id]);

  if (event.error) return <ErrorState message={event.error} onRetry={event.reload} />;
  if (!event.data) return <Spinner />;
  const e = event.data;

  return (
    <div>
      <Button variant="ghost" onClick={() => navigate(-1)} icon={<ArrowLeft className="h-4 w-4" />} className="mb-2 -ml-2">Back</Button>
      <PageHeader title={`${e.event_type}`} description={e.description || undefined}
        actions={<>{e.is_synthetic && <SyntheticTag />}<SeverityBadge severity={e.severity} /><RiskScore score={e.risk_score} /></>} />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Normalized event" className="xl:col-span-2">
          <KeyValue items={[
            ["Timestamp", formatDateTime(e.timestamp)], ["Event ID", <span className="font-mono text-xs">{e.event_uid}</span>],
            ["Source system", e.source_system], ["Category", titleCase(e.event_category)],
            ["Username", e.username], ["Action", e.action], ["Outcome", e.outcome ? titleCase(e.outcome) : null],
            ["Resource", e.resource ? <span className="font-mono text-xs">{e.resource}</span> : null],
            ["Source IP", e.source_ip ? <span className="inline-flex items-center gap-2 font-mono text-xs">{e.source_ip}
              {can("intel:lookup") && <Link to={`/intel?ip=${e.source_ip}`} className="text-accent" title="Check reputation"><Globe className="h-3.5 w-3.5" /></Link>}</span> : null],
            ["Destination IP", e.destination_ip ? <span className="font-mono text-xs">{e.destination_ip}</span> : null],
            ["Ingested", formatDateTime(e.ingested_at)],
            ["Ingestion job", e.ingestion_job_id ? <Link className="text-accent" to={`/events?job_id=${e.ingestion_job_id}`}>#{e.ingestion_job_id}</Link> : null],
          ]} />
        </Card>
        <div className="space-y-4">
          <Card title={`Associated alerts (${e.alerts.length})`} bodyClassName="p-0">
            {e.alerts.length === 0 ? <EmptyState title="Not used as alert evidence" /> : (
              <ul className="divide-y divide-line">
                {e.alerts.map((a) => (
                  <li key={a.id}><Link to={`/alerts/${a.id}`} className="block px-4 py-3 hover:bg-surface-2/60">
                    <div className="flex items-center justify-between gap-2"><span className="text-sm">{a.title}</span><RiskScore score={a.risk_score} /></div>
                    <div className="mt-1 flex items-center gap-2 text-xs text-ink-faint"><span className="font-mono">{a.rule_id}</span><StatusBadge status={a.status} /></div>
                  </Link></li>
                ))}
              </ul>
            )}
          </Card>
          <Card title={`Related incidents (${e.incidents.length})`} bodyClassName="p-0">
            {e.incidents.length === 0 ? <EmptyState title="No related incidents" /> : (
              <ul className="divide-y divide-line">
                {e.incidents.map((i) => (
                  <li key={i.id}><Link to={`/incidents/${i.id}`} className="block px-4 py-3 hover:bg-surface-2/60">
                    <div className="font-mono text-xs text-ink-faint">{i.reference}</div>
                    <div className="text-sm">{i.title}</div>
                    <div className="mt-1"><StatusBadge status={i.status} /></div>
                  </Link></li>
                ))}
              </ul>
            )}
          </Card>
        </div>
        <Card title="Raw event data" className="xl:col-span-3">
          <p className="mb-2 text-xs text-ink-faint">Original fields kept for investigation. Displayed as text; never interpreted.</p>
          <pre className="max-h-96 overflow-auto rounded-md border border-line bg-canvas p-3 font-mono text-xs text-ink-muted">
            {JSON.stringify(e.raw_data, null, 2)}
          </pre>
        </Card>
      </div>
    </div>
  );
}
