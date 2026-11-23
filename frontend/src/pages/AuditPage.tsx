import { Download, RefreshCw } from "lucide-react";
import { Fragment, useState } from "react";

import { Button, Card, EmptyState, ErrorState, InlineError, Input, PageHeader, Pagination, Select, Spinner, StatusBadge, Table, Td, Th } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { AuditEntry, Page } from "../types/api";
import { formatDateTime } from "../utils/format";

export default function AuditPage() {
  const [page, setPage] = useState(1);
  const [q, setQ] = useState("");
  const [outcome, setOutcome] = useState("");
  const [expanded, setExpanded] = useState<number | null>(null);
  const logs = useApi(() => api.get<Page<AuditEntry>>("/audit-logs", { page, q: q || undefined, outcome: outcome || undefined }), [page, q, outcome]);
  const action = useAction();
  return (
    <div>
      <PageHeader title="Audit logs" description="Append-only record of sign-ins, administrative changes and analyst actions. The database rejects updates and deletes to this table. Secrets are never recorded." />
      <Card bodyClassName="p-3">
        <div className="mb-3 flex flex-wrap gap-2">
          <Input aria-label="Search audit log" placeholder="Search action, user or object" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} className="max-w-xs" />
          <Select aria-label="Outcome" value={outcome} onChange={(e) => { setOutcome(e.target.value); setPage(1); }} className="w-40">
            <option value="">All outcomes</option><option value="success">Success</option><option value="failure">Failure</option><option value="denied">Denied</option>
          </Select>
          <div className="flex-1" />
          <Button variant="ghost" onClick={logs.reload} icon={<RefreshCw className="h-4 w-4" />}>Refresh</Button>
          <Button busy={action.busy} icon={<Download className="h-4 w-4" />}
            onClick={() => action.run(() => api.download("/audit-logs/export", { q: q || undefined, outcome: outcome || undefined }, "sentinel-audit-log.csv"))}>Export CSV</Button>
        </div>
        <InlineError message={action.error} />
        {logs.error ? <ErrorState message={logs.error} onRetry={logs.reload} /> : !logs.data ? <Spinner /> : logs.data.items.length === 0 ? <EmptyState title="No audit entries match" /> : (
          <>
            <Table>
              <thead><tr><Th>Time</Th><Th>Actor</Th><Th>Action</Th><Th>Object</Th><Th>Outcome</Th><Th>IP</Th><Th /></tr></thead>
              <tbody>{logs.data.items.map((l) => (
                <Fragment key={l.id}>
                  <tr className="hover:bg-surface-2/50">
                    <Td className="whitespace-nowrap font-mono text-xs">{formatDateTime(l.created_at)}</Td>
                    <Td>{l.actor_username ?? "system"}</Td><Td className="font-mono text-xs">{l.action}</Td>
                    <Td className="font-mono text-xs">{l.object_type ? `${l.object_type}${l.object_id ? ` #${l.object_id}` : ""}` : "-"}</Td>
                    <Td><StatusBadge status={l.outcome} /></Td><Td className="font-mono text-xs">{l.ip_address ?? "-"}</Td>
                    <Td className="text-right">{Object.keys(l.details).length > 0 && <Button variant="ghost" onClick={() => setExpanded(expanded === l.id ? null : l.id)}>{expanded === l.id ? "Hide" : "Details"}</Button>}</Td>
                  </tr>
                  {expanded === l.id && <tr><td colSpan={7} className="border-b border-line bg-canvas px-4 py-2"><pre className="overflow-x-auto font-mono text-xs text-ink-muted">{JSON.stringify(l.details, null, 2)}</pre></td></tr>}
                </Fragment>
              ))}</tbody>
            </Table>
            <Pagination page={logs.data.page} pages={logs.data.pages} total={logs.data.total} onPage={setPage} />
          </>
        )}
      </Card>
    </div>
  );
}
