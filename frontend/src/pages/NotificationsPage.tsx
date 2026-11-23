import { CheckCheck } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { Button, Card, EmptyState, ErrorState, PageHeader, Pagination, Select, Spinner, cx } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { Notification, Page } from "../types/api";
import { formatDateTime, formatRelative, titleCase } from "../utils/format";

export default function NotificationsPage() {
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const [filter, setFilter] = useState("");
  const items = useApi(() => api.get<Page<Notification>>("/notifications", { page, unread: filter === "unread" ? true : undefined }), [page, filter]);
  const action = useAction();

  async function open(n: Notification) {
    if (!n.is_read) await action.run(() => api.post(`/notifications/${n.id}/read`));
    if (n.link) navigate(n.link);
    else items.reload();
  }

  return (
    <div>
      <PageHeader title="Notifications" description="In-app notifications only. Sentinel never sends notifications outside the application unless an administrator configures it."
        actions={<>
          <Select aria-label="Filter" value={filter} onChange={(e) => { setFilter(e.target.value); setPage(1); }} className="w-36"><option value="">All</option><option value="unread">Unread</option></Select>
          <Button onClick={async () => { await action.run(() => api.post("/notifications/read-all")); items.reload(); }} busy={action.busy} icon={<CheckCheck className="h-4 w-4" />}>Mark all read</Button>
        </>} />
      <Card bodyClassName="p-0">
        {items.error ? <ErrorState message={items.error} onRetry={items.reload} /> : !items.data ? <Spinner /> : items.data.items.length === 0 ? (
          <EmptyState title="No notifications" description="You will be notified about critical alerts, high-risk incidents, assignments and failed ingestion jobs." />
        ) : (
          <>
            <ul className="divide-y divide-line">
              {items.data.items.map((n) => (
                <li key={n.id}>
                  <button type="button" onClick={() => open(n)} className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-surface-2/60">
                    <span className={cx("mt-1.5 h-2 w-2 shrink-0 rounded-full", n.is_read ? "bg-transparent" : "bg-accent")} aria-label={n.is_read ? "Read" : "Unread"} />
                    <span className="flex-1">
                      <span className={cx("block text-sm", !n.is_read && "font-medium")}>{n.title}</span>
                      {n.message && <span className="block text-sm text-ink-muted">{n.message}</span>}
                      <span className="block text-xs text-ink-faint">{titleCase(n.notification_type)} · <span title={formatDateTime(n.created_at)}>{formatRelative(n.created_at)}</span></span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
            <div className="px-4 pb-3"><Pagination page={items.data.page} pages={items.data.pages} total={items.data.total} onPage={setPage} /></div>
          </>
        )}
      </Card>
    </div>
  );
}
