import { BookOpen, Bot, MessageSquare } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";

import { Explanation } from "../components/AiPanel";
import { Button, Card, ErrorState, InlineError, Input, PageHeader, RiskScore, Spinner, Tabs } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { AiResponse, Alert, Page } from "../types/api";

export default function AiAnalystPage() {
  const [tab, setTab] = useState<"explain" | "ask" | "glossary">("explain");
  const status = useApi(() => api.get<{ state: string; message: string; provider: string | null }>("/ai/status"), []);
  const alerts = useApi(() => api.get<Page<Alert>>("/alerts", { sort: "risk_score", order: "desc", page_size: 12, status: ["new", "acknowledged", "investigating"] }), []);
  const glossary = useApi(() => api.get<{ term: string; definition: string }[]>("/ai/glossary"), []);
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState<AiResponse | null>(null);
  const [explained, setExplained] = useState<{ alert: Alert; result: AiResponse } | null>(null);
  const action = useAction();
  const [filter, setFilter] = useState("");

  async function ask(e: FormEvent) {
    e.preventDefault();
    if (question.trim().length < 3) return;
    const r = await action.run(() => api.post<AiResponse>("/ai/ask", { question }));
    if (r) setAnswer(r);
  }

  async function explain(alert: Alert) {
    const r = await action.run(() => api.post<AiResponse>(`/ai/explain/alert/${alert.id}`));
    if (r) setExplained({ alert, result: r });
  }

  const stateTone = status.data?.state === "available" ? "border-sev-low/40 text-sev-low" : "border-line-strong text-ink-muted";

  return (
    <div>
      <PageHeader title="AI security analyst" description="Explains detections, suggests defensive investigation steps and teaches security concepts. It assists analysts; it never decides, changes records or takes action." />
      {status.data && (
        <div className={`mb-4 flex items-center gap-2 rounded-md border px-3 py-2 text-sm ${stateTone}`}>
          <Bot className="h-4 w-4" aria-hidden /> {status.data.message}
        </div>
      )}
      <Tabs tabs={[{ id: "explain", label: "Explain an alert" }, { id: "ask", label: "Ask a question" }, { id: "glossary", label: "Glossary" }]} value={tab} onChange={setTab} />
      <InlineError message={action.error} />

      {tab === "explain" && (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          <Card title="Open alerts by risk" bodyClassName="p-0">
            {alerts.error ? <ErrorState message={alerts.error} /> : !alerts.data ? <Spinner /> : alerts.data.items.length === 0 ? (
              <p className="p-4 text-sm text-ink-muted">No open alerts.</p>
            ) : (
              <ul className="divide-y divide-line">{alerts.data.items.map((a) => (
                <li key={a.id}><button type="button" onClick={() => explain(a)} className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-surface-2/60">
                  <span className="flex-1 text-sm">{a.title}<span className="block font-mono text-xs text-ink-faint">#{a.id} {a.rule_id}</span></span>
                  <RiskScore score={a.risk_score} />
                </button></li>
              ))}</ul>
            )}
          </Card>
          <Card title={explained ? `Alert #${explained.alert.id}` : "Explanation"} className="xl:col-span-2"
            actions={explained && <Link to={`/alerts/${explained.alert.id}`} className="text-sm text-accent">Open alert</Link>}>
            {action.busy ? <Spinner label="Preparing explanation" /> : !explained ? (
              <p className="text-sm text-ink-muted">Choose an alert to see what happened, why it was flagged, what the risk score means, what is missing and which checks to perform.</p>
            ) : (
              <div className="space-y-4">
                <p className="rounded-md border border-line bg-canvas px-3 py-2 text-xs text-ink-muted">{explained.result.ai_status}</p>
                {explained.result.ai && (
                  <div className="rounded-md border border-accent/30 bg-accent/5 p-3">
                    <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-accent">AI assistant (verify before acting)</h3>
                    <Explanation data={explained.result.ai} />
                  </div>
                )}
                <div className="rounded-md border border-line p-3">
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-faint">Built-in explanation</h3>
                  <Explanation data={explained.result.deterministic} />
                </div>
              </div>
            )}
          </Card>
        </div>
      )}

      {tab === "ask" && (
        <Card title={<span className="inline-flex items-center gap-2"><MessageSquare className="h-4 w-4" />Ask about a security concept</span>}>
          <form onSubmit={ask} className="mb-4 flex gap-2">
            <Input aria-label="Question" placeholder="What is the difference between brute force and password spraying?" value={question} onChange={(e) => setQuestion(e.target.value)} />
            <Button type="submit" variant="primary" busy={action.busy}>Ask</Button>
          </form>
          {answer && (
            <div className="space-y-4">
              <p className="text-xs text-ink-muted">{answer.ai_status}</p>
              {answer.ai && <div className="rounded-md border border-accent/30 bg-accent/5 p-3"><Explanation data={answer.ai} /></div>}
              <div className="rounded-md border border-line p-3"><h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-faint">From the built-in glossary</h3><Explanation data={answer.deterministic} /></div>
            </div>
          )}
        </Card>
      )}

      {tab === "glossary" && (
        <Card title={<span className="inline-flex items-center gap-2"><BookOpen className="h-4 w-4" />Security glossary</span>}>
          <Input aria-label="Filter glossary" placeholder="Filter terms" value={filter} onChange={(e) => setFilter(e.target.value)} className="mb-4 max-w-sm" />
          {!glossary.data ? <Spinner /> : (
            <dl className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {glossary.data.filter((g) => `${g.term} ${g.definition}`.toLowerCase().includes(filter.toLowerCase())).map((g) => (
                <div key={g.term} className="rounded-md border border-line bg-canvas p-3"><dt className="font-medium">{g.term}</dt><dd className="mt-1 text-sm text-ink-muted">{g.definition}</dd></div>
              ))}
            </dl>
          )}
        </Card>
      )}
    </div>
  );
}
