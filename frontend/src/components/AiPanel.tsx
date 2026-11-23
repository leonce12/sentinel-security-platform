import { Bot, Sparkles } from "lucide-react";
import { useState } from "react";

import { useAction } from "../hooks/useApi";
import { api } from "../services/api";
import type { AiExplanation, AiResponse } from "../types/api";
import { Button, Card, InlineError } from "./ui";

function List({ title, items }: { title: string; items?: string[] }) {
  if (!items?.length) return null;
  return (
    <div>
      <h4 className="mb-1 text-xs font-medium uppercase tracking-wide text-ink-faint">{title}</h4>
      <ul className="list-disc space-y-1 pl-5 text-sm text-ink-muted">{items.map((item, i) => <li key={i}>{item}</li>)}</ul>
    </div>
  );
}

/** Rendered as plain text only. AI output is never interpreted as HTML. */
export function Explanation({ data }: { data: AiExplanation }) {
  return (
    <div className="space-y-3">
      <p className="text-sm">{data.summary}</p>
      {data.answer && <p className="text-sm text-ink-muted">{data.answer}</p>}
      <List title={data.what_happened ? "What happened" : "Facts"} items={data.what_happened ?? data.facts} />
      <List title="Risk score" items={data.risk_score_meaning} />
      <List title="Details" items={data.details} />
      <List title="Assumptions" items={data.assumptions} />
      <List title="Missing information" items={data.missing_information} />
      <List title="Recommended investigation steps" items={data.recommended_steps} />
      <List title="Possible legitimate explanations" items={data.false_positive_considerations} />
      {data.matches && data.matches.length > 1 && (
        <List title="Related glossary terms" items={data.matches.slice(1).map((m) => `${m.term}: ${m.definition}`)} />
      )}
    </div>
  );
}

export function AiPanel({ path, title }: { path: string; title: string }) {
  const [result, setResult] = useState<AiResponse | null>(null);
  const action = useAction();
  return (
    <Card title={<span className="inline-flex items-center gap-2"><Bot className="h-4 w-4 text-accent" />{title}</span>}
      actions={<Button onClick={async () => { const r = await action.run(() => api.post<AiResponse>(path)); if (r) setResult(r); }}
        busy={action.busy} icon={<Sparkles className="h-4 w-4" />}>{result ? "Regenerate" : "Explain"}</Button>}>
      <InlineError message={action.error} />
      {!result ? (
        <p className="text-sm text-ink-muted">Generate an explanation of the stored evidence. Explanations are read-only: they cannot change alerts, scores, rules or incidents.</p>
      ) : (
        <div className="space-y-4">
          <p className="rounded-md border border-line bg-canvas px-3 py-2 text-xs text-ink-muted">{result.ai_status}</p>
          {result.ai && (
            <div className="rounded-md border border-accent/30 bg-accent/5 p-3">
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-accent">AI assistant (verify before acting)</h3>
              <Explanation data={result.ai} />
            </div>
          )}
          <div className="rounded-md border border-line p-3">
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-faint">Built-in explanation (from stored data and rule definitions)</h3>
            <Explanation data={result.deterministic} />
          </div>
        </div>
      )}
    </Card>
  );
}
