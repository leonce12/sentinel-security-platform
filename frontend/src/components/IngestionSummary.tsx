import { CheckCircle2, XCircle } from "lucide-react";

import type { IngestionJob } from "../types/api";
import { StatusBadge } from "./ui";

export function IngestionSummary({ job }: { job: IngestionJob }) {
  const det = job.detection_summary;
  const ok = job.status === "completed";
  return (
    <div className="space-y-3 text-sm" data-testid="ingestion-summary">
      <div className="flex items-center gap-2">
        {ok ? <CheckCircle2 className="h-5 w-5 text-sev-low" aria-hidden /> : <XCircle className="h-5 w-5 text-sev-critical" aria-hidden />}
        <span className="font-medium">{job.filename ?? job.source_type}</span>
        <StatusBadge status={job.status} />
      </div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
        {[["Received", job.total_records], ["Stored", job.processed_records], ["Rejected", job.rejected_records],
          ["Duplicates", job.duplicate_records], ["Duration", `${job.duration_ms} ms`]].map(([label, value]) => (
          <div key={label as string} className="rounded-md border border-line bg-canvas px-3 py-2">
            <div className="text-xs text-ink-faint">{label}</div>
            <div className="font-semibold tabular-nums">{value}</div>
          </div>
        ))}
      </div>
      {det && (
        <p className="rounded-md border border-line bg-canvas px-3 py-2 text-ink-muted">
          Detection engine evaluated {det.rules_evaluated} rules over {det.events_considered.toLocaleString()} relevant events:{" "}
          <strong className="text-ink">{det.alerts_created} new alert(s)</strong>, {det.alerts_updated} updated with new evidence
          {det.incidents_created ? `, ${det.incidents_created} incident(s) created automatically` : ""}.
        </p>
      )}
      {job.errors.length > 0 && (
        <div>
          <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-ink-faint">Validation errors (records were not stored)</h3>
          <ul className="max-h-40 space-y-1 overflow-y-auto rounded-md border border-line bg-canvas p-2 font-mono text-xs">
            {job.errors.map((e, i) => (
              <li key={i}><span className="text-sev-high">{e.record ? `Record ${e.record}` : "File"}:</span>{" "}
                {e.errors.map((x) => `${x.field}: ${x.message}`).join("; ")}</li>
            ))}
          </ul>
        </div>
      )}
      {job.warnings.length > 0 && (
        <details className="text-xs text-ink-muted">
          <summary className="cursor-pointer">{job.warnings.length} record(s) stored with normalization warnings</summary>
          <ul className="mt-1 max-h-32 overflow-y-auto font-mono">
            {job.warnings.slice(0, 100).map((w, i) => <li key={i}>Record {w.record}: {w.warnings.join("; ")}</li>)}
          </ul>
        </details>
      )}
    </div>
  );
}
