import { Database, RotateCcw, Save } from "lucide-react";
import { useEffect, useState } from "react";

import { Button, Card, ErrorState, Field, InlineError, Input, Modal, PageHeader, Spinner, TextArea } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";

type Settings = Record<string, unknown>;
interface SettingsResponse {
  settings: Settings;
  environment: { ai_provider: string; ai_provider_configured: boolean; virustotal_configured: boolean; max_upload_mb: number; environment: string };
}

function Toggle({ label, hint, value, onChange }: { label: string; hint?: string; value: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-start gap-3 text-sm">
      <input type="checkbox" checked={value} onChange={(e) => onChange(e.target.checked)} className="mt-1" />
      <span><span className="font-medium">{label}</span>{hint && <span className="block text-xs text-ink-faint">{hint}</span>}</span>
    </label>
  );
}

export default function SettingsPage() {
  const data = useApi(() => api.get<SettingsResponse>("/settings"), []);
  const [draft, setDraft] = useState<Settings>({});
  const [assets, setAssets] = useState("");
  const save = useAction();
  const demo = useAction();
  const [message, setMessage] = useState<string | null>(null);
  const [resetOpen, setResetOpen] = useState(false);
  const [confirm, setConfirm] = useState("");

  useEffect(() => {
    if (data.data) {
      setDraft(data.data.settings);
      setAssets(Object.entries((data.data.settings.asset_criticality as Record<string, string>) ?? {}).map(([k, v]) => `${k}=${v}`).join("\n"));
    }
  }, [data.data]);

  if (data.error) return <ErrorState message={data.error} onRetry={data.reload} />;
  if (!data.data) return <Spinner />;
  const env = data.data.environment;
  const set = (key: string) => (value: unknown) => setDraft((d) => ({ ...d, [key]: value }));

  async function saveSettings() {
    setMessage(null);
    const asset_criticality: Record<string, string> = {};
    for (const line of assets.split("\n").map((l) => l.trim()).filter(Boolean)) {
      const [host, level] = line.split("=").map((s) => s.trim());
      if (!host || !["low", "medium", "high"].includes(level)) return save.setError(`Asset line "${line}" must look like host=low|medium|high`);
      asset_criticality[host] = level;
    }
    const original = data.data!.settings;
    const changes: Settings = {};
    for (const [k, v] of Object.entries({ ...draft, asset_criticality })) {
      if (JSON.stringify(v) !== JSON.stringify(original[k])) changes[k] = v;
    }
    if (!Object.keys(changes).length) return setMessage("No changes to save.");
    const ok = await save.run(() => api.patch("/settings", changes));
    if (ok) { setMessage("Settings saved and recorded in the audit log."); data.reload(); }
  }

  async function loadDemo() {
    setMessage(null);
    const r = await demo.run(() => api.post<{ jobs: { file: string; processed: number; detection: { alerts_created: number } | null }[] }>("/demo/load"));
    if (r) setMessage(`Demo data loaded: ${r.jobs.map((j) => `${j.file} (${j.processed} events, ${j.detection?.alerts_created ?? 0} alerts)`).join(", ")}.`);
  }

  async function resetDemo() {
    const r = await demo.run(() => api.post<Record<string, number>>("/demo/reset", { confirm }));
    if (r) {
      setResetOpen(false);
      setConfirm("");
      setMessage(`Demo data removed: ${r.events_removed} events, ${r.alerts_removed} alerts, ${r.incidents_removed} incidents. Your own records were kept.`);
    }
  }

  const num = (key: string) => Number(draft[key] ?? 0);

  return (
    <div>
      <PageHeader title="Settings" description="Operational settings stored in the database. Secrets such as API keys are configured through environment variables only and are never shown here."
        actions={<Button variant="primary" onClick={saveSettings} busy={save.busy} icon={<Save className="h-4 w-4" />}>Save settings</Button>} />
      {message && <p className="mb-4 rounded-md border border-sev-low/40 bg-sev-low/10 px-3 py-2 text-sm text-sev-low">{message}</p>}
      <InlineError message={save.error ?? demo.error} />
      <div className="mt-2 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Detection and incidents">
          <div className="space-y-4">
            <Toggle label="Run detection automatically after ingestion" value={!!draft.auto_detect_after_ingestion} onChange={set("auto_detect_after_ingestion")} />
            <Toggle label="Create incidents automatically for high-risk alerts" value={!!draft.auto_incident_enabled} onChange={set("auto_incident_enabled")} />
            <div className="grid grid-cols-3 gap-3">
              <Field label="Auto-incident minimum score"><Input type="number" min={0} max={100} value={num("auto_incident_min_score")} onChange={(e) => set("auto_incident_min_score")(Number(e.target.value))} /></Field>
              <Field label="Business hours start (UTC)"><Input type="number" min={0} max={23} value={num("business_hours_start")} onChange={(e) => set("business_hours_start")(Number(e.target.value))} /></Field>
              <Field label="Business hours end (UTC)"><Input type="number" min={1} max={24} value={num("business_hours_end")} onChange={(e) => set("business_hours_end")(Number(e.target.value))} /></Field>
            </div>
            <Field label="Asset importance" hint="One per line: source_system=low|medium|high. Used by the risk score's asset factor.">
              <TextArea value={assets} onChange={(e) => setAssets(e.target.value)} className="font-mono text-xs" placeholder="dc-01.corp.example=high" />
            </Field>
          </div>
        </Card>
        <Card title="Optional services">
          <div className="space-y-4">
            <Toggle label="Allow external threat intelligence lookups (VirusTotal)"
              hint={`Sends only the single public IP being checked. ${env.virustotal_configured ? "API key configured." : "No API key configured: lookups will report unavailable."}`}
              value={!!draft.external_intel_enabled} onChange={set("external_intel_enabled")} />
            <Field label="Threat intelligence cache (hours)"><Input type="number" min={1} max={720} value={num("intel_cache_hours")} onChange={(e) => set("intel_cache_hours")(Number(e.target.value))} className="max-w-[140px]" /></Field>
            <Toggle label="Enable AI assistance"
              hint={env.ai_provider_configured ? `Provider: ${env.ai_provider}. Only minimized, structured alert data is sent.` : "No AI provider configured. Built-in explanations are always available."}
              value={!!draft.ai_enabled} onChange={set("ai_enabled")} />
            <Toggle label="Enable experimental anomaly detection" hint="Isolation Forest over account activity. Advisory only." value={!!draft.anomaly_detection_enabled} onChange={set("anomaly_detection_enabled")} />
            <Field label="Anomaly contamination (expected unusual share)"><Input type="number" min={0.001} max={0.5} step={0.01} value={Number(draft.anomaly_contamination ?? 0.05)} onChange={(e) => set("anomaly_contamination")(Number(e.target.value))} className="max-w-[140px]" /></Field>
          </div>
        </Card>
        <Card title="Access">
          <div className="space-y-4">
            <Toggle label="Allow self-registration" hint="New accounts are inactive viewers until an administrator activates them." value={!!draft.allow_self_registration} onChange={set("allow_self_registration")} />
            <p className="text-sm text-ink-muted">Notifications are in-app only. External email delivery is not part of this release, so nothing is ever sent outside Sentinel.</p>
            <p className="text-sm text-ink-muted">Upload size limit: <span className="font-mono">{env.max_upload_mb} MB</span> (set with the <span className="font-mono">SENTINEL_MAX_UPLOAD_MB</span> environment variable). Environment: <span className="font-mono">{env.environment}</span>.</p>
          </div>
        </Card>
        <Card title="Demonstration data">
          <p className="mb-3 text-sm text-ink-muted">Load the bundled synthetic dataset (fictional users, reserved IP ranges, every record marked synthetic) or remove it again. Resetting never deletes records you created, audit logs or reports.</p>
          <div className="flex flex-wrap gap-2">
            <Button onClick={loadDemo} busy={demo.busy} icon={<Database className="h-4 w-4" />}>Load demo dataset</Button>
            <Button variant="danger" onClick={() => setResetOpen(true)} icon={<RotateCcw className="h-4 w-4" />}>Reset demo data</Button>
          </div>
        </Card>
      </div>
      <Modal title="Reset demonstration data" open={resetOpen} onClose={() => setResetOpen(false)}
        footer={<><Button onClick={() => setResetOpen(false)}>Cancel</Button><Button variant="danger" busy={demo.busy} disabled={confirm !== "RESET DEMO DATA"} onClick={resetDemo}>Reset</Button></>}>
        <p className="text-sm text-ink-muted">This permanently removes synthetic events, the alerts and incidents built only from them, synthetic anomaly results and synthetic intelligence entries.</p>
        <Field label='Type "RESET DEMO DATA" to confirm'><Input value={confirm} onChange={(e) => setConfirm(e.target.value)} /></Field>
        <InlineError message={demo.error} />
      </Modal>
    </div>
  );
}
