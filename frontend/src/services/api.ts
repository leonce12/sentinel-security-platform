/**
 * API client.
 *
 * The access token lives only in memory (never localStorage), so a script injected into the
 * page cannot read a stored token later. The refresh token is an HttpOnly cookie that the
 * browser sends only to /api/v1/auth. When a request returns 401 the client refreshes once
 * and retries; concurrent 401s share a single refresh call.
 */

export const API_BASE = "/api/v1";

export class ApiError extends Error {
  status: number;
  code: string;
  details: unknown;

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

let accessToken: string | null = null;
let refreshInFlight: Promise<boolean> | null = null;
let onSessionExpired: (() => void) | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}

export function setSessionExpiredHandler(handler: (() => void) | null) {
  onSessionExpired = handler;
}

async function parseError(response: Response): Promise<ApiError> {
  let body: { error?: { code?: string; message?: string; details?: unknown } } = {};
  try {
    body = await response.json();
  } catch {
    /* non-JSON error body */
  }
  const message =
    body.error?.message ??
    (response.status >= 500 ? "The server could not complete the request." : `Request failed (${response.status})`);
  return new ApiError(response.status, body.error?.code ?? "http_error", message, body.error?.details);
}

export async function refreshSession(): Promise<boolean> {
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      try {
        const response = await fetch(`${API_BASE}/auth/refresh`, { method: "POST", credentials: "same-origin" });
        if (!response.ok) return false;
        const data = await response.json();
        setAccessToken(data.access_token);
        return true;
      } catch {
        return false;
      } finally {
        setTimeout(() => (refreshInFlight = null), 0);
      }
    })();
  }
  return refreshInFlight;
}

type Query = Record<string, string | number | boolean | string[] | null | undefined>;

export function buildQuery(params?: Query): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) value.forEach((v) => search.append(key, v));
    else search.append(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

async function raw(method: string, path: string, body?: unknown, query?: Query, retry = true): Promise<Response> {
  const headers: Record<string, string> = {};
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  let payload: BodyInit | undefined;
  if (body instanceof FormData) payload = body;
  else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}${buildQuery(query)}`, {
      method,
      headers,
      body: payload,
      credentials: "same-origin",
    });
  } catch {
    throw new ApiError(0, "network_error", "Cannot reach the Sentinel API. Check that the backend is running.");
  }
  if (response.status === 401 && retry && !path.startsWith("/auth/")) {
    if (await refreshSession()) return raw(method, path, body, query, false);
    setAccessToken(null);
    onSessionExpired?.();
  }
  if (!response.ok) throw await parseError(response);
  return response;
}

export const api = {
  async get<T>(path: string, query?: Query): Promise<T> {
    return (await raw("GET", path, undefined, query)).json();
  },
  async post<T>(path: string, body?: unknown, query?: Query): Promise<T> {
    return (await raw("POST", path, body ?? {}, query)).json();
  },
  async patch<T>(path: string, body: unknown): Promise<T> {
    return (await raw("PATCH", path, body)).json();
  },
  async upload<T>(path: string, form: FormData): Promise<T> {
    return (await raw("POST", path, form)).json();
  },
  /** Download a file (exports, PDFs) through the authenticated client. */
  async download(path: string, query: Query | undefined, fallbackName: string): Promise<void> {
    const response = await raw("GET", path, undefined, query);
    const blob = await response.blob();
    const disposition = response.headers.get("Content-Disposition") ?? "";
    const match = /filename="([^"]+)"/.exec(disposition);
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = match?.[1] ?? fallbackName;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },
};

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (Array.isArray(error.details) && error.details.length) {
      const items = error.details
        .map((d) => (typeof d === "string" ? d : d && typeof d === "object" && "message" in d ? `${(d as { field?: string }).field ? `${(d as { field?: string }).field}: ` : ""}${(d as { message: string }).message}` : ""))
        .filter(Boolean);
      if (items.length) return `${error.message}: ${items.join("; ")}`;
    }
    return error.message;
  }
  return error instanceof Error ? error.message : "Something went wrong.";
}
