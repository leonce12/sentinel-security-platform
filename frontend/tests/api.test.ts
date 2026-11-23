import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, api, buildQuery, errorMessage, setAccessToken } from "../src/services/api";
import { mockFetch } from "./testUtils";

afterEach(() => {
  vi.unstubAllGlobals();
  setAccessToken(null);
});

describe("buildQuery", () => {
  it("skips empty values and repeats arrays", () => {
    expect(buildQuery({ q: "", a: 1, status: ["new", "investigating"], x: undefined, y: null, flag: false }))
      .toBe("?a=1&status=new&status=investigating&flag=false");
    expect(buildQuery({})).toBe("");
  });
});

describe("api client", () => {
  it("sends the bearer token and parses JSON", async () => {
    const calls = mockFetch(() => ({ body: { ok: true } }));
    setAccessToken("abc");
    await expect(api.get("/alerts", { page: 2 })).resolves.toEqual({ ok: true });
    expect(calls[0].url).toBe("/api/v1/alerts?page=2");
    expect((calls[0].init?.headers as Record<string, string>).Authorization).toBe("Bearer abc");
  });

  it("refreshes once on 401 and retries the original request", async () => {
    let first = true;
    const calls = mockFetch((url) => {
      if (url.endsWith("/auth/refresh")) return { body: { access_token: "fresh" } };
      if (first) { first = false; return { status: 401, body: { error: { code: "unauthorized", message: "expired" } } }; }
      return { body: { items: [] } };
    });
    setAccessToken("stale");
    await expect(api.get("/events")).resolves.toEqual({ items: [] });
    expect(calls.map((c) => c.url)).toEqual(["/api/v1/events", "/api/v1/auth/refresh", "/api/v1/events"]);
    expect((calls[2].init?.headers as Record<string, string>).Authorization).toBe("Bearer fresh");
  });

  it("turns backend errors into ApiError with readable messages", async () => {
    mockFetch(() => ({ status: 422, body: { error: { code: "weak_password", message: "Password does not meet the policy", details: ["Too short"] } } }));
    const error = (await api.post("/auth/change-password", {}).catch((e) => e)) as ApiError;
    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBe(422);
    expect(errorMessage(error)).toBe("Password does not meet the policy: Too short");
  });

  it("reports network failures clearly", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("Failed to fetch"); }));
    const error = (await api.get("/health").catch((e) => e)) as ApiError;
    expect(error.code).toBe("network_error");
  });
});
