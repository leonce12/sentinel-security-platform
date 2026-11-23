import { useCallback, useEffect, useRef, useState } from "react";

import { errorMessage } from "../services/api";

/**
 * Load data from the API and track loading/error state.
 * `deps` re-run the loader; `reload()` runs it on demand (for refresh buttons and after actions).
 * Responses that arrive after a newer request started are ignored.
 */
export function useApi<T>(loader: () => Promise<T>, deps: unknown[], options: { pollMs?: number } = {}) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const requestId = useRef(0);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const run = useCallback(loader, deps);

  const reload = useCallback(async () => {
    const id = ++requestId.current;
    setLoading(true);
    try {
      const result = await run();
      if (id === requestId.current) {
        setData(result);
        setError(null);
      }
    } catch (err) {
      if (id === requestId.current) setError(errorMessage(err));
    } finally {
      if (id === requestId.current) setLoading(false);
    }
  }, [run]);

  useEffect(() => {
    reload();
  }, [reload]);

  useEffect(() => {
    if (!options.pollMs) return;
    const timer = setInterval(reload, options.pollMs);
    return () => clearInterval(timer);
  }, [reload, options.pollMs]);

  return { data, error, loading, reload, setData };
}

/** Run a mutating action with busy/error state. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(async <R,>(action: () => Promise<R>): Promise<R | undefined> => {
    setBusy(true);
    setError(null);
    try {
      return await action();
    } catch (err) {
      setError(errorMessage(err));
      return undefined;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, error, run, setError };
}
