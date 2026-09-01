import { useEffect, useState } from 'react';
import type { ApiResult } from '../api/client';

// Runs an ApiResult-returning loader and tracks loading/result. HTTP success is
// never assumed to mean data exists — the ApiResult carries `empty` explicitly.
export function useApi<T>(loader: () => Promise<ApiResult<T>>, deps: unknown[] = []): {
  result: ApiResult<T>;
  reload: () => void;
} {
  const [result, setResult] = useState<ApiResult<T>>({ status: 'loading', data: null, httpStatus: null, error: null });
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let alive = true;
    setResult({ status: 'loading', data: null, httpStatus: null, error: null });
    loader().then((r) => {
      if (alive) setResult(r);
    });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  return { result, reload: () => setNonce((n) => n + 1) };
}
