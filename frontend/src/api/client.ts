// Typed API client (prompt 22 §19). Every call resolves to an ApiResult that
// distinguishes loading / success / empty / 404 / 400 / 500 / UNAVAILABLE. HTTP
// 200 is NOT treated as proof that data exists — an empty payload is surfaced as
// `empty`, never as "0 vulnerabilities" when the real state is UNKNOWN.

export type ApiStatus =
  | 'loading'
  | 'success'
  | 'empty'
  | 'not_found'
  | 'bad_request'
  | 'server_error'
  | 'unavailable'
  | 'network_error';

export interface ApiResult<T> {
  status: ApiStatus;
  data: T | null;
  httpStatus: number | null;
  error: string | null;
}

const BASE = '/api/v1';

function isEmpty(data: unknown): boolean {
  if (data === null || data === undefined) return true;
  if (Array.isArray(data)) return data.length === 0;
  if (typeof data === 'object') return Object.keys(data as object).length === 0;
  return false;
}

export async function apiGet<T>(path: string, params?: Record<string, string | number | undefined>): Promise<ApiResult<T>> {
  const url = new URL(BASE + path, window.location.origin);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== '') url.searchParams.set(k, String(v));
    }
  }
  return request<T>(url.toString(), { method: 'GET' });
}

export async function apiPost<T>(path: string, params?: Record<string, string | number | undefined>, body?: unknown): Promise<ApiResult<T>> {
  const url = new URL(BASE + path, window.location.origin);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== '') url.searchParams.set(k, String(v));
    }
  }
  return request<T>(url.toString(), {
    method: 'POST',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
}

export async function apiUpload<T>(path: string, file: File): Promise<ApiResult<T>> {
  const url = new URL(BASE + path, window.location.origin);
  const form = new FormData();
  form.append('file', file, file.name);
  return request<T>(url.toString(), { method: 'POST', body: form });
}

async function request<T>(url: string, init: RequestInit): Promise<ApiResult<T>> {
  let res: Response;
  try {
    res = await fetch(url, init);
  } catch (e) {
    return { status: 'network_error', data: null, httpStatus: null, error: String(e) };
  }
  if (res.status === 404) return { status: 'not_found', data: null, httpStatus: 404, error: 'Not found' };
  if (res.status === 400 || res.status === 409 || res.status === 413 || res.status === 422) {
    const detail = await safeDetail(res);
    return { status: 'bad_request', data: null, httpStatus: res.status, error: detail };
  }
  if (res.status >= 500) return { status: 'server_error', data: null, httpStatus: res.status, error: 'Server error' };
  if (!res.ok) return { status: 'server_error', data: null, httpStatus: res.status, error: `HTTP ${res.status}` };

  let data: T;
  try {
    data = (await res.json()) as T;
  } catch {
    return { status: 'server_error', data: null, httpStatus: res.status, error: 'Invalid JSON' };
  }
  // Success HTTP but no content -> empty (never fabricate a zero/negative fact).
  if (isEmpty(data)) return { status: 'empty', data, httpStatus: res.status, error: null };
  return { status: 'success', data, httpStatus: res.status, error: null };
}

async function safeDetail(res: Response): Promise<string> {
  try {
    const j = await res.json();
    return (j && (j.detail || j.error)) || `HTTP ${res.status}`;
  } catch {
    return `HTTP ${res.status}`;
  }
}
