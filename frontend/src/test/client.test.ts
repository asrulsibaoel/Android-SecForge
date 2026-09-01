import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiGet } from '../api/client';

function mockFetch(status: number, body: unknown) {
  return vi.fn().mockResolvedValue({
    status,
    ok: status >= 200 && status < 300,
    json: async () => body,
  } as unknown as Response);
}

describe('api client honesty (§19)', () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it('HTTP 200 with an empty array is `empty`, not `success` (never "0")', async () => {
    vi.stubGlobal('fetch', mockFetch(200, []));
    const r = await apiGet('/analysis/x/cve');
    expect(r.status).toBe('empty');
  });

  it('HTTP 200 with data is success', async () => {
    vi.stubGlobal('fetch', mockFetch(200, [{ id: 1 }]));
    const r = await apiGet('/analyses');
    expect(r.status).toBe('success');
    expect(r.data).toEqual([{ id: 1 }]);
  });

  it('404 is not_found', async () => {
    vi.stubGlobal('fetch', mockFetch(404, { detail: 'x' }));
    const r = await apiGet('/analysis/none');
    expect(r.status).toBe('not_found');
  });

  it('400 surfaces the backend detail', async () => {
    vi.stubGlobal('fetch', mockFetch(400, { detail: 'unknown query' }));
    const r = await apiGet('/analysis/x/graph/query');
    expect(r.status).toBe('bad_request');
    expect(r.error).toBe('unknown query');
  });

  it('500 is server_error', async () => {
    vi.stubGlobal('fetch', mockFetch(500, {}));
    const r = await apiGet('/analysis/x');
    expect(r.status).toBe('server_error');
  });

  it('network failure is network_error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('down')));
    const r = await apiGet('/analyses');
    expect(r.status).toBe('network_error');
  });

  it('empty object is `empty` (a capability with no rows is not a clean pass)', async () => {
    vi.stubGlobal('fetch', mockFetch(200, {}));
    const r = await apiGet('/analysis/x/runtime/validation');
    expect(r.status).toBe('empty');
  });
});
