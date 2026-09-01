import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ModeBadge, StatusBadge } from '../components/StatusBadge';
import { EvidenceItem } from '../components/EvidenceDrawer';
import { DataTable, type Column } from '../components/DataTable';
import { ResultGate } from '../components/States';
import type { ApiResult } from '../api/client';

describe('StatusBadge visual-semantics regressions (§25)', () => {
  it('MOCKED renders visibly as "NOT LIVE EVIDENCE"', () => {
    render(<StatusBadge value="MOCKED" />);
    expect(screen.getByText(/NOT LIVE EVIDENCE/)).toBeInTheDocument();
  });

  it('LIVE and MOCKED get different tones and labels', () => {
    const { container: live } = render(<StatusBadge value="LIVE" />);
    const { container: mocked } = render(<StatusBadge value="MOCKED" />);
    expect(live.querySelector('.tone-live')).toBeTruthy();
    expect(mocked.querySelector('.tone-mocked')).toBeTruthy();
  });

  it('ModeBadge marks MOCKED distinctly from LIVE', () => {
    const { container } = render(<ModeBadge mode="MOCKED" />);
    expect(container.querySelector('[data-mode="MOCKED"]')).toBeTruthy();
    expect(screen.getByText(/NOT LIVE EVIDENCE/)).toBeInTheDocument();
  });

  it('UNKNOWN never renders the word SAFE', () => {
    render(<StatusBadge value="UNKNOWN" />);
    expect(screen.getByText('UNKNOWN')).toBeInTheDocument();
    expect(screen.queryByText(/SAFE/)).toBeNull();
  });

  it('POSSIBLY_AFFECTED never renders as exact AFFECTED', () => {
    render(<StatusBadge value="POSSIBLY_AFFECTED" />);
    expect(screen.getByText('POSSIBLY AFFECTED')).toBeInTheDocument();
    expect(screen.queryByText('AFFECTED', { exact: true })).toBeNull();
  });

  it('NO_LONGER_DETECTED never renders as FIXED', () => {
    render(<StatusBadge value="NO_LONGER_DETECTED" />);
    expect(screen.queryByText('FIXED')).toBeNull();
  });
});

describe('EvidenceItem preserves UNKNOWN for missing provenance (§5/§17)', () => {
  it('missing fields show UNKNOWN, not a placeholder', () => {
    render(<EvidenceItem ev={{ source: 'native', detail: 'imports execl', artifact: null, line: null }} />);
    // At least one field renders UNKNOWN for the missing artifact/line.
    expect(screen.getAllByText('UNKNOWN').length).toBeGreaterThan(0);
    expect(screen.getByText('imports execl')).toBeInTheDocument();
  });

  it('surfaces LIVE/MOCKED on runtime evidence', () => {
    render(<EvidenceItem ev={{ source: 'runtime', detail: 'x', mode: 'MOCKED' }} />);
    expect(screen.getByText(/NOT LIVE EVIDENCE/)).toBeInTheDocument();
  });
});

describe('DataTable deterministic sorting & pagination (§29)', () => {
  interface Row { id: string; n: number }
  const rows: Row[] = [
    { id: 'a', n: 3 }, { id: 'b', n: 1 }, { id: 'c', n: 1 }, { id: 'd', n: 2 },
  ];
  const columns: Column<Row>[] = [
    { key: 'id', header: 'ID', sortValue: (r) => r.id },
    { key: 'n', header: 'N', sortValue: (r) => r.n },
  ];

  it('sorts deterministically with stable tie-break on rowKey', () => {
    render(<DataTable rows={rows} columns={columns} rowKey={(r) => r.id} initialSort={{ key: 'n', dir: 'asc' }} />);
    const cells = screen.getAllByRole('row').slice(1).map((tr) => tr.querySelector('td')?.textContent);
    // n asc: 1 (b), 1 (c) tie -> stable by id, then 2 (d), 3 (a)
    expect(cells).toEqual(['b', 'c', 'd', 'a']);
  });

  it('empty rows show an explicit label, not a blank table', () => {
    render(<DataTable rows={[]} columns={columns} rowKey={(r) => r.id} emptyLabel="NO ROWS" />);
    expect(screen.getByText('NO ROWS')).toBeInTheDocument();
  });
});

describe('ResultGate renders honest states', () => {
  function gate<T>(result: ApiResult<T>) {
    return render(<ResultGate result={result}>{() => <div>DATA</div>}</ResultGate>);
  }
  it('unavailable does not look like empty/zero', () => {
    gate({ status: 'unavailable', data: null, httpStatus: null, error: 'no device' });
    expect(screen.getByText('UNAVAILABLE')).toBeInTheDocument();
    expect(screen.queryByText('DATA')).toBeNull();
  });
  it('empty shows NO DATA, never DATA', () => {
    gate({ status: 'empty', data: [] as any, httpStatus: 200, error: null });
    expect(screen.queryByText('DATA')).toBeNull();
  });
  it('success renders children', () => {
    gate({ status: 'success', data: { x: 1 } as any, httpStatus: 200, error: null });
    expect(screen.getByText('DATA')).toBeInTheDocument();
  });
  it('network error is surfaced as an alert', () => {
    gate({ status: 'network_error', data: null, httpStatus: null, error: 'down' });
    expect(screen.getByRole('alert')).toBeInTheDocument();
  });
});

// hypothesis-does-not-alter-truth regression: the researcher-input helpers target
// only investigation endpoints — never any finding/risk/validation mutation route.
describe('researcher input never targets analytical-truth routes (§15)', () => {
  it('addHypothesis / addNote / pinNode only POST under /investigations', async () => {
    const seen: string[] = [];
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      seen.push(url);
      return Promise.resolve({ status: 201, ok: true, json: async () => ({ ok: true }) } as any);
    }));
    const api = await import('../api');
    await api.addHypothesis('inv1', 'a native path might be reachable');
    await api.addNote('inv1', 'note');
    await api.pinNode('inv1', 'FINDING:x', 'FINDING', 'x');
    for (const u of seen) {
      expect(u).toContain('/api/v1/investigations/inv1/');
      expect(u).not.toMatch(/\/findings\/|\/risk|\/validation\/|\/remediation\//);
    }
  });
});
