import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { ApiResult } from '../api/client';
import type { Finding } from '../api/types';

const ok = <T,>(data: T): ApiResult<T> => ({ status: 'success', data, httpStatus: 200, error: null });
const empty: ApiResult<any> = { status: 'empty', data: {}, httpStatus: 200, error: null };

const FINDINGS: Finding[] = [
  {
    id: 'f-live', rule_id: 'ANDROID-REACH-001', title: 'External input reaches WebView.loadUrl',
    category: 'reachability', severity: 'high', confidence: 'medium', status: 'POTENTIAL',
    component: 'com.x.Web', runtime_status: 'STATIC_RUNTIME_CONFIRMED',
    runtime_validation_state: 'CONFIRMED_RUNTIME_BEHAVIOR', evidence_count: 2,
    validation: { state: 'STATIC_SUPPORTED', confidence: 40, claim_count: 1, evidence_count: 2, blocker_count: 0 },
    evidence: [{ source: 'runtime', detail: 'loadUrl observed', mode: 'LIVE' }],
  },
  {
    id: 'f-mock', rule_id: 'ANDROID-CVE-001', title: 'CVE in dependency',
    category: 'cve', severity: 'medium', confidence: 'low', status: 'POTENTIAL',
    component: 'libssl.so', runtime_status: null,
    runtime_validation_state: 'RUNTIME_INCONCLUSIVE', evidence_count: 1,
    validation: { state: 'UNVERIFIED', confidence: 0, claim_count: 0, evidence_count: 1, blocker_count: 1 },
    evidence: [{ source: 'runtime', detail: 'mocked observation', mode: 'MOCKED' }],
  },
];

vi.mock('../api', () => ({
  getFindings: vi.fn(() => Promise.resolve(ok(FINDINGS))),
  explainFinding: vi.fn(() => Promise.resolve(empty)),
  findingEvidenceChain: vi.fn(() => Promise.resolve(empty)),
}));

import { Findings } from '../pages/Findings';

function renderFindings() {
  return render(
    <MemoryRouter initialEntries={['/analysis/A/findings']}>
      <Routes>
        <Route path="/analysis/:analysisId/findings" element={<Findings />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('Findings explorer (§4)', () => {
  beforeEach(() => vi.clearAllMocks());

  it('renders both findings with their distinct axes', async () => {
    renderFindings();
    expect(await screen.findByText('ANDROID-REACH-001')).toBeInTheDocument();
    expect(screen.getByText('ANDROID-CVE-001')).toBeInTheDocument();
    // runtime axis rendered per row: LIVE-confirmed vs MOCKED-inconclusive
    expect(screen.getByText('CONFIRMED RUNTIME BEHAVIOR')).toBeInTheDocument();
    expect(screen.getByText('RUNTIME INCONCLUSIVE')).toBeInTheDocument();
  });

  it('MOCKED-derived finding never renders as CONFIRMED/LIVE in its row', async () => {
    renderFindings();
    await screen.findByText('ANDROID-CVE-001');
    const row = screen.getByText('ANDROID-CVE-001').closest('tr')!;
    expect(within(row).queryByText('CONFIRMED RUNTIME BEHAVIOR')).toBeNull();
    expect(within(row).getByText('RUNTIME INCONCLUSIVE')).toBeInTheDocument();
  });

  it('filters by runtime state deterministically', async () => {
    renderFindings();
    await screen.findByText('ANDROID-REACH-001');
    const runtimeFilter = screen.getByLabelText('runtime') as HTMLSelectElement;
    await userEvent.selectOptions(runtimeFilter, 'RUNTIME_INCONCLUSIVE');
    expect(screen.queryByText('ANDROID-REACH-001')).toBeNull();
    expect(screen.getByText('ANDROID-CVE-001')).toBeInTheDocument();
  });

  it('opening a finding shows the evidence with its LIVE marker and a no-exploitable note', async () => {
    renderFindings();
    const row = await screen.findByText('ANDROID-REACH-001');
    await userEvent.click(row);
    await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument());
    expect(screen.getByText('loadUrl observed')).toBeInTheDocument();
    expect(screen.getByTestId('no-exploitable-note')).toHaveTextContent(/No exploitability is asserted/i);
  });
});
