import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { ApiResult } from '../api/client';

const ok = <T,>(data: T): ApiResult<T> => ({ status: 'success', data, httpStatus: 200, error: null });

const VIEW = {
  status: 'ASSESSMENT_INCONCLUSIVE',
  fingerprint: 'abc123',
  summary: { conclusions: 3, open: 2, blockers: 0, by_decision_state: { SUPPORTED: 1, REQUIRES_REVIEW: 1, INCONCLUSIVE: 1 }, truncated: {} },
  conclusions: [
    { id: 'c-sup', subject_type: 'RUNTIME', subject_ref: 'rt-1', conclusion_type: 'RUNTIME_CORROBORATED',
      decision_state: 'SUPPORTED', confidence: 'HIGH', rule_id: 'R-RT-LIVE-CORROBORATED', rationale: 'LIVE runtime corroborated.',
      evidence: [{ source_layer: 'RUNTIME', evidence_ref: 'rt-1', mode: 'LIVE', provenance: 'RUNTIME_ADB', detail: 'mode=LIVE' }],
      blockers: [], requirements: [], dependencies: [] },
    { id: 'c-rev', subject_type: 'REMEDIATION', subject_ref: 'rem-1', conclusion_type: 'REMEDIATION_REQUIRES_REVIEW',
      decision_state: 'REQUIRES_REVIEW', confidence: 'MEDIUM', rule_id: 'R-REM-REVIEW', rationale: 'review required.',
      evidence: [], blockers: [], requirements: [], dependencies: [] },
    { id: 'c-inc', subject_type: 'NATIVE', subject_ref: 'nd-1', conclusion_type: 'NATIVE_ANALYSIS_UNAVAILABLE',
      decision_state: 'INCONCLUSIVE', confidence: 'LOW', rule_id: 'R-NAT-ELF-ONLY', rationale: 'ELF-only.',
      evidence: [], blockers: [{ blocker: 'UNKNOWN_NATIVE_TARGET', reason: 'unresolved', missing: 'target' }],
      requirements: [], dependencies: [] },
  ],
  note: 'Decision states express evidentiary strength, not exploitability, and are never SAFE/UNSAFE.',
};

vi.mock('../api', () => ({
  getAssessment: vi.fn(() => Promise.resolve(ok(VIEW))),
  buildAssessment: vi.fn(() => Promise.resolve(ok({ status: 'ASSESSMENT_INCONCLUSIVE' }))),
  explainConclusion: vi.fn(() => Promise.resolve(ok({
    ref: 'c-sup', decision_state: 'SUPPORTED',
    chain: [{ step: 'CONCLUSION', detail: 'RUNTIME_CORROBORATED' }, { step: 'RULE', detail: 'R-RT-LIVE-CORROBORATED' }],
    note: 'never exploitability',
  }))),
}));

import { Assessment } from '../pages/Assessment';

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/analysis/A/assessment']}>
      <Routes><Route path="/analysis/:analysisId/assessment" element={<Assessment />} /></Routes>
    </MemoryRouter>,
  );
}

describe('Assessment page (§14)', () => {
  beforeEach(() => vi.clearAllMocks());

  it('renders the overall state as INCONCLUSIVE, never SAFE/UNSAFE', async () => {
    const { container } = renderPage();
    expect(await screen.findAllByText(/INCONCLUSIVE/)).not.toHaveLength(0);
    // the page disclaims SAFE/UNSAFE + exploitability rather than rendering them as verdicts
    expect(screen.getByText(/No SAFE\/UNSAFE/)).toBeInTheDocument();
    // no state badge is a SAFE/UNSAFE/EXPLOITABLE verdict
    const badges = Array.from(container.querySelectorAll('.badge')).map((b) => b.textContent?.toUpperCase());
    for (const label of badges) {
      expect(['SAFE', 'UNSAFE', 'EXPLOITABLE', 'VULNERABLE']).not.toContain(label);
    }
  });

  it('shows conclusions with their decision states and rule ids', async () => {
    renderPage();
    expect(await screen.findByText('RUNTIME_CORROBORATED')).toBeInTheDocument();
    expect(screen.getByText('REMEDIATION_REQUIRES_REVIEW')).toBeInTheDocument();
    expect(screen.getAllByText('R-RT-LIVE-CORROBORATED').length).toBeGreaterThan(0);
  });

  it('opening a conclusion shows LIVE evidence + a no-exploitability note', async () => {
    renderPage();
    const row = await screen.findByText('RUNTIME_CORROBORATED');
    await userEvent.click(row);
    await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument());
    // evidence reference + LIVE mode surfaced
    expect(screen.getAllByText(/LIVE/).length).toBeGreaterThan(0);
    expect(screen.getByText(/not an exploitability|not exploitab|never SAFE\/UNSAFE|not exploitability/i)).toBeInTheDocument();
  });
});
