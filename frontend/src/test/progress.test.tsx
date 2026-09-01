import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { ApiResult } from '../api/client';

const ok = <T,>(data: T): ApiResult<T> => ({ status: 'success', data, httpStatus: 200, error: null });

const getExecution = vi.fn();
vi.mock('../api', () => ({
  getExecution: (...a: any[]) => getExecution(...a),
  getAnalysisProgress: vi.fn(),
  cancelExecution: vi.fn(),
}));

import { Progress } from '../pages/Progress';

function renderProgress() {
  return render(
    <MemoryRouter initialEntries={['/progress/execution/exec-1']}>
      <Routes>
        <Route path="/progress/execution/:executionId" element={<Progress />} />
        <Route path="/analysis/:analysisId" element={<div>WORKSPACE</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('Analysis progress (§16/§20/§21)', () => {
  beforeEach(() => vi.clearAllMocks());

  it('completed-with-limitations keeps capability absence visible, never "success"', async () => {
    getExecution.mockResolvedValue(ok({
      execution_id: 'exec-1', analysis_id: 'an-1', state: 'COMPLETED_WITH_LIMITATIONS',
      current_stage: null,
      stages: [{ name: 'manifest', status: 'COMPLETE' }, { name: 'ghidra', status: 'SKIPPED' }],
      capability_limitations: [{ capability: 'ghidra', state: 'UNAVAILABLE' }],
      artifact: { package: 'com.topjohnwu.magisk' }, error: null,
    }));
    renderProgress();
    expect(await screen.findByText(/Completed with limitations/i)).toBeInTheDocument();
    expect(screen.getAllByText('ghidra').length).toBeGreaterThan(0);
    expect(screen.getByText('UNAVAILABLE')).toBeInTheDocument();
    // completion offers the existing workspace
    expect(screen.getByRole('link', { name: /Open Analysis Workspace/ })).toHaveAttribute('href', '/analysis/an-1');
  });

  it('failed analysis is shown as failure, not "no findings"', async () => {
    getExecution.mockResolvedValue(ok({
      execution_id: 'exec-1', analysis_id: null, state: 'FAILED', current_stage: 'dex',
      stages: [], capability_limitations: [],
      error: { code: 'RuntimeError', message: 'boom', stage: 'dex', retryable: true }, artifact: {},
    }));
    renderProgress();
    expect(await screen.findByText(/Analysis failed/i)).toBeInTheDocument();
    expect(screen.getByText(/not "no findings"/i)).toBeInTheDocument();
    expect(screen.queryByText(/Open Analysis Workspace/)).toBeNull();
  });

  it('renders real pipeline stages from the backend, marking unreported ones PENDING', async () => {
    getExecution.mockResolvedValue(ok({
      execution_id: 'exec-1', analysis_id: null, state: 'RUNNING', current_stage: 'native',
      stages: [{ name: 'ingest', status: 'COMPLETE' }, { name: 'manifest', status: 'COMPLETE' }],
      capability_limitations: [], error: null, artifact: {},
    }));
    renderProgress();
    await waitFor(() => expect(screen.getByText('ingest')).toBeInTheDocument());
    // a later, not-yet-run stage is PENDING (never fabricated as complete)
    expect(screen.getAllByText('PENDING').length).toBeGreaterThan(0);
    expect(screen.getByText('native')).toBeInTheDocument();
  });
});
