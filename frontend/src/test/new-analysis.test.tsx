import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { ApiResult } from '../api/client';

const ok = <T,>(data: T): ApiResult<T> => ({ status: 'success', data, httpStatus: 200, error: null });

const { uploadArtifact, createAnalysis } = vi.hoisted(() => ({
  uploadArtifact: vi.fn(),
  createAnalysis: vi.fn(),
}));
vi.mock('../api', () => ({ uploadArtifact, createAnalysis }));

import { NewAnalysis } from '../pages/NewAnalysis';

function file(name: string, bytes = 'PK\x03\x04data') {
  return new File([bytes], name, { type: 'application/octet-stream' });
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/analyses/new']}>
      <Routes>
        <Route path="/analyses/new" element={<NewAnalysis />} />
        <Route path="/progress/execution/:executionId" element={<div>PROGRESS PAGE exec-1</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

function pick(container: HTMLElement, files: File[]) {
  const input = container.querySelector('input[type="file"]') as HTMLInputElement;
  fireEvent.change(input, { target: { files } });
}

describe('New Analysis intake (§14/§15)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    uploadArtifact.mockImplementation((f: File) => Promise.resolve(ok({ id: 'art-' + f.name, artifact_type: 'apk' })));
    createAnalysis.mockResolvedValue(ok({ execution_id: 'exec-1', state: 'QUEUED' }));
  });

  it('classifies a supported artifact by intake type and marks it READY', () => {
    const { container } = renderPage();
    pick(container, [file('Magisk-v29.0.apk')]);
    expect(screen.getByText('Magisk-v29.0.apk')).toBeInTheDocument();
    expect(screen.getByText('APK')).toBeInTheDocument();
    expect(screen.getByText('READY')).toBeInTheDocument();
  });

  it('rejects unsupported extensions and empty files (client hint; backend authoritative)', () => {
    const { container } = renderPage();
    pick(container, [file('evil.txt'), new File([], 'empty.apk')]);
    expect(screen.getByText(/INVALID · unsupported extension/)).toBeInTheDocument();
    expect(screen.getByText(/INVALID · empty file/)).toBeInTheDocument();
  });

  it('supports multiple independent artifacts and removal before submission', async () => {
    const { container } = renderPage();
    pick(container, [file('a.apk'), file('b.apkm')]);
    expect(screen.getByText('a.apk')).toBeInTheDocument();
    expect(screen.getByText('b.apkm')).toBeInTheDocument();
    expect(screen.getByText('APKM')).toBeInTheDocument();
    await userEvent.click(screen.getByLabelText('Remove a.apk'));
    expect(screen.queryByText('a.apk')).toBeNull();
    expect(screen.getByText('b.apkm')).toBeInTheDocument();
  });

  it('Start Analysis uploads + creates via the backend and navigates to progress', async () => {
    const { container } = renderPage();
    pick(container, [file('a.apk')]);
    await userEvent.click(screen.getByRole('button', { name: /Start Analysis/ }));
    await waitFor(() => expect(uploadArtifact).toHaveBeenCalledOnce());
    expect(createAnalysis).toHaveBeenCalledWith('art-a.apk');
    await waitFor(() => expect(screen.getByText(/PROGRESS PAGE exec-1/)).toBeInTheDocument());
  });

  it('Start Analysis is disabled with no valid artifacts', () => {
    const { container } = renderPage();
    pick(container, [file('evil.txt')]);
    // only an INVALID item -> no Start button rendered at all until a valid item exists
    const start = screen.queryByRole('button', { name: /Start Analysis/ });
    if (start) expect(start).toBeDisabled();
  });
});
