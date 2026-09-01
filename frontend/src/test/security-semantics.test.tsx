import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { stateMeta } from '../lib/semantics';
import { StatusBadge } from '../components/StatusBadge';
import { MetricCard } from '../components/primitives';

// Prompt 25 §26 — explicit security-semantics regression guards for the states
// added/exposed by the final UI milestone. These never collapse to SAFE/UNSAFE
// and never imply exploitability.
describe('assessment & availability semantics never collapse (§26)', () => {
  const forbidden = ['SAFE', 'UNSAFE', 'EXPLOITABLE', 'VULNERABLE'];

  it('no assessment decision state renders as SAFE/UNSAFE/EXPLOITABLE', () => {
    const states = ['CONFIRMED', 'STRONGLY_SUPPORTED', 'SUPPORTED', 'CONDITIONALLY_SUPPORTED',
      'REQUIRES_REVIEW', 'UNVERIFIED', 'BLOCKED', 'INCONCLUSIVE', 'NOT_APPLICABLE', 'SUPERSEDED',
      'ASSESSMENT_CONCLUSIVE', 'ASSESSMENT_INCONCLUSIVE'];
    for (const s of states) {
      const label = stateMeta(s).label.toUpperCase();
      for (const bad of forbidden) expect(label).not.toBe(bad);
    }
  });

  it('assessment INCONCLUSIVE is not UNSAFE', () => {
    expect(stateMeta('ASSESSMENT_INCONCLUSIVE').label).toContain('INCONCLUSIVE');
    expect(stateMeta('ASSESSMENT_INCONCLUSIVE').tone).not.toBe('affirmed');
    expect(stateMeta('ASSESSMENT_INCONCLUSIVE').label).not.toMatch(/UNSAFE/);
  });

  it('assessment SUPPORTED never reads as EXPLOITABLE', () => {
    expect(stateMeta('SUPPORTED').label).not.toMatch(/EXPLOIT/i);
    expect(stateMeta('STRONGLY_SUPPORTED').note ?? '').not.toMatch(/exploitabilit(y|ies)\b(?!\s*verdict)/i);
  });

  it('native API presence is never native reachability', () => {
    render(<StatusBadge value="NATIVE_API_PRESENT" />);
    expect(screen.getByText('NATIVE API PRESENT')).toBeInTheDocument();
    expect(stateMeta('NATIVE_API_PRESENT').note).toMatch(/presence is not reachability/i);
    expect(stateMeta('NATIVE_API_PRESENT').label).not.toBe(stateMeta('REACHED').label);
  });

  it('JNI presence is never invocation', () => {
    expect(stateMeta('JNI_PRESENT').note).toMatch(/presence is not invocation/i);
  });

  it('native analysis unavailable is not zero native activity', () => {
    expect(stateMeta('NATIVE_ANALYSIS_UNAVAILABLE').tone).toBe('unknown');
    expect(stateMeta('ELF_ONLY').note).toMatch(/unavailable/i);
  });

  it('frida-server unavailable never inferred / not zero', () => {
    expect(stateMeta('FRIDA_SERVER_UNAVAILABLE').label).toMatch(/UNAVAILABLE/);
    expect(stateMeta('FRIDA_SERVER_UNAVAILABLE').tone).not.toBe('affirmed');
  });

  it('BLOCKED is not SAFE and explains a missing requirement', () => {
    expect(stateMeta('BLOCKED').note).toMatch(/missing/i);
    expect(stateMeta('BLOCKED').label).not.toMatch(/SAFE/);
  });
});

describe('MetricCard distinguishes UNAVAILABLE from zero (§19)', () => {
  it('an unavailable capability renders UNAVAILABLE, never "0"', () => {
    render(<MetricCard label="CVE intelligence" value={0} unavailable />);
    expect(screen.getByText('UNAVAILABLE')).toBeInTheDocument();
    expect(screen.queryByText('0')).toBeNull();
  });

  it('an available metric renders its real count', () => {
    render(<MetricCard label="Findings" value={17} />);
    expect(screen.getByText('17')).toBeInTheDocument();
    expect(screen.queryByText('UNAVAILABLE')).toBeNull();
  });
});
