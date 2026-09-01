import { describe, expect, it } from 'vitest';
import { priorityMeta, severityMeta, stateMeta } from '../lib/semantics';

// Explicit regression guards for the strict visual-semantics rules (§21/§25).
describe('security semantics never collapse states', () => {
  const forbidden = ['SAFE', 'UNSAFE', 'VULNERABLE', 'NOT VULNERABLE', 'EXPLOITABLE'];

  it('no state ever renders as SAFE/UNSAFE/EXPLOITABLE', () => {
    const samples = [
      'UNKNOWN', 'NOT_OBSERVED', 'NOT_REACHABLE', 'POSSIBLY_AFFECTED', 'NO_LONGER_DETECTED',
      'MOCKED', 'LIVE', 'UNAVAILABLE', 'INCONCLUSIVE', 'VALIDATION_BLOCKED', 'UNVERIFIED',
      'STATIC_SUPPORTED', 'RUNTIME_CORROBORATED', 'MULTI_SOURCE_CORROBORATED', 'AFFECTED', 'NOT_AFFECTED',
      'NATIVE_API_PRESENT', 'NATIVE_CALL_CHAIN_REACHES_API', 'UNKNOWN_NATIVE_TARGET', 'ELF_ONLY',
    ];
    for (const s of samples) {
      const label = stateMeta(s).label.toUpperCase();
      for (const bad of forbidden) expect(label).not.toBe(bad);
    }
  });

  it('MOCKED is permanently distinct from LIVE', () => {
    const mocked = stateMeta('MOCKED');
    const live = stateMeta('LIVE');
    expect(mocked.label).toContain('NOT LIVE');
    expect(mocked.label).not.toBe(live.label);
    expect(mocked.tone).toBe('mocked');
    expect(live.tone).toBe('live');
    expect(mocked.tone).not.toBe(live.tone);
  });

  it('UNKNOWN is distinct from NOT_FOUND and never SAFE', () => {
    expect(stateMeta('UNKNOWN').label).toBe('UNKNOWN');
    expect(stateMeta('NOT_FOUND').label).toBe('NOT FOUND');
    expect(stateMeta('UNKNOWN').label).not.toBe(stateMeta('NOT_FOUND').label);
  });

  it('POSSIBLY_AFFECTED never renders as AFFECTED', () => {
    const pa = stateMeta('POSSIBLY_AFFECTED');
    expect(pa.label).toBe('POSSIBLY AFFECTED');
    expect(pa.label).not.toBe(stateMeta('AFFECTED').label);
    expect(pa.note).toMatch(/NOT the same as AFFECTED/i);
  });

  it('NO_LONGER_DETECTED never renders as FIXED', () => {
    const nld = stateMeta('NO_LONGER_DETECTED');
    expect(nld.label).not.toBe('FIXED');
    expect(nld.note).toMatch(/not the same as FIXED/i);
  });

  it('NOT_OBSERVED / NOT_REACHABLE carry a "not safe" clarification', () => {
    expect(stateMeta('NOT_OBSERVED').note).toMatch(/not mean SAFE/i);
    expect(stateMeta('NOT_REACHABLE').note).toMatch(/does not mean SAFE/i);
  });

  it('native presence is distinct from reachability', () => {
    expect(stateMeta('NATIVE_API_PRESENT').label).not.toBe(stateMeta('NATIVE_CALL_CHAIN_REACHES_API').label);
  });

  it('severity and priority are separate axes with their own scales', () => {
    expect(severityMeta('high').label).toBe('HIGH');
    expect(priorityMeta('HIGH').label).toBe('HIGH');
    // an anti-analysis INDICATOR must not read as confirmed behavior
    expect(stateMeta('INDICATOR').note).toMatch(/does not prove/i);
  });

  it('unknown tokens are shown verbatim, never invented', () => {
    expect(stateMeta('SOME_FUTURE_STATE').label).toBe('SOME_FUTURE_STATE');
    expect(stateMeta(null).label).toBe('UNKNOWN');
  });
});
