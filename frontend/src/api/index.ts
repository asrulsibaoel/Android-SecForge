// Typed API modules (prompt 22 §19). Each function maps to an existing backend
// endpoint under /api/v1 and returns an ApiResult. No business logic is
// duplicated here — these are thin, typed transports over the canonical backend.

import { apiGet, apiPost, apiUpload, ApiResult } from './client';
import type {
  AnalysisListItem, AnalysisReport, DoctorReport, Finding, KnowledgeGraph,
  RemediationItem, RuntimeValidationView, ValidationClaim, Comparison,
} from './types';

// --- dashboard / doctor ---
export const listAnalyses = (limit = 50) => apiGet<AnalysisListItem[]>('/analyses', { limit });
export const getDoctor = () => apiGet<DoctorReport>('/doctor');

// --- web intake & execution (prompt 26) ---
export const uploadArtifact = (file: File) => apiUpload<any>('/apk/import', file);
export const createAnalysis = (artifactId: string) => apiPost<any>('/analyses', { artifact_id: artifactId });
export const getExecution = (executionId: string) => apiGet<any>(`/analysis/execution/${executionId}`);
export const getAnalysisProgress = (analysisId: string) => apiGet<any>(`/analysis/${analysisId}/progress`);
export const cancelExecution = (executionId: string) => apiPost<any>(`/analysis/execution/${executionId}/cancel`);

// --- analysis ---
export const getAnalysis = (id: string) => apiGet<AnalysisReport>(`/analysis/${id}`);
export const getFindings = (id: string) => apiGet<Finding[]>(`/analysis/${id}/findings`);
export const getRisk = (id: string) => apiGet<any>(`/analysis/${id}/risk`);
export const getRootCauses = (id: string) => apiGet<any[]>(`/analysis/${id}/root-causes`);
export const getAttackSurface = (id: string) => apiGet<any[]>(`/analysis/${id}/attack-surface`);

// --- explanations (WHY) ---
export const explainFinding = (findingId: string) => apiGet<any>(`/findings/${findingId}/explain`);
export const findingEvidenceChain = (findingId: string) => apiGet<any>(`/findings/${findingId}/evidence-chain`);
export const exploreFinding = (findingId: string) => apiGet<any>(`/findings/${findingId}/explore`);

// --- cve intelligence ---
export const getCve = (id: string) => apiGet<any[]>(`/analysis/${id}/cve`);
export const explainAnalysisCve = (id: string, matchId: string) => apiGet<any>(`/analysis/${id}/cve/${matchId}/explain`);
export const getCveRecord = (cveId: string) => apiGet<any>(`/cve/${cveId}`);
export const explainCve = (cveId: string) => apiGet<any>(`/cve/${cveId}/explain`);
export const cveProviders = () => apiGet<any>('/cve/providers');

// --- remediation ---
export const getRemediation = (id: string) => apiGet<{ items: RemediationItem[]; summary: any; note?: string }>(`/analysis/${id}/remediation`);
export const explainRemediation = (id: string, itemId: string) => apiGet<any>(`/analysis/${id}/remediation/${itemId}/explain`);

// --- validation ---
export const getValidationClaims = (id: string) => apiGet<ValidationClaim[]>(`/analysis/${id}/validation/claims`);
export const getValidationSummary = (id: string) => apiGet<any>(`/analysis/${id}/validation/summary`);
export const getValidationBlockers = (id: string) => apiGet<any[]>(`/analysis/${id}/validation/blockers`);
export const explainClaim = (id: string, claimId: string) => apiGet<any>(`/analysis/${id}/validation/${claimId}/explain`);

// --- runtime ---
export const getRuntimeValidation = (id: string) => apiGet<RuntimeValidationView>(`/analysis/${id}/runtime/validation`);
export const getDeviceCapability = (serial?: string) => apiGet<any>('/runtime/device', serial ? { serial } : undefined);
export const getRuntimeCorrelations = (id: string) => apiGet<any[]>(`/analysis/${id}/runtime/correlations`);
export const getRuntime = (id: string) => apiGet<any>(`/analysis/${id}/runtime`);
export const explainRuntime = (id: string, subject: string) => apiGet<any>(`/analysis/${id}/runtime/explain/${encodeURIComponent(subject)}`);
// Explicit, user-triggered correlation build (read of already-persisted runtime evidence).
export const buildRuntimeCorrelation = (id: string) => apiPost<any>(`/analysis/${id}/runtime/correlate`);

// --- native / deep native ---
export const getNative = (id: string) => apiGet<any>(`/analysis/${id}/native`);
export const getNativeBinaries = (id: string) => apiGet<any[]>(`/analysis/${id}/native/binaries`);
export const getNativeFunctions = (id: string) => apiGet<any[]>(`/analysis/${id}/native/functions`);
export const getNativeJni = (id: string) => apiGet<any[]>(`/analysis/${id}/native/jni`);
export const explainNative = (id: string, target: string) => apiGet<any>(`/analysis/${id}/native/explain/${encodeURIComponent(target)}`);

// --- obfuscation ---
export const getObfuscationSummary = (id: string) => apiGet<any>(`/analysis/${id}/obfuscation/summary`);
export const getObfuscation = (id: string) => apiGet<any>(`/analysis/${id}/obfuscation`);
export const getObfuscationObservations = (id: string) => apiGet<any[]>(`/analysis/${id}/obfuscation/observations`);
export const getObfuscationAnti = (id: string) => apiGet<any[]>(`/analysis/${id}/obfuscation/anti-analysis`);
export const getObfuscationImpacts = (id: string) => apiGet<any[]>(`/analysis/${id}/obfuscation/impacts`);

// --- graph ---
export const getKnowledgeGraph = (id: string) => apiGet<KnowledgeGraph>(`/analysis/${id}/graph/knowledge`);
export const getGraphSnapshot = (id: string) => apiGet<any>(`/analysis/${id}/graph/snapshot`);
export const runGraphQuery = (id: string, name: string) => apiGet<any>(`/analysis/${id}/graph/query`, { name });
export const graphExportUrl = (id: string, format: string) => `/api/v1/analysis/${id}/graph/export?format=${encodeURIComponent(format)}`;

// --- diff ---
export const getComparison = (cmpId: string) => apiGet<Comparison>(`/diff/${cmpId}`);
export const getComparisonSummary = (cmpId: string) => apiGet<any>(`/diff/${cmpId}/summary`);
export const getComparisonChanges = (cmpId: string) => apiGet<any[]>(`/diff/${cmpId}/changes`);
export const getComparisonRuntime = (cmpId: string) => apiGet<any>(`/diff/${cmpId}/runtime`);
export const getComparisonNative = (cmpId: string) => apiGet<any>(`/diff/${cmpId}/native`);
export const createComparison = (baseline: string, candidate: string) => apiPost<any>('/diff', { baseline, candidate });

// --- assessment / decision intelligence (prompt 24) ---
export const getAssessment = (id: string) => apiGet<any>(`/analysis/${id}/assessment`);
export const buildAssessment = (id: string) => apiPost<any>(`/analysis/${id}/assessment`);
export const getAssessmentConclusions = (id: string, state?: string) =>
  apiGet<any[]>(`/analysis/${id}/assessment/conclusions`, state ? { state } : undefined);
export const explainConclusion = (id: string, ref: string) =>
  apiGet<any>(`/analysis/${id}/assessment/explain/${encodeURIComponent(ref)}`);

// --- investigation ---
export const listInvestigations = () => apiGet<any[]>('/investigations');
export const getInvestigation = (invId: string) => apiGet<any>(`/investigations/${invId}`);
export const getInvestigationTimeline = (invId: string) => apiGet<any[]>(`/investigations/${invId}/timeline`);
export const getInvestigationGraph = (invId: string) => apiGet<any>(`/investigations/${invId}/graph`);
export const getInvestigationFindings = (invId: string) => apiGet<any[]>(`/investigations/${invId}/findings`);
export const createInvestigation = (analysisId: string, name?: string) =>
  apiPost<any>('/investigations', { analysis_id: analysisId, name });
export const pinNode = (invId: string, nodeRef: string, nodeType?: string, label?: string) =>
  apiPost<any>(`/investigations/${invId}/nodes`, { node_ref: nodeRef, node_type: nodeType, label });
export const addNote = (invId: string, body: string) => apiPost<any>(`/investigations/${invId}/notes`, { body });
export const addHypothesis = (invId: string, statement: string) =>
  apiPost<any>(`/investigations/${invId}/hypotheses`, { statement });
export const investigationExportUrl = (invId: string, format: string) =>
  `/api/v1/investigations/${invId}/export?format=${encodeURIComponent(format)}`;

export type { ApiResult };
