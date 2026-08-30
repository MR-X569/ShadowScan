import api from './api';
import type {
  AIStatus,
  ScanAIAnalysis,
  FindingAIExplanation,
  AIChatResponse,
  AIChatMessage,
} from '@/types/ai';

/**
 * GET /ai/status — Check if Ollama AI engine is enabled and reachable.
 */
export async function getAIStatus(): Promise<AIStatus> {
  const response = await api.get<AIStatus>('/ai/status');
  return response.data;
}

/**
 * GET /scans/{scan_id}/ai/analysis — Retrieve structured AI analysis for a scan.
 */
export async function getScanAIAnalysis(scanId: number): Promise<ScanAIAnalysis> {
  const response = await api.get<ScanAIAnalysis>(`/scans/${scanId}/ai/analysis`);
  return response.data;
}

/**
 * POST /scans/{scan_id}/ai/analysis — Trigger/refresh AI analysis for a scan.
 */
export async function generateScanAIAnalysis(scanId: number): Promise<ScanAIAnalysis> {
  const response = await api.post<ScanAIAnalysis>(`/scans/${scanId}/ai/analysis`);
  return response.data;
}

/**
 * POST /scans/{scan_id}/ai/findings/{finding_id}/explain — Explain a finding with AI.
 */
export async function explainFindingWithAI(
  scanId: number,
  findingId: number
): Promise<FindingAIExplanation> {
  const response = await api.post<FindingAIExplanation>(
    `/scans/${scanId}/ai/findings/${findingId}/explain`
  );
  return response.data;
}

/**
 * POST /scans/{scan_id}/ai/chat — Send a query to the scan-scoped security chat.
 */
export async function sendAIChat(
  scanId: number,
  message: string,
  history: AIChatMessage[] = []
): Promise<AIChatResponse> {
  const response = await api.post<AIChatResponse>(`/scans/${scanId}/ai/chat`, {
    message,
    history,
  });
  return response.data;
}
