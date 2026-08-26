import api from './api';
import type { Scan, ScanDetail, ScanCreatePayload, Finding } from '@/types/scan';

/**
 * POST /scans — Create a new scan for the given target URL.
 * Returns the full ScanDetail of the newly created scan.
 */
export async function createScan(payload: ScanCreatePayload): Promise<ScanDetail> {
  const response = await api.post<ScanDetail>('/scans', payload);
  return response.data;
}

/**
 * GET /scans — List all scans for the authenticated user.
 * Results are ordered newest-first.
 */
export async function listScans(skip = 0, limit = 100): Promise<Scan[]> {
  const response = await api.get<Scan[]>('/scans', { params: { skip, limit } });
  return response.data;
}

/**
 * GET /scans/{scan_id} — Get full details for a single scan.
 */
export async function getScan(scanId: number): Promise<ScanDetail> {
  const response = await api.get<ScanDetail>(`/scans/${scanId}`);
  return response.data;
}

/**
 * GET /scans/{scan_id}/findings — Retrieve findings for a given scan.
 */
export async function getScanFindings(scanId: number): Promise<Finding[]> {
  const response = await api.get<Finding[]>(`/scans/${scanId}/findings`);
  return response.data;
}

/**
 * GET /scans/findings/all — Retrieve all findings across all scans for user.
 */
export async function listAllFindings(): Promise<Finding[]> {
  const response = await api.get<Finding[]>('/scans/findings/all');
  return response.data;
}

/**
 * DELETE /scans/{scan_id} — Delete a scan.
 */
export async function deleteScan(scanId: number): Promise<void> {
  await api.delete(`/scans/${scanId}`);
}

