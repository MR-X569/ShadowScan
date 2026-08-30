import api from './api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AdminStats {
  total_users: number;
  verified_users: number;
  total_scans: number;
  scans_running: number;
  scans_completed: number;
  scans_failed: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  latest_scans: AdminLatestScan[];
  latest_users: AdminLatestUser[];
}

export interface AdminLatestScan {
  id: number;
  target_url: string;
  status: string;
  risk_score: number | null;
  created_at: string | null;
  username: string;
}

export interface AdminLatestUser {
  id: number;
  username: string;
  email: string;
  is_verified: boolean;
  created_at: string | null;
}

export interface AdminUser {
  id: number;
  username: string;
  email: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
  is_verified: boolean;
  created_at: string | null;
}

export interface AdminScan {
  id: number;
  target_url: string;
  status: string;
  risk_score: number | null;
  created_at: string | null;
  completed_at: string | null;
  username: string;
}

export interface AdminFinding {
  id: number;
  scan_id: number;
  vulnerability_name: string;
  plugin: string | null;
  severity: string;
  description: string | null;
  target_url: string;
  created_at: string | null;
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

export async function getAdminStats(): Promise<AdminStats> {
  const res = await api.get<AdminStats>('/admin/stats');
  return res.data;
}

export async function getAdminUsers(): Promise<AdminUser[]> {
  const res = await api.get<AdminUser[]>('/admin/users');
  return res.data;
}

export async function getAdminScans(): Promise<AdminScan[]> {
  const res = await api.get<AdminScan[]>('/admin/scans');
  return res.data;
}

export async function getAdminFindings(): Promise<AdminFinding[]> {
  const res = await api.get<AdminFinding[]>('/admin/findings');
  return res.data;
}

export async function disableUser(userId: number): Promise<{ detail: string }> {
  const res = await api.put<{ detail: string }>(`/admin/users/${userId}/disable`);
  return res.data;
}

export async function enableUser(userId: number): Promise<{ detail: string }> {
  const res = await api.put<{ detail: string }>(`/admin/users/${userId}/enable`);
  return res.data;
}

export async function deleteUser(userId: number): Promise<{ detail: string }> {
  const res = await api.delete<{ detail: string }>(`/admin/users/${userId}`);
  return res.data;
}
