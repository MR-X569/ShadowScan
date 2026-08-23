export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';

export interface Scan {
  id: number;
  target_url: string;
  status: ScanStatus;
  risk_score: number | null;
  created_at: string;
}

export interface ScanDetail extends Scan {
  user_id: number;
  completed_at: string | null;
}

export interface ScanCreatePayload {
  target_url: string;
}

export interface Finding {
  id: number;
  scan_id: number;
  vulnerability_name: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string | null;
  recommendation: string | null;
  status: string;
}

export interface ScanStats {
  total: number;
  running: number;
  completed: number;
  failed: number;
}
