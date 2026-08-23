import { useCallback, useEffect, useState } from 'react';
import { listScans } from '@/services/scans';
import type { Scan, ScanStats } from '@/types/scan';

interface UseScansResult {
  scans: Scan[];
  stats: ScanStats;
  loading: boolean;
  error: string;
  refresh: () => void;
}

function computeStats(scans: Scan[]): ScanStats {
  return {
    total: scans.length,
    running: scans.filter((s) => s.status === 'RUNNING' || s.status === 'PENDING').length,
    completed: scans.filter((s) => s.status === 'COMPLETED').length,
    failed: scans.filter((s) => s.status === 'FAILED').length,
  };
}

/**
 * Fetches the authenticated user's scan list from GET /scans.
 * Exposes a refresh() callback for re-fetching after a new scan is created.
 */
export function useScans(): UseScansResult {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchScans = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await listScans(0, 100);
      setScans(data);
    } catch {
      setError('Failed to load scans. Please try again.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  return {
    scans,
    stats: computeStats(scans),
    loading,
    error,
    refresh: fetchScans,
  };
}
