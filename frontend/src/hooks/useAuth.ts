import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getCurrentUser, getToken } from '@/services/auth';
import type { UserProfile } from '@/types/user';

interface UseAuthResult {
  user: UserProfile | null;
  loading: boolean;
}

/**
 * Fetches the current authenticated user from GET /users/me.
 * Redirects to /login if no token is found or if the request fails (401).
 */
export function useAuth(): UseAuthResult {
  const navigate = useNavigate();
  const [user, setUser] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = getToken();
    if (!token) {
      navigate('/login', { replace: true });
      return;
    }

    getCurrentUser()
      .then((profile) => {
        setUser(profile);
      })
      .catch(() => {
        navigate('/login', { replace: true });
      })
      .finally(() => {
        setLoading(false);
      });
  }, [navigate]);

  return { user, loading };
}
