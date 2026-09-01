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
 * If requireAuth is true, redirects to /login if no token is found or request fails.
 */
export function useAuth(requireAuth: boolean = false): UseAuthResult {
  const navigate = useNavigate();
  const [user, setUser] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = getToken();
    if (!token) {
      setUser(null);
      setLoading(false);
      if (requireAuth) {
        navigate('/login', { replace: true });
      }
      return;
    }

    getCurrentUser()
      .then((profile) => {
        setUser(profile);
      })
      .catch(() => {
        setUser(null);
        if (requireAuth) {
          navigate('/login', { replace: true });
        }
      })
      .finally(() => {
        setLoading(false);
      });
  }, [navigate, requireAuth]);

  return { user, loading };
}
