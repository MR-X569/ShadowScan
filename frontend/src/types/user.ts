export interface UserProfile {
  id: number;
  username: string;
  email: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
  is_verified?: boolean;
  created_at?: string;
}
