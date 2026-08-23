import api from './api';
import type { LoginRequest, RegisterRequest, AuthResponse } from '@/types/auth';
import type { UserProfile } from '@/types/user';

/**
 * Login — the backend uses OAuth2PasswordRequestForm which expects
 * application/x-www-form-urlencoded with "username" and "password" fields.
 * The "username" field accepts the user's email address.
 */
export async function login(data: LoginRequest): Promise<AuthResponse> {
  const formData = new URLSearchParams();
  formData.append('username', data.email);
  formData.append('password', data.password);

  const response = await api.post<{ access_token: string; token_type: string }>(
    '/auth/login',
    formData,
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );

  const { access_token } = response.data;
  localStorage.setItem('token', access_token);

  return { access_token };
}

export async function register(data: RegisterRequest): Promise<void> {
  await api.post('/auth/register', data);
}

export async function getCurrentUser(): Promise<UserProfile> {
  const response = await api.get<UserProfile>('/users/me');
  return response.data;
}

export function logout(): void {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
}

export function getToken(): string | null {
  return localStorage.getItem('token');
}
