import api, { API_BASE_URL } from './api';
import type {
  LoginRequest,
  RegisterRequest,
  AuthResponse,
  VerifyEmailRequest,
  ResendOTPRequest,
  ResetPasswordRequest,
} from '@/types/auth';
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

export async function verifyEmail(data: VerifyEmailRequest): Promise<{ message: string }> {
  const response = await api.post<{ message: string }>('/auth/verify-email', data);
  return response.data;
}

export async function resendVerificationOtp(data: ResendOTPRequest): Promise<{ message: string }> {
  const response = await api.post<{ message: string }>('/auth/resend-otp', data);
  return response.data;
}

export async function requestPasswordResetOtp(data: { email: string }): Promise<{ message: string }> {
  const response = await api.post<{ message: string }>('/auth/forgot-password', data);
  return response.data;
}

export async function verifyResetOtp(data: { email: string; otp: string }): Promise<{ message: string }> {
  const response = await api.post<{ message: string }>('/auth/verify-reset-otp', data);
  return response.data;
}

/**
 * Reset password with OTP.
 */
export async function resetPassword(data: ResetPasswordRequest): Promise<{ message: string }> {
  const response = await api.post<{ message: string }>('/auth/reset-password', data);
  return response.data;
}

/**
 * Change password for authenticated user.
 */
export async function changePassword(data: {
  old_password: string;
  new_password: string;
}): Promise<{ message: string }> {
  const response = await api.post<{ message: string }>('/users/change-password', data);
  return response.data;
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

export function getGoogleLoginUrl(): string {
  return `${API_BASE_URL}/auth/google/login`;
}

export async function exchangeGoogleTokenCookie(): Promise<AuthResponse> {
  const response = await api.post<{ access_token: string; token_type: string }>('/auth/google/token-exchange');
  const { access_token } = response.data;
  localStorage.setItem('token', access_token);
  return { access_token };
}

export async function exchangeGoogleCallback(params: {
  code?: string;
  state?: string;
  error?: string;
}): Promise<AuthResponse> {
  const response = await api.get<{ access_token: string; token_type: string }>('/auth/google/callback', {
    params,
  });
  const { access_token } = response.data;
  localStorage.setItem('token', access_token);
  return { access_token };
}

