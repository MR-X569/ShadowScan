export interface LoginRequest {
  identifier?: string;
  email?: string;
  username?: string;
  password: string;
}


export interface RegisterRequest {
  full_name: string;
  username: string;
  email: string;
  password: string;
}

export interface AuthUser {
  id: number | string;
  full_name?: string;
  username?: string;
  email: string;
}

export interface AuthResponse {
  access_token: string;
  token_type?: string;
  user?: AuthUser;
}

export interface VerifyEmailRequest {
  email: string;
  otp: string;
}

export interface ResendOTPRequest {
  email: string;
}

export interface ForgotPasswordRequest {
  email: string;
}

export interface ResetPasswordRequest {
  email: string;
  otp: string;
  password: string;
}
