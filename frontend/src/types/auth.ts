export interface LoginRequest {
  email: string;
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
