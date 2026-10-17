import { API_BASE_URL } from '../config/constants';
import type { ApiError, GenericSuccess, LoginResponse, PasswordValidation, ResetCompletion, ResetRequest } from './types';

export class ApiException extends Error {
  constructor(message: string, readonly status: number, readonly payload?: ApiError) { super(message); this.name = 'ApiException'; }
}

async function request<T>(path: string, body: unknown): Promise<T> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body), signal: controller.signal });
    const payload = await response.json() as T & ApiError;
    if (!response.ok) throw new ApiException(payload.errors?.[0] ?? payload.message ?? 'La demande a échoué.', response.status, payload);
    return payload;
  } catch (error) {
    if (error instanceof ApiException) throw error;
    throw new ApiException(error instanceof DOMException && error.name === 'AbortError' ? 'La demande a expiré.' : 'Le serveur est momentanément indisponible.', 0);
  } finally { window.clearTimeout(timer); }
}

export const api = {
  submitLogin: (values: { username: string; password: string; totp_code?: string; recovery_code?: string }) => request<LoginResponse>('/login', values),
  submitRegistration: (values: { username: string; email: string; password: string; password_confirm: string }) => request<GenericSuccess>('/register', values),
  logout: async () => { const response = await fetch(`${API_BASE_URL}/logout`, { method: 'GET', credentials: 'include', redirect: 'manual' }); return response.status; },
  validatePassword: (password: string, username = '') => request<PasswordValidation>('/api/validate-password', { password, username }),
  requestPasswordReset: (data: ResetRequest) => request<GenericSuccess>('/password-reset', data),
  completePasswordReset: (data: ResetCompletion) => request<GenericSuccess>('/password-reset/confirm', data),
  requestMfaRecovery: () => request<GenericSuccess>('/mfa/recovery/request', {}),
};
