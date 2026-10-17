export type ApiError = { success?: false; errors?: string[]; message?: string; locked_until?: string };
export type PasswordValidation = { valid: boolean; errors: string[] };
export type ResetRequest = { identifier: string };
export type ResetCompletion = { token: string; new_password: string; totp_code?: string; recovery_code?: string };
export type GenericSuccess = { success: boolean; message?: string; errors?: string[] };
export type LoginResponse = GenericSuccess & {
  mfa_required?: boolean;
  mfa_enrollment_required?: boolean;
  locked_until?: string;
  user?: { id: number; username: string; email: string; role: string };
};
