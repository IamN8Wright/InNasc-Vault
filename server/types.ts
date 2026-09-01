import type { Request } from 'express';

import type { Role } from './config.js';

export type UserRow = {
  id: string;
  name: string;
  email: string;
  role: Role;
  password_hash: string;
  kdf_salt: string;
  wrapped_key_nonce: string;
  wrapped_key_ciphertext: string;
  mfa_secret_nonce: string;
  mfa_secret_ciphertext: string;
  mfa_enabled: number;
  failed_login_count: number;
  locked_until: string | null;
  disabled_at: string | null;
  must_change_password: number;
  welcome_sent_at: string | null;
  welcome_send_count: number;
  last_login_at: string | null;
  created_at: string;
  updated_at: string;
};

export type SessionRow = {
  id_hash: string;
  user_id: string;
  csrf_token: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  step_up_until: string | null;
  ip_hash: string | null;
  user_agent: string | null;
};

export type AuthenticatedRequest = Request & {
  auth: {
    session: SessionRow;
    user: UserRow;
    vaultKey: Uint8Array;
  };
};

export type VaultSecret = {
  username: string;
  password: string;
  pin: string;
  apiToken: string;
  licenseKey: string;
  notes: string;
};
