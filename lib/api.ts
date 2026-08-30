function apiRoot() {
  if (typeof window === 'undefined') return '/api';
  return window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:3778/api'
    : '/api';
}

export class ApiError extends Error {
  status: number;
  code?: string;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

export async function api<T>(
  path: string,
  options: RequestInit & { csrfToken?: string } = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  if (options.csrfToken) headers.set('X-CSRF-Token', options.csrfToken);

  let response: Response;
  try {
    response = await fetch(`${apiRoot()}${path}`, {
      ...options,
      headers,
      credentials: 'include',
    });
  } catch {
    throw new ApiError('The local vault service is not running. Start InNasc Vault and try again.', 0, 'SERVICE_OFFLINE');
  }

  if (!response.ok) {
    let payload: { error?: string; code?: string } = {};
    try {
      payload = await response.json();
    } catch {
      // Keep the generic message for non-JSON failures.
    }
    throw new ApiError(payload.error ?? `Request failed (${response.status}).`, response.status, payload.code);
  }

  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export async function downloadFromApi(path: string, body: unknown, csrfToken: string) {
  const response = await fetch(`${apiRoot()}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
    credentials: 'include',
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({})) as { error?: string; code?: string };
    throw new ApiError(payload.error ?? `Download failed (${response.status}).`, response.status, payload.code);
  }
  const blob = await response.blob();
  const disposition = response.headers.get('content-disposition') ?? '';
  const match = disposition.match(/filename="?([^";]+)"?/i);
  const fileName = match?.[1] ?? 'InNasc_Vault_Export.bin';
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  URL.revokeObjectURL(url);
}
