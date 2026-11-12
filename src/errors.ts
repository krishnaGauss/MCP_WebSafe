export type ErrorCode =
  | 'INVALID_URL'
  | 'BLOCKED_DESTINATION'
  | 'DNS_FAILURE'
  | 'FETCH_TIMEOUT'
  | 'FETCH_FAILED'
  | 'NOT_FOUND'
  | 'UNSUPPORTED'
  | 'INTERNAL_ERROR';

export class GeoShieldError extends Error {
  constructor(
    public readonly code: ErrorCode,
    message: string,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'GeoShieldError';
  }

  toJSON(): { code: ErrorCode; message: string; details?: Record<string, unknown> } {
    return { code: this.code, message: this.message, ...(this.details ? { details: this.details } : {}) };
  }
}

export function toGeoShieldError(err: unknown): GeoShieldError {
  if (err instanceof GeoShieldError) return err;
  const cause = err as { name?: string; code?: string; message?: string; cause?: unknown };
  // undici wraps the real reason (e.g. our lookup rejection) in `cause`.
  if (cause?.cause instanceof GeoShieldError) return cause.cause;
  const inner = cause?.cause as { code?: string; message?: string } | undefined;
  const code = inner?.code ?? cause?.code;
  if (cause?.name === 'AbortError' || cause?.name === 'TimeoutError' || code === 'UND_ERR_CONNECT_TIMEOUT' || code === 'UND_ERR_HEADERS_TIMEOUT' || code === 'UND_ERR_BODY_TIMEOUT') {
    return new GeoShieldError('FETCH_TIMEOUT', 'The request timed out.');
  }
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
    return new GeoShieldError('DNS_FAILURE', `The hostname could not be resolved (${code}).`);
  }
  const message = inner?.message ?? cause?.message ?? String(err);
  return new GeoShieldError('FETCH_FAILED', `Request failed: ${message}`);
}
