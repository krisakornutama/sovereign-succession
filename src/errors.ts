/**
 * One error type for everything succession rejects, so callers branch on `code`
 * instead of parsing messages. Every code is a refusal, never a warning: the
 * library has no partial-success path.
 */
export type SuccessionErrorCode =
  | 'invalid-policy'
  | 'invalid-claim'
  | 'invalid-state'
  | 'rollback'
  | 'bad-signature'
  | 'unauthorised'
  | 'not-dormant'
  | 'too-early'
  | 'insufficient-shares'
  | 'unknown-heir'
  | 'heir-revoked'
  | 'duplicate-share'
  | 'bad-share'
  | 'replay'
  | 'receipt-required';

export class SuccessionError extends Error {
  readonly code: SuccessionErrorCode;
  readonly details: Readonly<Record<string, unknown>> | undefined;

  constructor(
    code: SuccessionErrorCode,
    message: string,
    options: { cause?: unknown; details?: Readonly<Record<string, unknown>> } = {}
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'SuccessionError';
    this.code = code;
    this.details = options.details;
  }
}

/** Narrowing helper so tests and callers can assert on `code` without casts. */
export function isSuccessionError(error: unknown): error is SuccessionError {
  return error instanceof SuccessionError;
}
