import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect } from 'vitest';
import { createSigningKey, type SigningKey } from 'sovereign-attest';
import { DAY_MS } from '../src/policy.js';
import { SuccessionError } from '../src/errors.js';

export const T0 = Date.UTC(2026, 0, 1);
export { DAY_MS };

export function key(keyId: string): SigningKey {
  return createSigningKey(keyId, T0);
}

export function heirKeys(ids: readonly string[] = ['ann', 'bob', 'cy']): SigningKey[] {
  return ids.map((id) => key(id));
}

export async function tempDir(prefix = 'sovereign-succession-'): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

export interface ManualClock {
  readonly now: () => number;
  set(at: number): void;
  add(ms: number): void;
}

export function manualClock(start: number = T0): ManualClock {
  let at = start;
  return {
    now: () => at,
    set: (value: number) => {
      at = value;
    },
    add: (ms: number) => {
      at += ms;
    },
  };
}

/** Asserts the refusal code without leaking the stack trace into the failure message. */
export function expectCode(fn: () => unknown, code: string): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(SuccessionError);
    expect((error as SuccessionError).code).toBe(code);
    return;
  }
  throw new Error(`expected a ${code} refusal, but nothing was thrown`);
}
