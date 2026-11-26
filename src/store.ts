import { randomUUID } from 'node:crypto';
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { Receipt, SigningKey } from 'sovereign-attest';
import { SuccessionError } from './errors.js';

/** On-disk layout: one policy, one pointer file, one file per chained receipt. */
export const POLICY_FILE = 'policy.json';
export const STATE_FILE = 'state.json';
export const SYSTEM_KEY_FILE = 'system-key.json';
export const RECEIPTS_DIR = 'receipts';

export interface SuccessionState {
  readonly v: 1;
  readonly policyId: string;
  /** Receipt id of the newest link in the chain, or null before the first receipt. */
  readonly head: string | null;
  /** Claim request ids already consumed, oldest first. Replays are refused from here, not from memory. */
  readonly used: readonly string[];
}

export interface StorePaths {
  readonly dir: string;
  readonly policy: string;
  readonly state: string;
  readonly systemKey: string;
  readonly receipts: string;
}

export function storePaths(dir: string): StorePaths {
  return {
    dir,
    policy: join(dir, POLICY_FILE),
    state: join(dir, STATE_FILE),
    systemKey: join(dir, SYSTEM_KEY_FILE),
    receipts: join(dir, RECEIPTS_DIR),
  };
}

export async function ensureStore(dir: string): Promise<StorePaths> {
  const paths = storePaths(dir);
  await mkdir(paths.receipts, { recursive: true });
  return paths;
}

async function readJson(path: string, code: 'invalid-policy' | 'invalid-state'): Promise<unknown> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (error) {
    if ((error as { code?: string }).code === 'ENOENT') return null;
    throw new SuccessionError(code, `cannot read ${path}`, { cause: error });
  }
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    throw new SuccessionError(code, `${path} is not valid JSON`, { cause: error });
  }
}

/** Write-then-rename: a crash leaves the previous file intact, never a half-written one. */
export async function writeJsonAtomic(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${randomUUID()}`;
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  await rename(tmp, path);
}

export async function loadPolicyFile(dir: string): Promise<unknown> {
  return readJson(storePaths(dir).policy, 'invalid-policy');
}

export async function savePolicyFile(dir: string, policy: unknown): Promise<void> {
  await writeJsonAtomic(storePaths(dir).policy, policy);
}

export async function loadStateFile(dir: string): Promise<SuccessionState | null> {
  const raw = await readJson(storePaths(dir).state, 'invalid-state');
  if (raw === null) return null;
  if (typeof raw !== 'object') {
    throw new SuccessionError('invalid-state', 'state.json must be an object');
  }
  const state = raw as Partial<SuccessionState>;
  if (state.v !== 1) throw new SuccessionError('invalid-state', 'state version must be 1');
  if (typeof state.policyId !== 'string') {
    throw new SuccessionError('invalid-state', 'state.policyId is required');
  }
  if (state.head !== null && typeof state.head !== 'string') {
    throw new SuccessionError('invalid-state', 'state.head must be a receipt id or null');
  }
  const used = state.used ?? [];
  if (!Array.isArray(used) || used.some((id) => typeof id !== 'string')) {
    throw new SuccessionError('invalid-state', 'state.used must be a list of request ids');
  }
  return {
    v: 1,
    policyId: state.policyId,
    head: state.head ?? null,
    used: [...used],
  };
}

export async function saveStateFile(dir: string, state: SuccessionState): Promise<void> {
  await writeJsonAtomic(storePaths(dir).state, state);
}

export function receiptPath(dir: string, id: string): string {
  if (!/^[0-9a-f]{64}$/.test(id)) {
    throw new SuccessionError('invalid-state', `receipt id "${id}" is not a SHA-256 digest`);
  }
  return join(storePaths(dir).receipts, `${id}.json`);
}

export async function saveReceiptFile(dir: string, receipt: Receipt): Promise<void> {
  await writeJsonAtomic(receiptPath(dir, receipt.id), receipt);
}

export async function loadReceiptFile(dir: string, id: string): Promise<Receipt | null> {
  const raw = await readJson(receiptPath(dir, id), 'invalid-state');
  if (raw === null) return null;
  if (typeof raw !== 'object' || typeof (raw as Receipt).id !== 'string') {
    throw new SuccessionError('invalid-state', `receipt file ${id} is not a receipt`);
  }
  return raw as Receipt;
}

/** The system key signs denials and grants, so a claim never needs the owner online. */
export async function loadSystemKey(dir: string): Promise<SigningKey> {
  const raw = await readJson(storePaths(dir).systemKey, 'invalid-state');
  if (raw === null) {
    throw new SuccessionError('invalid-state', 'system key is missing from the store');
  }
  const key = raw as Partial<SigningKey>;
  if (
    typeof key.keyId !== 'string' ||
    typeof key.privateKey !== 'string' ||
    typeof key.publicKey !== 'string' ||
    typeof key.createdAt !== 'number'
  ) {
    throw new SuccessionError('invalid-state', 'system key file is malformed');
  }
  return {
    keyId: key.keyId,
    privateKey: key.privateKey,
    publicKey: key.publicKey,
    createdAt: key.createdAt,
  };
}

export async function saveSystemKey(dir: string, key: SigningKey): Promise<void> {
  const path = storePaths(dir).systemKey;
  await writeJsonAtomic(path, key);
  // The private half is at rest in the store; keep it owner-readable only where the OS allows.
  try {
    await chmod(path, 0o600);
  } catch {
    // Windows and some filesystems have no POSIX mode; the write already succeeded.
  }
}
