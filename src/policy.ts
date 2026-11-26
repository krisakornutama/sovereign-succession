import {
  canonicalJson,
  publicKeyMatches,
  sha256Hex,
  signBytes,
  utf8,
  verifyBytes,
  type SigningKey,
} from 'sovereign-attest';
import { SuccessionError } from './errors.js';

export const POLICY_VERSION = 1 as const;

/** 24 hours in milliseconds. Days are the only unit a policy may express time in. */
export const DAY_MS = 86_400_000;

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export interface Heir {
  readonly id: string;
  readonly publicKey: string;
  readonly label?: string;
}

/** The signed policy body. `policyId` is the SHA-256 of this object's canonical JSON. */
export interface SuccessionPolicyBody {
  readonly v: typeof POLICY_VERSION;
  readonly owner: { readonly keyId: string; readonly publicKey: string };
  /** Every heir ever named, including revoked ones, so history stays auditable. */
  readonly heirs: readonly Heir[];
  readonly revoked: readonly string[];
  /** How many distinct, non-revoked heirs must sign one claim. */
  readonly threshold: number;
  /** Days without an owner heartbeat before the successor window opens. */
  readonly dormantAfterDays: number;
  /** Absolute time-lock (ms): no claim is accepted before this instant, whatever the clock says. */
  readonly notBefore: number | null;
  readonly createdAt: number;
}

export interface SuccessionPolicy {
  readonly body: SuccessionPolicyBody;
  readonly policyId: string;
  readonly sig: string;
}

/** What a caller supplies when creating a policy; ids/defaults are filled in here. */
export interface SuccessionPolicyInput {
  readonly heirs: readonly Heir[];
  readonly threshold: number;
  readonly dormantAfterDays: number;
  readonly notBefore?: number | null;
  readonly createdAt?: number;
}

function fail(message: string, details?: Readonly<Record<string, unknown>>): never {
  throw new SuccessionError('invalid-policy', message, { details });
}

export function assertId(value: unknown, field: string): string {
  if (typeof value !== 'string' || !ID_PATTERN.test(value)) {
    fail(`${field} must be 1-64 characters of letters, digits, dot, dash or underscore`);
  }
  return value;
}

function assertPublicKey(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.trim().startsWith('-----BEGIN PUBLIC KEY-----')) {
    fail(`${field} must be an SPKI PEM public key`);
  }
  // Parsing here means a malformed key is refused at policy time, not at claim time:
  // publicKeyMatches throws unless both sides parse as Ed25519 SPKI keys.
  try {
    publicKeyMatches(value, value);
  } catch {
    fail(`${field} is not a usable Ed25519 public key`);
  }
  return value.trim();
}

function normaliseHeirs(input: unknown): Heir[] {
  if (!Array.isArray(input) || input.length === 0) {
    fail('policy needs at least one heir');
  }
  const seen = new Set<string>();
  const heirs: Heir[] = [];
  for (const raw of input as readonly unknown[]) {
    if (typeof raw !== 'object' || raw === null) fail('each heir must be an object');
    // Cast to unknown-valued fields, not to `Heir`: runtime JSON can violate the type.
    const heir = raw as { id?: unknown; publicKey?: unknown; label?: unknown };
    const id = assertId(heir.id, 'heir.id');
    if (seen.has(id)) fail(`heir id "${id}" appears twice`, { heirId: id });
    seen.add(id);
    const publicKey = assertPublicKey(heir.publicKey, `heir "${id}" publicKey`);
    if (heir.label !== undefined && typeof heir.label !== 'string') {
      fail(`heir "${id}" label must be a string`);
    }
    heirs.push({
      id,
      publicKey,
      ...(heir.label === undefined ? {} : { label: heir.label.slice(0, 120) }),
    });
  }
  heirs.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return heirs;
}

/** Validates and normalises an untrusted policy body (from disk or the wire). */
export function normalisePolicyBody(raw: unknown): SuccessionPolicyBody {
  if (typeof raw !== 'object' || raw === null) fail('policy body must be an object');
  const input = raw as Partial<SuccessionPolicyBody>;

  if (input.v !== POLICY_VERSION) fail(`policy version must be ${POLICY_VERSION}`);
  const owner: unknown = input.owner;
  if (typeof owner !== 'object' || owner === null) fail('policy owner is required');
  const ownerFields = owner as { keyId?: unknown; publicKey?: unknown };
  const keyId = assertId(ownerFields.keyId, 'owner.keyId');
  const publicKey = assertPublicKey(ownerFields.publicKey, 'owner.publicKey');

  const heirs = normaliseHeirs(input.heirs);

  const revokedRaw = input.revoked ?? [];
  if (!Array.isArray(revokedRaw)) fail('policy revoked must be a list of heir ids');
  const ids = new Set(heirs.map((heir) => heir.id));
  const revoked = [...new Set(revokedRaw as readonly string[])].map((id) =>
    assertId(id, 'revoked')
  );
  for (const id of revoked) {
    if (!ids.has(id)) fail(`revoked heir "${id}" is not named in heirs`, { heirId: id });
  }

  const threshold = input.threshold;
  if (typeof threshold !== 'number' || !Number.isInteger(threshold) || threshold < 1) {
    fail('policy threshold must be a positive integer');
  }
  const active = heirs.length - revoked.length;
  if (threshold > active) {
    fail(`threshold ${threshold} exceeds active heirs (${active})`, { threshold, active });
  }

  const days = input.dormantAfterDays;
  if (typeof days !== 'number' || !Number.isInteger(days) || days < 1 || days > 3650) {
    fail('dormantAfterDays must be an integer between 1 and 3650');
  }

  const notBefore = input.notBefore ?? null;
  if (
    notBefore !== null &&
    (typeof notBefore !== 'number' || !Number.isInteger(notBefore) || notBefore <= 0)
  ) {
    fail('notBefore must be a positive epoch-ms integer or null');
  }

  const createdAt = input.createdAt;
  if (typeof createdAt !== 'number' || !Number.isInteger(createdAt) || createdAt <= 0) {
    fail('createdAt must be a positive epoch-ms integer');
  }

  return {
    v: POLICY_VERSION,
    owner: { keyId, publicKey },
    heirs,
    revoked: revoked.sort(),
    threshold,
    dormantAfterDays: days,
    notBefore,
    createdAt,
  };
}

export function policyPayload(body: SuccessionPolicyBody): Uint8Array {
  return utf8(canonicalJson(body));
}

export function policyIdOf(body: SuccessionPolicyBody): string {
  return sha256Hex(canonicalJson(body));
}

/** Remarks the policy with the owner's key; the id is derived, never supplied. */
export function sealPolicy(key: SigningKey, input: SuccessionPolicyInput): SuccessionPolicy {
  const body = normalisePolicyBody({
    v: POLICY_VERSION,
    owner: { keyId: key.keyId, publicKey: key.publicKey },
    heirs: input.heirs,
    revoked: [],
    threshold: input.threshold,
    dormantAfterDays: input.dormantAfterDays,
    notBefore: input.notBefore ?? null,
    createdAt: input.createdAt ?? key.createdAt,
  });
  return {
    body,
    policyId: policyIdOf(body),
    sig: signBytes(key.privateKey, policyPayload(body)),
  };
}

/**
 * Checks a stored or received policy: shape, id, signature, and (when the caller
 * pins one) that the owner is the key it expects. A policy whose signature does not
 * verify is refused before any clock or claim logic runs.
 */
export function openPolicy(input: unknown, trustedOwnerPublicKey?: string): SuccessionPolicyBody {
  if (typeof input !== 'object' || input === null) fail('policy must be an object');
  const raw = input as Partial<SuccessionPolicy>;
  if (typeof raw.policyId !== 'string') fail('policy.policyId is required');
  if (typeof raw.sig !== 'string' || raw.sig.length === 0) fail('policy.sig is required');

  const body = normalisePolicyBody(raw.body);
  const expected = policyIdOf(body);
  if (expected !== raw.policyId) {
    fail(`policy id ${raw.policyId} does not hash its own body (${expected})`);
  }
  if (!verifyBytes(body.owner.publicKey, policyPayload(body), raw.sig)) {
    fail('policy signature does not verify against its own owner key');
  }
  if (trustedOwnerPublicKey !== undefined) {
    let matches = false;
    try {
      matches = publicKeyMatches(trustedOwnerPublicKey, body.owner.publicKey);
    } catch {
      fail('the pinned owner key is not a usable Ed25519 public key');
    }
    if (!matches) {
      throw new SuccessionError('unauthorised', 'policy owner is not the pinned owner key');
    }
  }
  return body;
}

/** Heirs whose share still counts toward the threshold. */
export function activeHeirs(body: SuccessionPolicyBody): readonly Heir[] {
  const revoked = new Set(body.revoked);
  return body.heirs.filter((heir) => !revoked.has(heir.id));
}
