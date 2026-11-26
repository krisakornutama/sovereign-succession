import { canonicalJson, sha256Hex, utf8, verifyBytes } from 'sovereign-attest';
import type { SuccessionStatus } from './clock.js';
import { SuccessionError, type SuccessionErrorCode } from './errors.js';
import { activeHeirs, type Heir, type SuccessionPolicyBody } from './policy.js';

/** Domain separator: a share signed for anything else cannot be replayed as a claim. */
export const CLAIM_KIND = 'succession.access.claim';
export const CUSTODY_KIND = 'succession.custody';

const REQUEST_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$/;

export interface ClaimShare {
  readonly heirId: string;
  /** Ed25519 signature (base64) by the heir's key over {@link claimPayload}. */
  readonly sig: string;
}

export interface ClaimInput {
  /** Caller-chosen id, unique per request; a reused id is refused as a replay. */
  readonly requestId: string;
  /** The instant the claim is evaluated at. Never "whatever the machine clock says". */
  readonly at: number;
  readonly shares: readonly ClaimShare[];
  readonly purpose?: string;
}

export interface ClaimEvaluation {
  readonly ok: boolean;
  /** Heirs whose shares verified, sorted; empty on refusal. */
  readonly holders: readonly string[];
  readonly code: SuccessionErrorCode | null;
  readonly reason: string | null;
}

export interface EvaluateInput {
  readonly policy: SuccessionPolicyBody;
  /** Status computed at `claim.at`, so a stale or future claim cannot borrow another window. */
  readonly status: SuccessionStatus;
  readonly used: readonly string[];
  readonly claim: ClaimInput;
}

/** The exact bytes every heir signs. Same policy, request and instant ⇒ same bytes on every machine. */
export function claimPayload(policyId: string, requestId: string, at: number): Uint8Array {
  return utf8(canonicalJson({ kind: CLAIM_KIND, policyId, requestId, at }));
}

/**
 * A handle the granting machine keeps so the heir can quote one value later.
 * It is deliberately **not** a key: M1 decides access and proves it, it does not unwrap data.
 */
export function custodyToken(
  policyId: string,
  requestId: string,
  holders: readonly string[]
): string {
  return sha256Hex(
    canonicalJson({
      kind: CUSTODY_KIND,
      policyId,
      requestId,
      holders: [...holders].sort(),
    })
  );
}

function refuse(code: SuccessionErrorCode, reason: string): ClaimEvaluation {
  return { ok: false, holders: [], code, reason };
}

/**
 * Decides a claim without touching disk. Pure, so the same inputs always produce the
 * same refusal — and so every refusal can be replayed by an auditor from the receipts.
 */
export function evaluateClaim(input: EvaluateInput): ClaimEvaluation {
  const { policy, status, used, claim } = input;

  if (typeof claim.requestId !== 'string' || !REQUEST_PATTERN.test(claim.requestId)) {
    return refuse(
      'invalid-claim',
      'requestId must be 8-64 characters of letters, digits, dot, dash or underscore'
    );
  }
  if (typeof claim.at !== 'number' || !Number.isInteger(claim.at) || claim.at < 0) {
    return refuse('invalid-claim', 'claim.at must be a non-negative epoch-ms integer');
  }
  if (used.includes(claim.requestId)) {
    return refuse('replay', `request ${claim.requestId} was already decided`);
  }
  if (status.phase === 'active') {
    return refuse('not-dormant', 'the owner heartbeats are still current; the window is closed');
  }
  if (status.phase === 'dormant') {
    return refuse(
      'too-early',
      `the window opens at ${status.opensAt}, which is after this claim (${claim.at})`
    );
  }

  if (!Array.isArray(claim.shares) || claim.shares.length === 0) {
    return refuse('invalid-claim', 'a claim needs at least one heir share');
  }

  const payload = claimPayload(status.policyId, claim.requestId, claim.at);
  const known = new Map<string, Heir>(policy.heirs.map((heir) => [heir.id, heir]));
  const revoked = new Set(policy.revoked);
  const seen = new Set<string>();
  const holders: string[] = [];

  for (const share of claim.shares as readonly unknown[]) {
    if (typeof share !== 'object' || share === null) {
      return refuse('invalid-claim', 'each share must be an object');
    }
    const { heirId, sig } = share as Partial<ClaimShare>;
    if (typeof heirId !== 'string') return refuse('invalid-claim', 'share.heirId must be a string');
    if (typeof sig !== 'string' || sig.length === 0) {
      return refuse('invalid-claim', `share from "${heirId}" has no signature`);
    }
    const heir = known.get(heirId);
    if (!heir) return refuse('unknown-heir', `heir "${heirId}" is not named in the policy`);
    if (revoked.has(heirId)) return refuse('heir-revoked', `heir "${heirId}" was revoked`);
    if (seen.has(heirId)) return refuse('duplicate-share', `heir "${heirId}" signed twice`);
    seen.add(heirId);
    if (!verifyBytes(heir.publicKey, payload, sig)) {
      return refuse('bad-share', `share from "${heirId}" is not a valid signature for this claim`);
    }
    holders.push(heirId);
  }

  holders.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const active = activeHeirs(policy).length;
  if (holders.length < policy.threshold) {
    return refuse(
      'insufficient-shares',
      `${holders.length} valid shares, policy needs ${policy.threshold} of ${active}`
    );
  }
  return { ok: true, holders, code: null, reason: null };
}

/** Rebuilds the error a refusal would raise, so callers can throw exactly one code. */
export function refusalError(evaluation: ClaimEvaluation): SuccessionError {
  const code = evaluation.code ?? 'invalid-claim';
  return new SuccessionError(code, evaluation.reason ?? 'claim refused', {
    details: { holders: evaluation.holders },
  });
}
