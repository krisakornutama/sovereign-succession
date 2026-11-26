import { describe, expect, it } from 'vitest';
import { signBytes } from 'sovereign-attest';
import type { SuccessionStatus } from '../src/clock.js';
import {
  claimPayload,
  custodyToken,
  evaluateClaim,
  refusalError,
  type ClaimInput,
} from '../src/claim.js';
import { DAY_MS, normalisePolicyBody, policyIdOf, sealPolicy } from '../src/policy.js';
import { T0, heirKeys, key } from './helpers.js';

const owner = key('owner-primary');
const [ann, bob, cy, dan] = heirKeys(['ann', 'bob', 'cy', 'dan']);

function policyWith(overrides: Record<string, unknown> = {}) {
  const sealed = sealPolicy(owner, {
    heirs: [
      { id: 'ann', publicKey: ann.publicKey },
      { id: 'bob', publicKey: bob.publicKey },
      { id: 'cy', publicKey: cy.publicKey },
      { id: 'dan', publicKey: dan.publicKey },
    ],
    threshold: 2,
    dormantAfterDays: 90,
    createdAt: T0,
  }).body;
  return normalisePolicyBody({ ...sealed, ...overrides });
}

const policy = policyWith();
const policyId = policyIdOf(policy);

function statusOf(phase: SuccessionStatus['phase'], at = T0 + 90 * DAY_MS): SuccessionStatus {
  return {
    policyId,
    phase,
    lastSeenAt: T0,
    dormantAt: at,
    opensAt: at,
    elapsedDays: 90,
    head: null,
  };
}

function share(who: keyName, requestId = 'estate-open-1', at = T0 + 90 * DAY_MS) {
  const payload = claimPayload(policyId, requestId, at);
  return { heirId: who.keyId, sig: signBytes(who.privateKey, payload) };
}

type keyName = ReturnType<typeof key>;

function claimWith(overrides: Partial<ClaimInput> = {}): ClaimInput {
  return {
    requestId: 'estate-open-1',
    at: T0 + 90 * DAY_MS,
    shares: [share(ann), share(bob)],
    ...overrides,
  };
}

function evaluate(
  claim: ClaimInput,
  options: { phase?: SuccessionStatus['phase']; used?: string[]; body?: typeof policy } = {}
) {
  return evaluateClaim({
    policy: options.body ?? policy,
    status: statusOf(options.phase ?? 'window-open', claim.at),
    used: options.used ?? [],
    claim,
  });
}

describe('claim evaluation', () => {
  it('accepts a threshold set of distinct heir shares and sorts the holders', () => {
    const result = evaluate(claimWith());
    expect(result.ok).toBe(true);
    expect(result.holders).toEqual(['ann', 'bob']);
    expect(result.code).toBeNull();
  });

  it('accepts more than the threshold', () => {
    const result = evaluate(claimWith({ shares: [share(ann), share(bob), share(cy)] }));
    expect(result.holders).toEqual(['ann', 'bob', 'cy']);
  });

  it('refuses while the owner is still heartbeating', () => {
    const result = evaluate(claimWith(), { phase: 'active' });
    expect(result).toMatchObject({ ok: false, code: 'not-dormant' });
  });

  it('refuses before the window opens', () => {
    const result = evaluate(claimWith(), { phase: 'dormant' });
    expect(result).toMatchObject({ ok: false, code: 'too-early' });
  });

  it('refuses a reused request id', () => {
    const result = evaluate(claimWith(), { used: ['estate-open-1'] });
    expect(result).toMatchObject({ ok: false, code: 'replay' });
  });

  it('refuses fewer shares than the threshold', () => {
    const result = evaluate(claimWith({ shares: [share(ann)] }));
    expect(result).toMatchObject({ ok: false, code: 'insufficient-shares' });
  });

  it('refuses a share from an heir the policy does not name', () => {
    const stranger = key('stranger');
    const forged = {
      heirId: 'stranger',
      sig: signBytes(
        stranger.privateKey,
        claimPayload(policyId, 'estate-open-1', T0 + 90 * DAY_MS)
      ),
    };
    const result = evaluate(claimWith({ shares: [share(ann), forged] }));
    expect(result).toMatchObject({ ok: false, code: 'unknown-heir' });
  });

  it('refuses a share from a revoked heir', () => {
    const revokedPolicy = policyWith({ revoked: ['bob'] });
    const result = evaluate(claimWith(), { body: revokedPolicy });
    expect(result).toMatchObject({ ok: false, code: 'heir-revoked' });
  });

  it('refuses the same heir signing twice', () => {
    const result = evaluate(claimWith({ shares: [share(ann), share(ann)] }));
    expect(result).toMatchObject({ ok: false, code: 'duplicate-share' });
  });

  it('refuses a signature made for another request', () => {
    const stale = share(bob, 'estate-open-2');
    const result = evaluate(claimWith({ shares: [share(ann), stale] }));
    expect(result).toMatchObject({ ok: false, code: 'bad-share' });
  });

  it('refuses a signature from the wrong key', () => {
    const forged = { heirId: 'bob', sig: share(cy).sig };
    const result = evaluate(claimWith({ shares: [share(ann), forged] }));
    expect(result).toMatchObject({ ok: false, code: 'bad-share' });
  });

  it('refuses a malformed request id', () => {
    const result = evaluate(claimWith({ requestId: 'short' }));
    expect(result).toMatchObject({ ok: false, code: 'invalid-claim' });
  });

  it('refuses a claim time that is not an instant', () => {
    const result = evaluate(claimWith({ at: 1.5 }));
    expect(result).toMatchObject({ ok: false, code: 'invalid-claim' });
  });

  it('refuses a claim with no shares at all', () => {
    const result = evaluate(claimWith({ shares: [] }));
    expect(result).toMatchObject({ ok: false, code: 'invalid-claim' });
  });

  it('refuses shares that are not objects or carry no signature', () => {
    expect(evaluate(claimWith({ shares: [null as never] }))).toMatchObject({
      ok: false,
      code: 'invalid-claim',
    });
    expect(evaluate(claimWith({ shares: [{ heirId: 7 } as never] }))).toMatchObject({
      ok: false,
      code: 'invalid-claim',
    });
    expect(evaluate(claimWith({ shares: [{ heirId: 'ann' } as never] }))).toMatchObject({
      ok: false,
      code: 'invalid-claim',
    });
  });

  it('turns a refusal into one typed error', () => {
    const refusal = evaluate(claimWith({ shares: [share(ann)] }));
    const error = refusalError(refusal);
    expect(error.code).toBe('insufficient-shares');
    expect(refusalError({ ok: false, holders: [], code: null, reason: null }).code).toBe(
      'invalid-claim'
    );
  });

  it('derives the custody handle from the request, not from share order', () => {
    const forward = custodyToken(policyId, 'estate-open-1', ['ann', 'bob']);
    const reversed = custodyToken(policyId, 'estate-open-1', ['bob', 'ann']);
    const other = custodyToken(policyId, 'estate-open-2', ['ann', 'bob']);
    expect(forward).toBe(reversed);
    expect(other).not.toBe(forward);
  });
});
