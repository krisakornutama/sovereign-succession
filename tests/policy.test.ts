import { describe, expect, it } from 'vitest';
import { createSigningKey } from 'sovereign-attest';
import {
  DAY_MS,
  activeHeirs,
  normalisePolicyBody,
  openPolicy,
  policyIdOf,
  sealPolicy,
} from '../src/policy.js';
import { isSuccessionError } from '../src/errors.js';
import { T0, expectCode, heirKeys, key } from './helpers.js';

const owner = key('owner-primary');
const [ann, bob, cy] = heirKeys();

function draft(overrides: Record<string, unknown> = {}) {
  return {
    heirs: [
      { id: 'ann', publicKey: ann.publicKey },
      { id: 'bob', publicKey: bob.publicKey },
      { id: 'cy', publicKey: cy.publicKey },
    ],
    threshold: 2,
    dormantAfterDays: 90,
    createdAt: T0,
    ...overrides,
  };
}

describe('policy sealing', () => {
  it('derives the id from the body and signs it with the owner key', () => {
    const sealed = sealPolicy(owner, draft());
    expect(sealed.policyId).toBe(policyIdOf(sealed.body));
    expect(sealed.body.owner.publicKey.trim()).toBe(owner.publicKey.trim());
    expect(sealed.body.heirs.map((heir) => heir.id)).toEqual(['ann', 'bob', 'cy']);
    expect(openPolicy(sealed).threshold).toBe(2);
  });

  it('sorts heirs by id so the same policy always hashes the same', () => {
    const forward = sealPolicy(owner, draft());
    const reversed = sealPolicy(
      owner,
      draft({
        heirs: [
          { id: 'cy', publicKey: cy.publicKey },
          { id: 'bob', publicKey: bob.publicKey },
          { id: 'ann', publicKey: ann.publicKey },
        ],
      })
    );
    expect(reversed.policyId).toBe(forward.policyId);
  });

  it('drops heirs from the count when they are revoked', () => {
    const body = normalisePolicyBody({
      ...sealPolicy(owner, draft()).body,
      revoked: ['cy'],
      threshold: 2,
    });
    expect(activeHeirs(body).map((heir) => heir.id)).toEqual(['ann', 'bob']);
  });
});

describe('policy refusals', () => {
  it('refuses a threshold above the active heirs', () => {
    expectCode(() => sealPolicy(owner, draft({ threshold: 4 })), 'invalid-policy');
  });

  it('refuses a zero threshold', () => {
    expectCode(() => sealPolicy(owner, draft({ threshold: 0 })), 'invalid-policy');
  });

  it('refuses a duplicate heir id', () => {
    expectCode(
      () =>
        sealPolicy(owner, {
          ...draft(),
          heirs: [
            { id: 'ann', publicKey: ann.publicKey },
            { id: 'ann', publicKey: bob.publicKey },
          ],
        }),
      'invalid-policy'
    );
  });

  it('refuses an heir key that is not a PEM public key', () => {
    expectCode(
      () => sealPolicy(owner, { ...draft(), heirs: [{ id: 'ann', publicKey: 'nope' }] }),
      'invalid-policy'
    );
  });

  it('refuses an unpinned heir id with characters that ids cannot carry', () => {
    expectCode(
      () => sealPolicy(owner, { ...draft(), heirs: [{ id: 'a b', publicKey: ann.publicKey }] }),
      'invalid-policy'
    );
  });

  it('refuses a dormantAfterDays of zero', () => {
    expectCode(() => sealPolicy(owner, draft({ dormantAfterDays: 0 })), 'invalid-policy');
  });

  it('refuses a notBefore that is not a positive instant', () => {
    expectCode(() => sealPolicy(owner, draft({ notBefore: 0 })), 'invalid-policy');
  });

  it('refuses a revoked heir that the policy does not name', () => {
    expectCode(
      () =>
        normalisePolicyBody({
          ...sealPolicy(owner, draft()).body,
          revoked: ['zed'],
        }),
      'invalid-policy'
    );
  });

  it('refuses a body without a creation time', () => {
    expectCode(() => sealPolicy(owner, draft({ createdAt: 0 })), 'invalid-policy');
  });

  it('refuses a body edited after signing', () => {
    const sealed = sealPolicy(owner, draft());
    const tampered = { ...sealed, body: { ...sealed.body, threshold: 1 } };
    expectCode(() => openPolicy(tampered), 'invalid-policy');
  });

  it('refuses a signature that does not verify', () => {
    const sealed = sealPolicy(owner, draft());
    const flipped = `${sealed.sig.slice(0, -4)}AAAA`;
    expectCode(() => openPolicy({ ...sealed, sig: flipped }), 'invalid-policy');
  });

  it('refuses a policy whose owner is not the pinned key', () => {
    const sealed = sealPolicy(owner, draft());
    const other = createSigningKey('other-owner', T0);
    expectCode(() => openPolicy(sealed, other.publicKey), 'unauthorised');
  });

  it('refuses a pinned key that cannot be parsed', () => {
    const sealed = sealPolicy(owner, draft());
    expectCode(() => openPolicy(sealed, 'not a pem'), 'invalid-policy');
  });

  it('refuses a value that is not a policy at all', () => {
    expectCode(() => openPolicy(null), 'invalid-policy');
    expectCode(() => openPolicy({ policyId: 'x' }), 'invalid-policy');
  });

  it('exposes isSuccessionError for callers that catch refusals', () => {
    try {
      sealPolicy(owner, draft({ threshold: 9 }));
      throw new Error('unreachable');
    } catch (error) {
      expect(isSuccessionError(error)).toBe(true);
      expect(isSuccessionError(new Error('other'))).toBe(false);
    }
  });

  it('keeps a time-lock as a positive instant when supplied', () => {
    const body = sealPolicy(owner, draft({ notBefore: T0 + 400 * DAY_MS })).body;
    expect(body.notBefore).toBe(T0 + 400 * DAY_MS);
    expect(DAY_MS).toBe(86_400_000);
  });

  it('keeps an heir label and truncates it to 120 characters', () => {
    const long = 'x'.repeat(200);
    const body = sealPolicy(owner, {
      ...draft(),
      heirs: [{ id: 'ann', publicKey: ann.publicKey, label: long }],
      threshold: 1,
    }).body;
    expect(body.heirs[0].label).toHaveLength(120);
  });

  it('refuses a policy with no heirs at all', () => {
    expectCode(() => sealPolicy(owner, { ...draft(), heirs: [] }), 'invalid-policy');
  });

  it('refuses an heir that is not an object', () => {
    expectCode(() => sealPolicy(owner, { ...draft(), heirs: [null as never] }), 'invalid-policy');
  });

  it('refuses an heir label that is not text', () => {
    expectCode(
      () =>
        sealPolicy(owner, {
          ...draft(),
          heirs: [{ id: 'ann', publicKey: ann.publicKey, label: 7 as never }],
          threshold: 1,
        }),
      'invalid-policy'
    );
  });

  it('refuses a key with the right header but no parsable body', () => {
    expectCode(
      () =>
        sealPolicy(owner, {
          ...draft(),
          heirs: [
            {
              id: 'ann',
              publicKey: '-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----',
            },
          ],
          threshold: 1,
        }),
      'invalid-policy'
    );
  });
});
