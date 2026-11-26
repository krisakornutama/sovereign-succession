import { describe, expect, it } from 'vitest';
import type { Receipt } from 'sovereign-attest';
import { ACTION_HEARTBEAT, DormancyClock } from '../src/clock.js';
import { sealPolicy } from '../src/policy.js';
import { DAY_MS, T0, expectCode, heirKeys, key } from './helpers.js';

const owner = key('owner-primary');
const [ann, bob] = heirKeys(['ann', 'bob']);

const body = sealPolicy(owner, {
  heirs: [
    { id: 'ann', publicKey: ann.publicKey },
    { id: 'bob', publicKey: bob.publicKey },
  ],
  threshold: 2,
  dormantAfterDays: 90,
  createdAt: T0,
}).body;

const lockedBody = sealPolicy(owner, {
  heirs: [
    { id: 'ann', publicKey: ann.publicKey },
    { id: 'bob', publicKey: bob.publicKey },
  ],
  threshold: 2,
  dormantAfterDays: 90,
  notBefore: T0 + 400 * DAY_MS,
  createdAt: T0,
}).body;

/** Only `action` and `at` matter to the clock; signatures were checked upstream. */
function heartbeatAt(at: number): Receipt {
  return {
    v: 1,
    id: 'a'.repeat(64),
    keyId: 'owner-primary',
    publicKey: owner.publicKey,
    body: {
      v: 1,
      action: ACTION_HEARTBEAT,
      actor: 'owner-primary',
      artifact: { name: 'succession/policy', sha256: 'b'.repeat(64) },
      at,
      prev: null,
    },
    sig: 'sig',
  };
}

function clockWith(receipts: Receipt[], policy = body): DormancyClock {
  return new DormancyClock({ policy, receipts, head: receipts.at(-1)?.id ?? null });
}

describe('dormancy clock', () => {
  it('counts from the policy creation time until the first heartbeat', () => {
    const clock = clockWith([]);
    expect(clock.lastSeenAt).toBe(T0);
    expect(clock.heartbeats()).toHaveLength(0);
    expect(clock.status(T0 + 1).phase).toBe('active');
  });

  it('uses the newest heartbeat, not the newest receipt of any kind', () => {
    const denial = heartbeatAt(T0 + 50 * DAY_MS);
    const clock = clockWith([
      heartbeatAt(T0 + 10 * DAY_MS),
      { ...denial, body: { ...denial.body, action: 'succession.access.denied' } },
      heartbeatAt(T0 + 30 * DAY_MS),
    ]);
    expect(clock.lastSeenAt).toBe(T0 + 30 * DAY_MS);
    expect(clock.heartbeats()).toHaveLength(2);
  });

  it('is active up to the day before dormancy', () => {
    const clock = clockWith([heartbeatAt(T0)]);
    const status = clock.status(T0 + 90 * DAY_MS - 1);
    expect(status.phase).toBe('active');
    expect(status.dormantAt).toBe(T0 + 90 * DAY_MS);
    expect(status.opensAt).toBe(status.dormantAt);
    expect(status.elapsedDays).toBe(89);
  });

  it('opens the window exactly at dormancy when there is no time-lock', () => {
    const clock = clockWith([heartbeatAt(T0)]);
    expect(clock.status(T0 + 90 * DAY_MS).phase).toBe('window-open');
    expect(clock.status(T0 + 500 * DAY_MS).elapsedDays).toBe(500);
  });

  it('holds the window closed while an absolute time-lock is in the future', () => {
    const clock = clockWith([heartbeatAt(T0)], lockedBody);
    expect(clock.status(T0 + 100 * DAY_MS).phase).toBe('dormant');
    expect(clock.status(T0 + 400 * DAY_MS - 1).phase).toBe('dormant');
    expect(clock.status(T0 + 400 * DAY_MS).phase).toBe('window-open');
    expect(clock.status(T0 + 100 * DAY_MS).opensAt).toBe(T0 + 400 * DAY_MS);
  });

  it('refuses to answer for a time that is not an instant', () => {
    const clock = clockWith([]);
    expectCode(() => clock.status(-1), 'invalid-state');
    expectCode(() => clock.status(1.5), 'invalid-state');
    expectCode(() => clock.status(Number.NaN), 'invalid-state');
  });
});
