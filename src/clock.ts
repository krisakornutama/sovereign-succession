import type { Receipt } from 'sovereign-attest';
import { SuccessionError } from './errors.js';
import { DAY_MS, policyIdOf, type SuccessionPolicyBody } from './policy.js';

/** Receipt actions this module writes. Verifiers branch on these strings, so they are frozen. */
export const ACTION_POLICY_SEALED = 'succession.policy.sealed';
export const ACTION_HEARTBEAT = 'succession.owner.alive';
export const ACTION_GRANTED = 'succession.access.granted';
export const ACTION_DENIED = 'succession.access.denied';

export type SuccessionPhase = 'active' | 'dormant' | 'window-open';

export interface SuccessionStatus {
  readonly policyId: string;
  readonly phase: SuccessionPhase;
  /** Newest verified owner heartbeat (or the policy's creation time before the first one). */
  readonly lastSeenAt: number;
  /** When dormancy is reached: `lastSeenAt + dormantAfterDays`. */
  readonly dormantAt: number;
  /** When a claim would be accepted: the later of dormancy and the policy time-lock. */
  readonly opensAt: number;
  /** Whole days since the last heartbeat, rounded down. */
  readonly elapsedDays: number;
  /** Current chain head, so a caller can quote one handle for the whole state. */
  readonly head: string | null;
}

function assertTime(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new SuccessionError('invalid-state', `${field} must be a non-negative epoch-ms integer`);
  }
  return value;
}

/**
 * Reads the dormancy state out of a verified receipt chain.
 *
 * The clock is not a timer and it is not trusted input: it is a pure function of
 * (signed heartbeats, policy, the time the caller asks about). Two machines with the
 * same chain and the same `now` must reach the same answer.
 */
export class DormancyClock {
  private readonly policy: SuccessionPolicyBody;
  private readonly receipts: readonly Receipt[];
  private readonly head: string | null;

  constructor(options: {
    readonly policy: SuccessionPolicyBody;
    /** Oldest first, every signature already verified. */
    readonly receipts: readonly Receipt[];
    readonly head: string | null;
  }) {
    this.policy = options.policy;
    this.receipts = options.receipts;
    this.head = options.head;
  }

  /** Every verified heartbeat, oldest first. */
  heartbeats(): readonly Receipt[] {
    return this.receipts.filter((receipt) => receipt.body.action === ACTION_HEARTBEAT);
  }

  get lastSeenAt(): number {
    let last = this.policy.createdAt;
    for (const receipt of this.heartbeats()) {
      if (receipt.body.at > last) last = receipt.body.at;
    }
    return last;
  }

  status(now: number): SuccessionStatus {
    const at = assertTime(now, 'now');
    const lastSeenAt = this.lastSeenAt;
    const dormantAt = lastSeenAt + this.policy.dormantAfterDays * DAY_MS;
    const opensAt =
      this.policy.notBefore === null ? dormantAt : Math.max(dormantAt, this.policy.notBefore);
    const phase: SuccessionPhase =
      at < dormantAt ? 'active' : at < opensAt ? 'dormant' : 'window-open';
    return {
      policyId: policyIdOf(this.policy),
      phase,
      lastSeenAt,
      dormantAt,
      opensAt,
      elapsedDays: Math.floor((at - lastSeenAt) / DAY_MS),
      head: this.head,
    };
  }
}
