/** Lambda is configured with a 25 s timeout; finish well before it. */
export const MAX_REQUEST_MS = 20_000;
/** Time reserved after the deadline to build and return a clean response. */
export const RESPONSE_RESERVE_MS = 3_000;

/**
 * A request-wide deadline. Every upstream call derives its signal from it, so
 * the handler returns a clean retryable response instead of being killed by
 * the Lambda timeout.
 */
export class Deadline {
    readonly signal: AbortSignal;
    private readonly expiresAt: number;

    constructor(budgetMs: number, private readonly now: () => number = Date.now) {
        const budget = Math.max(0, Math.floor(budgetMs));
        this.expiresAt = now() + budget;
        this.signal = AbortSignal.timeout(Math.max(1, budget));
    }

    /** Builds the deadline from the live Lambda context when it is available. */
    static fromContext(remainingMs: (() => number) | undefined, now: () => number = Date.now, maxMs = MAX_REQUEST_MS): Deadline {
        let budget = maxMs;
        if (remainingMs) {
            let remaining: number;
            try {
                remaining = remainingMs();
            } catch {
                remaining = 0;
            }
            budget = Number.isFinite(remaining) ? Math.min(maxMs, remaining - RESPONSE_RESERVE_MS) : 0;
        }
        return new Deadline(budget, now);
    }

    remainingMs(): number {
        return Math.max(0, this.expiresAt - this.now());
    }

    expired(): boolean {
        return this.signal.aborted || this.remainingMs() <= 0;
    }

    /** A signal for one upstream call: the per-call limit or the deadline, whichever is first. */
    signalFor(perCallMs?: number): AbortSignal {
        if (perCallMs === undefined) {
            return this.signal;
        }
        return AbortSignal.any([this.signal, AbortSignal.timeout(Math.max(1, Math.min(perCallMs, this.remainingMs())))]);
    }
}
