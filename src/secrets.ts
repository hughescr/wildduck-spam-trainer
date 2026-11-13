import { createHash, timingSafeEqual } from 'node:crypto';
import { GetParameterCommand } from '@aws-sdk/client-ssm';
import { GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import type { Logger } from './log';

/** The narrow slice of an AWS SDK v3 client these loaders use (injectable in tests). */
export interface SdkSender<C> {
    send(command: C, options?: { abortSignal?: AbortSignal }): Promise<unknown>;
}
export type SsmSender = SdkSender<GetParameterCommand>;
export type SecretsSender = SdkSender<GetSecretValueCommand>;

const digest = (value: string) => createHash('sha256').update(value, 'utf8').digest();

/** Constant-time comparison of a presented value against expected digests. */
export function matchesAnyDigest(presented: string, digests: readonly Buffer[]): boolean {
    // Hashing both sides gives equal-length inputs to timingSafeEqual.
    const candidate = digest(presented);
    let matched = false;
    for (const expected of digests) {
        // Evaluate every entry so timing does not reveal which one matched.
        matched = timingSafeEqual(candidate, expected) || matched;
    }
    return matched;
}

/** Runs one SDK call, aborted at `timeoutMs` or when `deadline` (the request deadline) aborts, whichever is first. */
async function withTimeout<T>(timeoutMs: number, run: (signal: AbortSignal) => Promise<T>, deadline?: AbortSignal): Promise<T> {
    if (deadline?.aborted) {
        throw new Error('deadline');
    }
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let onDeadline: (() => void) | undefined;
    try {
        return await Promise.race([
            run(controller.signal),
            new Promise<never>((_resolve, reject) => {
                const fail = (reason: string) => {
                    controller.abort();
                    reject(new Error(reason));
                };
                timer = setTimeout(() => fail('timeout'), timeoutMs);
                onDeadline = () => fail('deadline');
                deadline?.addEventListener('abort', onDeadline, { once: true });
            }),
        ]);
    } finally {
        clearTimeout(timer);
        if (onDeadline) {
            deadline?.removeEventListener('abort', onDeadline);
        }
    }
}

const errorName = (error: unknown) => (typeof error === 'object' && error !== null && 'name' in error ? String((error as { name: unknown }).name) : '');

/** Printable ASCII without spaces: a safe single header value. */
const TRAINING_KEY = /^[\x21-\x7e]{16,4096}$/;
/** Bootstrap generates an alphanumeric value (ExcludePunctuation), so it is a safe header value. */
export const ORIGIN_SECRET = /^[A-Za-z0-9]{32,1024}$/;

export interface TrainingKeyStoreOptions {
    client: () => SsmSender;
    /** Unset means unconfigured: the key is never available (503). */
    parameterName: string | undefined;
    log: Logger;
    now?: () => number;
    /** A loaded key is reused this long, so rotation needs no deploy. */
    ttlMs?: number;
    /** After a failed attempt, wait this long before calling SSM again. */
    failureRetryMs?: number;
    /** On transient SSM failure, a previously loaded key stays usable this much longer. */
    maxStaleMs?: number;
    timeoutMs?: number;
}

export interface TrainingKeySource {
    /** `deadline` (the request deadline) bounds any load this call starts or joins. */
    get(deadline?: AbortSignal): Promise<string | undefined>;
    /** The proxy rejected the key: reload it on the next request (still rate-limited). */
    invalidate(): void;
}

/** Loads the operator-provisioned SecureString training key, cached with a TTL and coalesced. */
export class TrainingKeyStore implements TrainingKeySource {
    private readonly now: () => number;
    private readonly ttlMs: number;
    private readonly failureRetryMs: number;
    private readonly maxStaleMs: number;
    private readonly timeoutMs: number;
    private key: string | undefined;
    private loadedAt = Number.NEGATIVE_INFINITY;
    private lastAttempt = Number.NEGATIVE_INFINITY;
    private forceRefresh = false;
    private pending: Promise<void> | undefined;

    constructor(private readonly options: TrainingKeyStoreOptions) {
        this.now = options.now ?? Date.now;
        this.ttlMs = options.ttlMs ?? 300_000;
        this.failureRetryMs = options.failureRetryMs ?? 10_000;
        this.maxStaleMs = options.maxStaleMs ?? 600_000;
        this.timeoutMs = options.timeoutMs ?? 3_000;
    }

    async get(deadline?: AbortSignal): Promise<string | undefined> {
        if (!this.options.parameterName) {
            this.options.log.error('training_key_unavailable', { upstream: 'ssm', reason: 'unconfigured' });
            return undefined;
        }
        const needsRefresh = !this.key || this.forceRefresh || this.now() - this.loadedAt >= this.ttlMs;
        // Join an in-flight load; otherwise start one at most once per retry interval.
        // A Lambda instance serves one request at a time, so the starter's deadline bounds the load.
        if (needsRefresh && (this.pending || this.now() - this.lastAttempt >= this.failureRetryMs)) {
            this.pending ??= this.load(this.options.parameterName, deadline).finally(() => {
                this.pending = undefined;
            });
            await this.pending;
        }
        if (this.key && this.now() - this.loadedAt < this.ttlMs + this.maxStaleMs) {
            return this.key;
        }
        this.key = undefined;
        return undefined;
    }

    invalidate(): void {
        this.forceRefresh = true;
    }

    private async load(name: string, deadline: AbortSignal | undefined): Promise<void> {
        const started = this.now();
        this.lastAttempt = started;
        let output: unknown;
        try {
            output = await withTimeout(this.timeoutMs, signal => this.options.client().send(new GetParameterCommand({ Name: name, WithDecryption: true }), { abortSignal: signal }), deadline);
        } catch (error) {
            const missing = errorName(error) === 'ParameterNotFound';
            if (missing) {
                // Definitive: the operator has not installed (or removed) the key.
                this.key = undefined;
            }
            this.options.log.error('training_key_unavailable', { upstream: 'ssm', reason: missing ? 'parameter_not_found' : 'request_failed', durationMs: Math.max(0, this.now() - started) });
            return;
        }
        const parameter = (output as { Parameter?: { Type?: unknown; Value?: unknown } } | undefined)?.Parameter;
        // Tolerate one trailing newline from file-based provisioning; nothing else is altered.
        const value = typeof parameter?.Value === 'string' ? parameter.Value.replace(/\r?\n$/, '') : undefined;
        if (parameter?.Type !== 'SecureString' || value === undefined || !TRAINING_KEY.test(value)) {
            this.key = undefined;
            this.options.log.error('training_key_unavailable', { upstream: 'ssm', reason: 'invalid_parameter' });
            return;
        }
        this.key = value;
        this.loadedAt = this.now();
        this.forceRefresh = false;
    }
}

export type OriginCheck = 'ok' | 'mismatch' | 'unavailable';

export interface OriginVerifierOptions {
    client: () => SecretsSender;
    /** Unset means unconfigured: every request fails closed (503) once a header is presented. */
    secretId: string | undefined;
    log: Logger;
    now?: () => number;
    /** Loaded values are reused this long. */
    ttlMs?: number;
    /** A well-formed mismatch may trigger at most one refresh per interval (rotation propagation). */
    mismatchRefreshMs?: number;
    /** After a failed load, wait this long before calling Secrets Manager again. */
    failureRetryMs?: number;
    timeoutMs?: number;
}

export interface OriginCheckSource {
    /** `deadline` (the request deadline) bounds any secret load this call starts or joins. */
    verify(presented: string | undefined, deadline?: AbortSignal): Promise<OriginCheck>;
}

/**
 * Verifies the CloudFront origin custom header against the AWSCURRENT and
 * AWSPREVIOUS versions of the bootstrap-owned secret, so rotation propagation
 * causes no outage. Loads are coalesced and rate-limited, and a missing or
 * malformed header is rejected without any Secrets Manager call, so public
 * traffic cannot drive Secrets Manager usage beyond a small bounded rate.
 */
export class OriginVerifier implements OriginCheckSource {
    private readonly now: () => number;
    private readonly ttlMs: number;
    private readonly mismatchRefreshMs: number;
    private readonly failureRetryMs: number;
    private readonly timeoutMs: number;
    private digests: Buffer[] | undefined;
    private loadedAt = Number.NEGATIVE_INFINITY;
    private lastAttempt = Number.NEGATIVE_INFINITY;
    private pending: Promise<void> | undefined;

    constructor(private readonly options: OriginVerifierOptions) {
        this.now = options.now ?? Date.now;
        this.ttlMs = options.ttlMs ?? 300_000;
        this.mismatchRefreshMs = options.mismatchRefreshMs ?? 60_000;
        this.failureRetryMs = options.failureRetryMs ?? 10_000;
        this.timeoutMs = options.timeoutMs ?? 3_000;
    }

    async verify(presented: string | undefined, deadline?: AbortSignal): Promise<OriginCheck> {
        if (presented === undefined || !ORIGIN_SECRET.test(presented)) {
            return 'mismatch';
        }
        if (!this.options.secretId) {
            this.options.log.error('origin_secret_unavailable', { upstream: 'secretsmanager', reason: 'unconfigured' });
            return 'unavailable';
        }
        // Join an in-flight load; otherwise start one when stale, at most once per retry interval.
        if ((!this.digests || this.now() - this.loadedAt >= this.ttlMs) && (this.pending || this.now() - this.lastAttempt >= this.failureRetryMs)) {
            await this.refresh(this.options.secretId, deadline);
        }
        // Fail closed: values past their TTL are never used, even when a reload just failed.
        if (this.digests && this.now() - this.loadedAt >= this.ttlMs) {
            this.digests = undefined;
        }
        if (!this.digests) {
            return 'unavailable';
        }
        if (matchesAnyDigest(presented, this.digests)) {
            return 'ok';
        }
        if (this.pending || this.now() - this.lastAttempt >= this.mismatchRefreshMs) {
            await this.refresh(this.options.secretId, deadline);
            if (this.digests && matchesAnyDigest(presented, this.digests)) {
                return 'ok';
            }
        }
        return 'mismatch';
    }

    /** Joins an in-flight load or starts one; a Lambda instance serves one request at a time, so the starter's deadline bounds it. */
    private refresh(secretId: string, deadline: AbortSignal | undefined): Promise<void> {
        this.pending ??= this.load(secretId, deadline).finally(() => {
            this.pending = undefined;
        });
        return this.pending;
    }

    private async fetchStage(secretId: string, stage: 'AWSCURRENT' | 'AWSPREVIOUS', deadline: AbortSignal | undefined): Promise<string | undefined> {
        try {
            const output = await withTimeout(this.timeoutMs, signal => this.options.client().send(new GetSecretValueCommand({ SecretId: secretId, VersionStage: stage }), { abortSignal: signal }), deadline);
            const value = (output as { SecretString?: unknown } | undefined)?.SecretString;
            return typeof value === 'string' && ORIGIN_SECRET.test(value) ? value : undefined;
        } catch (error) {
            // A secret that was never rotated has no AWSPREVIOUS version.
            if (stage === 'AWSPREVIOUS' && errorName(error) === 'ResourceNotFoundException') {
                return undefined;
            }
            throw error;
        }
    }

    private async load(secretId: string, deadline: AbortSignal | undefined): Promise<void> {
        const started = this.now();
        this.lastAttempt = started;
        try {
            const [current, previous] = await Promise.all([this.fetchStage(secretId, 'AWSCURRENT', deadline), this.fetchStage(secretId, 'AWSPREVIOUS', deadline)]);
            if (!current) {
                throw new Error('missing current origin secret');
            }
            this.digests = [current, ...(previous ? [previous] : [])].map(digest);
            this.loadedAt = this.now();
        } catch {
            // Values still inside their TTL stay usable (a failed mismatch-triggered refresh
            // must not let untrusted traffic evict a working cache); expired ones are dropped in verify().
            this.options.log.error('origin_secret_unavailable', { upstream: 'secretsmanager', reason: 'request_failed', durationMs: Math.max(0, this.now() - started) });
        }
    }
}
