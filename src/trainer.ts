import { TRAINING_KEY_HEADER } from './config';
import type { Deadline } from './deadline';
import { MAX_MESSAGE_BYTES, openStrippedBody, type StripFailure, type StrippedBody } from './header-strip';
import type { Logger, LogLevel, UpstreamName } from './log';
import type { TrainingRequest } from './payload';
import type { TrainingKeySource } from './secrets';

/**
 * Training decisions. Every proxy request carries only the training key header;
 * no WildDuck access token or Rspamd password is ever sent from here.
 */

export type FetchLike = (input: string, init: RequestInit & { duplex?: 'half' }) => Promise<Response>;

export interface Decision {
    /** HTTP status returned to WildDuck: 200 (done, no retry) or 502/503 (retry). */
    readonly status: 200 | 502 | 503;
    readonly action: 'trained' | 'ignored' | 'skipped' | 'retry';
    /** Logged outcome token; distinct per result. */
    readonly outcome: string;
    readonly reason?: string;
    readonly level: LogLevel;
}

export interface TrainerOptions {
    readonly apiBaseUrl: string;
    readonly learnBaseUrl: string;
    readonly fetch: FetchLike;
    readonly trainingKey: TrainingKeySource;
    readonly log: Logger;
    readonly now?: () => number;
    /** Per-call limit for the small JSON lookups (the request deadline still applies). */
    readonly lookupTimeoutMs?: number;
}

const JUNK = '\\Junk';
const TRASH = '\\Trash';
const FLAGGED = '\\flagged';
/** Message metadata JSON can contain parsed text/HTML; bound what is buffered. */
const MAX_JSON_BYTES = 32 * 1024 * 1024;
const OBJECT_ID = /^[0-9a-f]{24}$/;

const trained = (outcome = 'trained'): Decision => ({ status: 200, action: 'trained', outcome, level: 'info' });
const ignored = (reason: string): Decision => ({ status: 200, action: 'ignored', outcome: 'ignored', reason, level: 'info' });
const skipped = (reason: string, level: LogLevel = 'warn'): Decision => ({ status: 200, action: 'skipped', outcome: 'skipped', reason, level });
const retry = (reason: string, status: 502 | 503 = 502): Decision => ({ status, action: 'retry', outcome: 'retry', reason, level: 'error' });

/** Short-circuits the decision flow with a final decision. */
class Stop extends Error {
    constructor(readonly decision: Decision) {
        super(decision.outcome);
    }
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const isAbort = (error: unknown) => typeof error === 'object' && error !== null && 'name' in error && ['AbortError', 'TimeoutError'].includes(String((error as { name: unknown }).name));

/**
 * Cancels an unneeded body without waiting: a cancel that never settles must not
 * delay the response to WildDuck.
 */
function discard(response: Response): void {
    try {
        response.body?.cancel().catch(() => undefined);
    } catch {
        // Nothing to recover: the body is not needed.
    }
}

/** One macrotask: lets the fetch implementation finish writing the request (its final chunk) after reading its end. */
const nextMacrotask = () => new Promise<void>(resolve => {
    setImmediate(resolve);
});

/** Reads at most `limit` bytes; returns undefined when the body is larger. */
async function readCapped(response: Response, limit: number): Promise<Uint8Array | undefined> {
    if (!response.body) {
        return new Uint8Array(0);
    }
    const reader = response.body.getReader();
    const parts: Uint8Array[] = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) {
            break;
        }
        total += value.length;
        if (total > limit) {
            reader.cancel().catch(() => undefined);
            return undefined;
        }
        parts.push(value);
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

const parseLength = (response: Response) => {
    const header = response.headers.get('content-length');
    return header !== null && /^[0-9]{1,16}$/.test(header) ? Number(header) : undefined;
};

export class Trainer {
    private readonly now: () => number;
    private readonly lookupTimeoutMs: number;

    constructor(private readonly options: TrainerOptions) {
        this.now = options.now ?? Date.now;
        this.lookupTimeoutMs = options.lookupTimeoutMs ?? 8_000;
    }

    async train(request: TrainingRequest, deadline: Deadline, log: Logger): Promise<Decision> {
        try {
            const key = await this.options.trainingKey.get(deadline.signal);
            if (!key) {
                return retry('training_key_unavailable', 503);
            }
            const run = new TrainingRun(this.options, this.now, this.lookupTimeoutMs, request, deadline, log, key);
            return request.ev === 'marked.spam' ? await run.spam() : await run.ham();
        } catch (error) {
            if (error instanceof Stop) {
                return error.decision;
            }
            throw error;
        }
    }
}

class TrainingRun {
    private readonly base: string;

    constructor(
        private readonly options: TrainerOptions,
        private readonly now: () => number,
        private readonly lookupTimeoutMs: number,
        private readonly request: TrainingRequest,
        private readonly deadline: Deadline,
        private readonly log: Logger,
        private readonly key: string,
    ) {
        // Identifiers were validated (24-hex ObjectIds, positive safe integer) before interpolation.
        this.base = `${options.apiBaseUrl}/users/${request.user}/mailboxes/${request.mailbox}`;
    }

    async spam(): Promise<Decision> {
        const mailbox = await this.mailbox();
        if (mailbox.specialUse !== JUNK) {
            return ignored('not_in_junk');
        }
        return this.learn('learn-spam');
    }

    async ham(): Promise<Decision> {
        const mailbox = await this.mailbox();
        if (mailbox.specialUse === JUNK) {
            return ignored('in_junk');
        }
        if (mailbox.specialUse === TRASH) {
            return ignored('in_trash');
        }
        const message = await this.lookup('message', `${this.base}/messages/${this.request.uid}`);
        if (typeof message['user'] !== 'string' || typeof message['mailbox'] !== 'string' || typeof message['id'] !== 'number') {
            throw new Stop(retry('invalid_response'));
        }
        if (message['user'].toLowerCase() !== this.request.user || message['mailbox'].toLowerCase() !== this.request.mailbox || message['id'] !== this.request.uid) {
            throw new Stop(skipped('identity_mismatch'));
        }
        const flags = message['flags'];
        if (typeof message['flagged'] !== 'boolean' || !Array.isArray(flags) || !flags.every(flag => typeof flag === 'string')) {
            throw new Stop(retry('invalid_response'));
        }
        // WildDuck also emits marked.ham when a message is merely starred/flagged.
        if (message['flagged'] || (flags as string[]).some(flag => flag.toLowerCase() === FLAGGED)) {
            return ignored('flagged');
        }
        const size = message['size'];
        if (typeof size === 'number' && size > MAX_MESSAGE_BYTES) {
            return skipped('too_large');
        }
        return this.learn('learn-ham');
    }

    private async mailbox(): Promise<{ specialUse: unknown }> {
        const mailbox = await this.lookup('mailbox', this.base);
        if (typeof mailbox['id'] !== 'string' || !OBJECT_ID.test(mailbox['id'].toLowerCase())) {
            throw new Stop(retry('invalid_response'));
        }
        if (mailbox['id'].toLowerCase() !== this.request.mailbox) {
            throw new Stop(skipped('identity_mismatch'));
        }
        return { specialUse: mailbox['specialUse'] };
    }

    /** Issues one proxy request. Network failure or timeout stops with a retryable decision. */
    private async call(upstream: UpstreamName, url: string, init: RequestInit & { duplex?: 'half' }, signal: AbortSignal, onError?: () => Decision | undefined): Promise<Response> {
        const started = this.now();
        try {
            const response = await this.options.fetch(url, {
                ...init,
                redirect: 'error',
                signal,
                headers: { ...(init.headers as Record<string, string> | undefined), [TRAINING_KEY_HEADER]: this.key },
            });
            this.log.info('upstream_response', { upstream, upstreamStatus: response.status, durationMs: Math.max(0, this.now() - started) });
            return response;
        } catch (error) {
            const specific = onError?.();
            if (specific) {
                throw new Stop(specific);
            }
            const timedOut = isAbort(error) || signal.aborted || this.deadline.expired();
            this.log.error('upstream_failed', { upstream, reason: timedOut ? 'timeout' : 'network', durationMs: Math.max(0, this.now() - started) });
            throw new Stop(timedOut ? retry('timeout', 503) : retry('upstream_unreachable'));
        }
    }

    /** Shared status handling for the WildDuck-side lookups (mailbox, message, eml). */
    private checkLookupStatus(upstream: UpstreamName, response: Response): void {
        const status = response.status;
        if (status === 200) {
            return;
        }
        discard(response);
        if (status === 404) {
            // Moved or deleted between the event and now: harmless.
            throw new Stop(skipped('stale', 'info'));
        }
        if (status === 401 || status === 403) {
            this.options.trainingKey.invalidate();
            this.log.error('proxy_auth_failed', { upstream, upstreamStatus: status });
            throw new Stop(retry('proxy_auth_failed'));
        }
        if (status === 408 || status === 425 || status === 429 || status >= 500) {
            throw new Stop(retry('upstream_unavailable'));
        }
        throw new Stop(skipped('upstream_rejected'));
    }

    private async lookup(upstream: 'mailbox' | 'message', url: string): Promise<Record<string, unknown>> {
        const response = await this.call(upstream, url, { method: 'GET', headers: { Accept: 'application/json' } }, this.deadline.signalFor(this.lookupTimeoutMs));
        this.checkLookupStatus(upstream, response);
        let bytes: Uint8Array | undefined;
        try {
            bytes = await readCapped(response, MAX_JSON_BYTES);
        } catch {
            throw new Stop(this.deadline.expired() ? retry('timeout', 503) : retry('upstream_unreachable'));
        }
        if (!bytes) {
            throw new Stop(skipped('too_large'));
        }
        let body: unknown;
        try {
            body = JSON.parse(new TextDecoder().decode(bytes));
        } catch {
            throw new Stop(retry('invalid_response'));
        }
        if (!isRecord(body) || body['success'] !== true) {
            throw new Stop(retry('upstream_unsuccessful'));
        }
        return body;
    }

    /** Maps a failure to open or stream the message to a decision. */
    private streamFailure(failure: StripFailure | undefined): Decision | undefined {
        switch (failure) {
            case 'message_too_large': return skipped('too_large');
            case 'header_too_large': return skipped('header_too_large');
            case 'malformed_message': return skipped('malformed_message');
            case 'source_error': return this.deadline.expired() ? retry('timeout', 503) : retry('eml_read_failed');
            default: return undefined;
        }
    }

    /**
     * Reads and validates the whole header section of the raw message, then streams
     * the normalized message into the learn endpoint. A malformed message is never sent.
     */
    private async learn(endpoint: 'learn-spam' | 'learn-ham'): Promise<Decision> {
        const eml = await this.call('eml', `${this.base}/messages/${this.request.uid}/message.eml`, { method: 'GET', headers: { Accept: 'message/rfc822' } }, this.deadline.signal);
        this.checkLookupStatus('eml', eml);
        const declared = parseLength(eml);
        if (declared !== undefined && declared > MAX_MESSAGE_BYTES) {
            discard(eml);
            return skipped('too_large');
        }
        const source = eml.body ?? new ReadableStream<Uint8Array>({ start: controller => controller.close() });
        const opened = await openStrippedBody(source, { signal: this.deadline.signal });
        if (!opened.ok) {
            if (opened.malformed) {
                // A category code only; never content.
                this.log.warn('message_malformed', { upstream: 'eml', reason: opened.malformed });
            }
            return this.streamFailure(opened.failure) ?? retry('eml_read_failed');
        }
        const stripped: StrippedBody = opened.body;
        try {
            // An interrupted upload also aborts the request, so the proxy sees an aborted
            // request rather than a complete one.
            const response = await this.call('learn', `${this.options.learnBaseUrl}/${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'message/rfc822' },
                body: stripped.stream,
                duplex: 'half',
            }, AbortSignal.any([this.deadline.signal, stripped.signal]), () => this.streamFailure(stripped.failure()));
            return await this.learnResult(response, stripped);
        } finally {
            // No-op once the upload completed; otherwise it ends by error, never by a clean end.
            stripped.abort();
        }
    }

    /**
     * Maps the learn response (relayed by the proxy) to a decision. Only the status is
     * used; the body is never read. A 2xx means the message was handed off only once
     * the whole upload has completed.
     */
    private async learnResult(response: Response, stripped: StrippedBody): Promise<Decision> {
        const status = response.status;
        const success = status >= 200 && status < 300;
        if (!success) {
            // An early error answer stops an unfinished upload (by abort); the status is then classified.
            stripped.abort();
        } else if ((await stripped.settled) === 'complete') {
            // A 2xx counts only once the upload completes, so an early one waits for that or
            // its failure (the deadline fails it). The response body is left alone meanwhile:
            // cancelling it aborts the request, and the end of the upload with it. Node's fetch
            // writes the final chunk only after reading the stream's end, so one macrotask
            // passes before the cancel below (the smoke test fails without it).
            await nextMacrotask();
        }
        discard(response);
        const failure = this.streamFailure(stripped.failure());
        if (failure) {
            // Our own stream failed (truncated upload); our reason is authoritative over any status.
            return failure;
        }
        if (success && stripped.state() !== 'complete') {
            // The consumer stopped reading before the end: a partial upload is never a hand-off.
            this.log.error('upload_incomplete', { upstream: 'learn', upstreamStatus: status });
            return this.deadline.expired() ? retry('timeout', 503) : retry('upload_incomplete');
        }
        if (stripped.state() === 'complete') {
            this.log.info('message_streamed', { upstream: 'eml', bytes: stripped.stripper.inputBytes, removedHeaders: stripped.stripper.removedFields });
        }
        if (success) {
            // 208: already learned; 204: not learnable (token count, learn conditions). Log detail only.
            return trained(status === 208 ? 'already_learned' : status === 204 ? 'not_learnable' : 'trained');
        }
        if (status === 413) {
            return skipped('too_large');
        }
        if (status === 401 || status === 403) {
            this.options.trainingKey.invalidate();
            this.log.error('proxy_auth_failed', { upstream: 'learn', upstreamStatus: status });
            return retry('proxy_auth_failed');
        }
        if (status === 408 || status === 425 || status === 429 || status >= 500) {
            return retry('upstream_unavailable');
        }
        return skipped('learn_rejected');
    }
}
