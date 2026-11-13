import { randomUUID } from 'node:crypto';
import { version as packageVersion } from '../package.json';
import { ORIGIN_VERIFY_HEADER } from './config';
import { Deadline } from './deadline';
import { withFields, type LogFields, type Logger, type LogLevel } from './log';

/** Request summary fields plus the level of the final log line. */
type RequestFields = LogFields & { level?: LogLevel };
import { parsePayload } from './payload';
import type { OriginCheckSource, TrainingKeySource } from './secrets';
import { Trainer, type FetchLike } from './trainer';

export const SERVICE_NAME = 'wildduck-spam-trainer';
export const SERVICE_VERSION: string = packageVersion;
/** Webhook bodies (including BIMI SVGs) are tens of KB; anything above this is refused. */
export const MAX_BODY_BYTES = 1024 * 1024;

/** The subset of a Lambda Function URL (payload v2) event this service reads. */
export interface FunctionUrlEvent {
    rawPath?: string;
    headers?: Record<string, string | undefined>;
    body?: string;
    isBase64Encoded?: boolean;
    requestContext?: { requestId?: string; http?: { method?: string } };
}

export interface LambdaContextLike {
    awsRequestId?: string;
    getRemainingTimeInMillis?: () => number;
}

export interface HttpResult {
    statusCode: number;
    headers: Record<string, string>;
    body: string;
    isBase64Encoded: false;
}

export interface AppDependencies {
    readonly apiBaseUrl: string;
    readonly learnBaseUrl: string;
    readonly origin: OriginCheckSource;
    readonly trainingKey: TrainingKeySource;
    readonly fetch: FetchLike;
    readonly log: Logger;
    readonly now?: () => number;
}

type Route = '/healthz' | '/readyz' | '/hooks/wildduck';
const ROUTES: Record<Route, readonly string[]> = {
    '/healthz': ['GET', 'HEAD'],
    '/readyz': ['GET', 'HEAD'],
    '/hooks/wildduck': ['POST'],
};
const KNOWN_METHODS: ReadonlySet<string> = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const REQUEST_ID = /^[A-Za-z0-9-]{1,128}$/;

/**
 * WildDuck deletes a webhook that answers 410 Gone. Nothing here may ever send it:
 * every response passes through this guard.
 */
export function neverGone(result: HttpResult): HttpResult {
    return result.statusCode === 410 ? { ...result, statusCode: 500, body: JSON.stringify({ error: 'internal_error' }) } : result;
}

function json(statusCode: number, body: Record<string, unknown>, headers: Record<string, string> = {}): HttpResult {
    return neverGone({ statusCode, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers }, body: JSON.stringify(body), isBase64Encoded: false });
}

function header(event: FunctionUrlEvent, name: string): string | undefined {
    const headers = event.headers ?? {};
    const direct = headers[name];
    if (direct !== undefined) {
        return direct;
    }
    for (const [key, value] of Object.entries(headers)) {
        if (key.toLowerCase() === name) {
            return value;
        }
    }
    return undefined;
}

/** Decodes the body with the size cap applied before any allocation proportional to an oversized body. */
function bodyText(event: FunctionUrlEvent): string | 'too_large' {
    const raw = event.body ?? '';
    if (event.isBase64Encoded) {
        if (raw.length > Math.ceil(MAX_BODY_BYTES / 3) * 4 + 4) {
            return 'too_large';
        }
        const bytes = Buffer.from(raw, 'base64');
        return bytes.length > MAX_BODY_BYTES ? 'too_large' : bytes.toString('utf8');
    }
    // UTF-8 never encodes a UTF-16 code unit in fewer bytes, so this check is conservative.
    if (raw.length > MAX_BODY_BYTES || Buffer.byteLength(raw, 'utf8') > MAX_BODY_BYTES) {
        return 'too_large';
    }
    return raw;
}

export function createApp(deps: AppDependencies) {
    const now = deps.now ?? Date.now;
    const trainer = new Trainer({ apiBaseUrl: deps.apiBaseUrl, learnBaseUrl: deps.learnBaseUrl, fetch: deps.fetch, trainingKey: deps.trainingKey, log: deps.log, now });

    async function route(event: FunctionUrlEvent, context: LambdaContextLike | undefined, requestId: string, setFields: (extra: RequestFields) => void): Promise<HttpResult> {
        // 1. Origin verification, for every route (including health and unknown paths).
        const origin = await deps.origin.verify(header(event, ORIGIN_VERIFY_HEADER));
        if (origin === 'unavailable') {
            setFields({ outcome: 'origin_unavailable' });
            return json(503, { error: 'unavailable' });
        }
        if (origin !== 'ok') {
            setFields({ outcome: 'forbidden' });
            return json(403, { error: 'forbidden' });
        }
        // 2. Route and method.
        const path = event.rawPath ?? '/';
        const method = event.requestContext?.http?.method?.toUpperCase() ?? 'GET';
        if (!Object.hasOwn(ROUTES, path)) {
            setFields({ outcome: 'not_found' });
            return json(404, { error: 'not_found' });
        }
        const routeName = path as Route;
        setFields({ route: routeName });
        const allowed = ROUTES[routeName];
        if (!allowed.includes(method)) {
            setFields({ outcome: 'method_not_allowed' });
            return json(405, { error: 'method_not_allowed' }, { allow: allowed.join(', ') });
        }
        if (routeName === '/healthz') {
            setFields({ outcome: 'ok' });
            return json(200, { service: SERVICE_NAME, version: SERVICE_VERSION, status: 'ok' });
        }
        if (routeName === '/readyz') {
            const ready = (await deps.trainingKey.get()) !== undefined;
            setFields({ outcome: ready ? 'ready' : 'not_ready' });
            return json(ready ? 200 : 503, { ready });
        }
        // 3. Body size cap, 4. JSON parse, 5. validation.
        const text = bodyText(event);
        if (text === 'too_large') {
            setFields({ outcome: 'invalid', reason: 'body_too_large' });
            return json(413, { error: 'payload_too_large' });
        }
        let parsed: unknown;
        try {
            parsed = JSON.parse(text);
        } catch {
            setFields({ outcome: 'invalid', reason: 'invalid_json' });
            return json(400, { error: 'invalid_json' });
        }
        const payload = parsePayload(parsed);
        if (payload.kind === 'invalid') {
            setFields({ outcome: 'invalid', reason: payload.reason, ...(payload.deliveryId ? { deliveryId: payload.deliveryId } : {}) });
            return json(400, { error: 'invalid_payload' });
        }
        if (payload.kind === 'ignored') {
            setFields({ outcome: 'ignored', reason: 'unsupported_event', ...(payload.ev ? { ev: payload.ev } : {}), ...(payload.deliveryId ? { deliveryId: payload.deliveryId } : {}) });
            return json(200, { action: 'ignored' });
        }
        const { request } = payload;
        const requestFields: LogFields = { ev: request.ev, user: request.user, mailbox: request.mailbox, uid: request.uid, ...(request.deliveryId ? { deliveryId: request.deliveryId } : {}) };
        setFields(requestFields);
        const deadline = Deadline.fromContext(context?.getRemainingTimeInMillis ? () => context.getRemainingTimeInMillis?.() ?? 0 : undefined, now);
        const decision = await trainer.train(request, deadline, withFields(deps.log, { requestId, ...requestFields }));
        setFields({ outcome: decision.outcome, ...(decision.reason ? { reason: decision.reason } : {}), level: decision.level });
        return json(decision.status, { action: decision.action, ...(decision.action !== 'trained' && decision.reason ? { reason: decision.reason } : {}) });
    }

    return async function handle(event: FunctionUrlEvent, context?: LambdaContextLike): Promise<HttpResult> {
        const started = now();
        const candidate = context?.awsRequestId ?? event.requestContext?.requestId;
        const requestId = candidate && REQUEST_ID.test(candidate) ? candidate : randomUUID();
        const rawMethod = event.requestContext?.http?.method?.toUpperCase() ?? 'GET';
        const fields: RequestFields = { requestId, route: 'other', method: KNOWN_METHODS.has(rawMethod) ? rawMethod : 'other' };
        let result: HttpResult;
        try {
            result = await route(event, context, requestId, extra => Object.assign(fields, extra));
        } catch {
            // Never serialize the error: it could carry upstream or message data.
            fields.outcome = 'internal_error';
            fields.level = 'error';
            result = json(500, { error: 'internal_error' });
        }
        result = neverGone(result);
        const { level = 'info', ...logFields } = fields;
        deps.log[level]('request_completed', { ...logFields, status: result.statusCode, durationMs: Math.max(0, now() - started) });
        return result;
    };
}
