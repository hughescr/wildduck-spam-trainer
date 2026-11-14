import { createApp, type FunctionUrlEvent, type HttpResult } from '../src/app';
import { createLogger, type Logger } from '../src/log';
import type { OriginCheckSource, TrainingKeySource } from '../src/secrets';
import type { FetchLike } from '../src/trainer';

export const API = 'https://api.test/_mail-training/v1';
export const LEARN = 'https://learn.test/_mail-training/v1';
export const USER = '5f1e0c2b9a7d4e3f8a6b1c2d';
export const MAILBOX = '6a2f1d3c0b8e5f4a9b7c2d3e';
export const UID = 4242;
export const DELIVERY = '65a1b2c3d4e5f6a7b8c9d0e1:1';

/** Sensitive markers: none may ever appear in a log line. */
export const KEY = 'training-KEY-sensitive-0123456789';
export const ORIGIN_SECRET = 'OriginSecretSensitive0123456789abcdefABCDEF0123456789zz';
export const SUBJECT = 'Subject-Marker Quarterly Invoice';
export const ADDRESS = 'alice.marker@example.org';
export const MESSAGE_ID = '<msgid-marker-77@example.org>';
export const BODY_MARKER = 'BODY-CONTENT-MARKER';
export const SENSITIVE = [KEY, ORIGIN_SECRET, SUBJECT, ADDRESS, MESSAGE_ID, BODY_MARKER, 'msgid-marker', 'alice.marker', 'Subject-Marker'];

/** As WildDuck stores it: leading delivery fields, then the message with post-scan fields mixed in. */
export const RAW_MESSAGE = [
    `Delivered-To: ${ADDRESS}\r\n`,
    `Return-Path: <${ADDRESS}>\r\n`,
    'Received: from mx.example.org (mx.example.org [192.0.2.1])\r\n\tby mail.rungie.com; Mon, 1 Jan 2026 00:00:00 +0000\r\n',
    'Authentication-Results: mail.rungie.com; spf=pass smtp.mailfrom=example.org\r\n',
    'X-Spam-Flag: YES\r\n',
    'X-Rspamd-Score: 15.2\r\n\t(folded continuation)\r\n',
    `From: ${ADDRESS}\r\n`,
    `Subject: ${SUBJECT}\r\n`,
    `Message-ID: ${MESSAGE_ID}\r\n`,
    'WD-Mail-Classification: spam\r\n',
    '\r\n',
    `${BODY_MARKER}\r\nX-Rspamd-Score: 1\r\n`,
].join('');
/** RAW_MESSAGE minus the five removed fields (Delivered-To, Return-Path, X-Spam-Flag, X-Rspamd-Score, WD-Mail-Classification). */
export const STRIPPED_MESSAGE = [
    'Received: from mx.example.org (mx.example.org [192.0.2.1])\r\n\tby mail.rungie.com; Mon, 1 Jan 2026 00:00:00 +0000\r\n',
    'Authentication-Results: mail.rungie.com; spf=pass smtp.mailfrom=example.org\r\n',
    `From: ${ADDRESS}\r\n`,
    `Subject: ${SUBJECT}\r\n`,
    `Message-ID: ${MESSAGE_ID}\r\n`,
    '\r\n',
    `${BODY_MARKER}\r\nX-Rspamd-Score: 1\r\n`,
].join('');

export function webhookBody(overrides: Record<string, unknown> = {}): string {
    return JSON.stringify({
        id: DELIVERY, ev: 'marked.spam', time: 1767225600000, user: USER, mailbox: MAILBOX, message: UID,
        from: { name: 'Alice', address: ADDRESS }, to: [{ name: '', address: ADDRESS }], messageId: MESSAGE_ID, subject: SUBJECT,
        date: '2026-01-01T00:00:00.000Z', verificationResults: { tls: { name: 'TLSv1.3' } }, bimi: { image: `data:image/svg+xml;base64,${btoa(SUBJECT)}` },
        ...overrides,
    });
}

export function event(path: string, options: { method?: string; headers?: Record<string, string>; body?: string; base64?: boolean; sourceIp?: string } = {}): FunctionUrlEvent {
    return {
        rawPath: path,
        headers: { host: 'example.lambda-url.us-west-2.on.aws', 'x-origin-verify': ORIGIN_SECRET, 'user-agent': 'wildduck/1.47.0', ...options.headers },
        requestContext: { requestId: 'req-1', http: { method: options.method ?? 'GET', ...(options.sourceIp ? { sourceIp: options.sourceIp } : {}) } as { method: string } },
        ...(options.body === undefined ? {} : { body: options.base64 ? Buffer.from(options.body).toString('base64') : options.body }),
        isBase64Encoded: options.base64 === true,
    };
}

export const hook = (body = webhookBody(), headers: Record<string, string> = {}) => event('/hooks/wildduck', { method: 'POST', body, headers: { 'content-type': 'application/json', ...headers } });

export function staticOrigin(expected: readonly string[] = [ORIGIN_SECRET]): OriginCheckSource {
    return { verify: async value => (value !== undefined && expected.includes(value) ? 'ok' : 'mismatch') };
}

export class FakeKey implements TrainingKeySource {
    invalidations = 0;
    /** `null` models a missing key. */
    constructor(public value: string | null = KEY) {}
    async get() { return this.value ?? undefined; }
    invalidate() { this.invalidations++; }
}

export interface RecordedCall {
    url: string;
    method: string;
    headers: Headers;
    signal: AbortSignal;
    /** The upload as sent; a {@link streamingRoute} reads it itself. */
    stream?: ReadableStream<Uint8Array>;
    /** The drained upload (routes that are not streaming routes). */
    body?: Uint8Array;
    /** How the drained upload ended: its normal end, or an error. */
    uploadEnd?: 'eof' | 'error';
}
export type Route = (call: RecordedCall) => Response | Promise<Response>;

const STREAMING = Symbol('streaming');
/** Marks a route that reads the upload itself (`call.stream`), so it can answer before or while reading it. */
export const streamingRoute = (route: Route): Route => Object.assign(route, { [STREAMING]: true });
const isStreaming = (route: Route) => STREAMING in route;

/** What a {@link earlyLearn} double saw of the upload. */
export interface UploadSeen {
    /** Bytes received so far, as latin1 text. */
    text(): string;
    /** Chunks read before the double answered. */
    chunksBeforeResponse: number;
    /** How the upload ended (undefined while it is still running). */
    end: 'eof' | 'error' | undefined;
    /** Settles when the background read of the upload ends. */
    done: Promise<void>;
    call?: RecordedCall;
}

/**
 * A learn double that answers after reading `readFirst` upload chunks and then keeps
 * reading the rest in the background, like a server that answers early.
 */
export function earlyLearn(respond: () => Response, readFirst = 1): { route: Route; upload: UploadSeen } {
    const parts: Uint8Array[] = [];
    const upload: UploadSeen = { text: () => Buffer.concat(parts).toString('latin1'), chunksBeforeResponse: 0, end: undefined, done: Promise.resolve() };
    const route = streamingRoute(async call => {
        upload.call = call;
        if (!call.stream) {
            throw new Error('expected a streaming upload');
        }
        const reader = call.stream.getReader();
        const readOne = async (): Promise<boolean> => {
            const { done, value } = await reader.read();
            if (done) {
                upload.end = 'eof';
                return false;
            }
            parts.push(value);
            return true;
        };
        try {
            for (let index = 0; index < readFirst && await readOne(); index++) {
                upload.chunksBeforeResponse++;
            }
        } catch {
            upload.end = 'error';
        }
        upload.done = (async () => {
            try {
                while (upload.end === undefined && await readOne()) {
                    // Keep reading after answering.
                }
            } catch {
                upload.end = 'error';
            }
        })();
        return respond();
    });
    return { route, upload };
}

/** Reads a whole upload like a server would, recording how it ended; an error rejects like fetch does. */
async function drain(call: RecordedCall, stream: ReadableStream<Uint8Array>): Promise<void> {
    const reader = stream.getReader();
    const parts: Uint8Array[] = [];
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done) {
                break;
            }
            parts.push(value);
        }
    } catch (error) {
        call.uploadEnd = 'error';
        call.body = new Uint8Array(Buffer.concat(parts));
        throw new TypeError('fetch failed', { cause: error });
    }
    call.uploadEnd = 'eof';
    call.body = new Uint8Array(Buffer.concat(parts));
    if (call.signal.aborted) {
        throw call.signal.reason;
    }
}

const jsonResponse = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
export const mailboxResponse = (specialUse: string | null, id = MAILBOX) => jsonResponse(200, { success: true, id, path: specialUse ? specialUse.slice(1) : 'INBOX', specialUse });
export const messageResponse = (overrides: Record<string, unknown> = {}) => jsonResponse(200, { success: true, id: UID, mailbox: MAILBOX, user: USER, size: RAW_MESSAGE.length, flagged: false, flags: ['\\Seen'], subject: SUBJECT, from: { address: ADDRESS }, messageId: MESSAGE_ID, ...overrides });
export const emlResponse = (raw: string | Uint8Array<ArrayBuffer> | ReadableStream<Uint8Array> = RAW_MESSAGE, headers: Record<string, string> = {}) => new Response(raw, { status: 200, headers: { 'content-type': 'message/rfc822', ...headers } });
export const status = (code: number, body = `{"error":"${SUBJECT} ${ADDRESS}"}`) => new Response(code === 204 ? null : body, { status: code });
export { jsonResponse };

export interface Routes {
    mailbox?: Route;
    message?: Route;
    eml?: Route;
    learn?: Route;
}

/**
 * A recording fetch double. Each request is recorded on entry, before any body is
 * read, so "no request" assertions cannot pass vacuously. Unless the route is a
 * {@link streamingRoute}, the upload is drained before the route answers. Unrouted
 * URLs fail the test loudly.
 */
export function mockFetch(routes: Routes) {
    const calls: RecordedCall[] = [];
    const base = `${API}/users/${USER}/mailboxes/${MAILBOX}`;
    const fetch: FetchLike = async (input, init) => {
        const headers = new Headers(init.headers as Record<string, string>);
        if (init.redirect !== 'error' || !init.signal) {
            throw new Error('every upstream request must use redirect: error and an abort signal');
        }
        const call: RecordedCall = { url: input, method: init.method ?? 'GET', headers, signal: init.signal, ...(init.body instanceof ReadableStream ? { stream: init.body } : {}) };
        calls.push(call);
        let route: Route | undefined;
        if (input === base) { route = routes.mailbox; }
        else if (input === `${base}/messages/${UID}`) { route = routes.message; }
        else if (input === `${base}/messages/${UID}/message.eml`) { route = routes.eml; }
        else if (input === `${LEARN}/learn-spam` || input === `${LEARN}/learn-ham`) { route = routes.learn; }
        if (!route) {
            throw new Error(`unexpected upstream request ${input}`);
        }
        if (call.stream && !isStreaming(route)) {
            await drain(call, call.stream);
        }
        return route(call);
    };
    return { fetch, calls };
}

export function captureLogs(): { log: Logger; lines: string[]; records: () => Record<string, unknown>[] } {
    const lines: string[] = [];
    return { log: createLogger(line => lines.push(line)), lines, records: () => lines.map(line => JSON.parse(line) as Record<string, unknown>) };
}

export function buildApp(options: { routes?: Routes; key?: FakeKey; origin?: OriginCheckSource } = {}) {
    const { fetch, calls } = mockFetch(options.routes ?? {});
    const logs = captureLogs();
    const key = options.key ?? new FakeKey();
    const app = createApp({ apiBaseUrl: API, learnBaseUrl: LEARN, origin: options.origin ?? staticOrigin(), trainingKey: key, fetch, log: logs.log });
    return { app, calls, key, ...logs };
}

export const parse = (result: HttpResult) => JSON.parse(result.body) as Record<string, unknown>;

export const spamRoutes = (overrides: Routes = {}): Routes => ({ mailbox: () => mailboxResponse('\\Junk'), eml: () => emlResponse(), learn: () => jsonResponse(200, { success: true }), ...overrides });
export const hamRoutes = (overrides: Routes = {}): Routes => ({ mailbox: () => mailboxResponse(null), message: () => messageResponse(), eml: () => emlResponse(), learn: () => jsonResponse(200, { success: true }), ...overrides });
export const hamHook = () => hook(webhookBody({ ev: 'marked.ham' }));
