import { describe, expect, test } from 'bun:test';
import { DEFAULT_API_BASE_URL, DEFAULT_LEARN_BASE_URL, loadConfig, normalizeBaseUrl } from '../src/config';
import { buildRecord, createLogger, withFields } from '../src/log';
import { parsePayload } from '../src/payload';
import { Deadline } from '../src/deadline';

describe('configuration', () => {
    test('defaults are the fixed production bases with nothing configured (fail closed)', () => {
        expect(loadConfig({})).toEqual({ apiBaseUrl: DEFAULT_API_BASE_URL, learnBaseUrl: DEFAULT_LEARN_BASE_URL });
        expect(DEFAULT_API_BASE_URL).toBe('https://wildduck-api.rungie.com/_mail-training/v1');
        expect(DEFAULT_LEARN_BASE_URL).toBe('https://spam.rungie.com/_mail-training/v1');
    });

    test('names are validated', () => {
        expect(loadConfig({ TRAINING_PROXY_KEY_PARAMETER: '/wildduck-spam-trainer/prod/training-proxy-key', ORIGIN_VERIFY_SECRET_ID: 'wildduck-spam-trainer/prod/origin-verify-key' })).toMatchObject({
            trainingProxyKeyParameter: '/wildduck-spam-trainer/prod/training-proxy-key',
            originVerifySecretId: 'wildduck-spam-trainer/prod/origin-verify-key',
        });
        expect(() => loadConfig({ TRAINING_PROXY_KEY_PARAMETER: 'no-leading-slash' })).toThrow();
        expect(() => loadConfig({ TRAINING_PROXY_KEY_PARAMETER: '/aws/reference/secretsmanager/x' })).toThrow();
        expect(() => loadConfig({ ORIGIN_VERIFY_SECRET_ID: 'bad name with spaces' })).toThrow();
    });

    test('base URL overrides must be HTTPS (or loopback HTTP) without credentials, query or fragment', () => {
        expect(normalizeBaseUrl('https://example.test/base/', 'X')).toBe('https://example.test/base');
        expect(normalizeBaseUrl('http://127.0.0.1:8080/x', 'X')).toBe('http://127.0.0.1:8080/x');
        for (const bad of ['http://example.test', 'https://user:pass@example.test', 'https://example.test/?q=1', 'https://example.test/#f', 'ftp://example.test', 'not a url']) {
            expect(() => normalizeBaseUrl(bad, 'X')).toThrow();
        }
    });
});

describe('logging allowlist', () => {
    test('unknown fields and malformed values are dropped', () => {
        const record = buildRecord('info', 'request_completed', {
            requestId: 'abc-123', user: 'not-an-id', mailbox: 'a'.repeat(24), uid: -1, reason: 'Has Spaces', outcome: 'trained', status: 999,
            ...({ subject: 'secret subject', url: 'https://x', headers: { a: 1 } } as Record<string, unknown>),
        }, 0);
        expect(record).toEqual({ level: 'info', event: 'request_completed', time: '1970-01-01T00:00:00.000Z', requestId: 'abc-123', mailbox: 'a'.repeat(24), outcome: 'trained' });
    });

    test('event names are tokens; anything else is replaced', () => {
        expect(buildRecord('warn', 'Subject: hello', {}, 0)['event']).toBe('invalid_event');
    });

    test('sink failures never propagate', () => {
        const log = createLogger(() => { throw new Error('sink down'); });
        expect(() => log.error('x')).not.toThrow();
    });

    test('withFields binds request fields', () => {
        const lines: string[] = [];
        withFields(createLogger(line => lines.push(line)), { requestId: 'r1' }).info('upstream_response', { upstream: 'learn', upstreamStatus: 208 });
        expect(JSON.parse(lines[0] ?? '{}')).toMatchObject({ requestId: 'r1', upstream: 'learn', upstreamStatus: 208 });
    });
});

describe('payload parsing', () => {
    test('valid training events are normalized; ids only logged when well-formed', () => {
        expect(parsePayload({ id: 'x', ev: 'marked.ham', user: 'A'.repeat(24), mailbox: 'b'.repeat(24), message: 9 })).toEqual({ kind: 'train', request: { ev: 'marked.ham', user: 'a'.repeat(24), mailbox: 'b'.repeat(24), uid: 9 } });
    });

    test('unsupported events with odd names are ignored without echoing the name', () => {
        expect(parsePayload({ ev: 'Subject: secret' })).toEqual({ kind: 'ignored' });
        expect(parsePayload({ ev: 'messages.new' })).toEqual({ kind: 'ignored', ev: 'messages.new' });
    });
});

describe('deadline', () => {
    test('derives from the Lambda context with a response reserve, capped at 20 s', () => {
        expect(Deadline.fromContext(() => 25_000).remainingMs()).toBeLessThanOrEqual(20_000);
        expect(Deadline.fromContext(() => 25_000).remainingMs()).toBeGreaterThan(19_000);
        expect(Deadline.fromContext(() => 5_000).remainingMs()).toBeLessThanOrEqual(2_000);
        expect(Deadline.fromContext(() => { throw new Error('x'); }).expired()).toBe(true);
        expect(Deadline.fromContext(undefined).remainingMs()).toBeGreaterThan(19_000);
    });
});
