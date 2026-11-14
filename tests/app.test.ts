import { describe, expect, test } from 'bun:test';
import { MAX_BODY_BYTES, neverGone, SERVICE_VERSION, type HttpResult } from '../src/app';
import { OriginVerifier } from '../src/secrets';
import { buildApp, captureLogs, event, hook, jsonResponse, mailboxResponse, ORIGIN_SECRET, parse, spamRoutes, staticOrigin, webhookBody, FakeKey, emlResponse } from './helpers';
import packageJson from '../package.json';

const expectJsonNoStore = (result: HttpResult) => {
    expect(result.headers['content-type']).toBe('application/json');
    expect(result.headers['cache-control']).toBe('no-store');
};

describe('origin verification precedes everything', () => {
    for (const [name, headers] of [['missing', { 'x-origin-verify': '' }], ['wrong', { 'x-origin-verify': 'WrongValue0123456789WrongValue0123456789' }]] as const) {
        test(`${name} origin header is a uniform 403 on every route, including health`, async () => {
            const { app, calls } = buildApp({ routes: spamRoutes() });
            for (const request of [event('/healthz', { headers }), event('/readyz', { headers }), event('/nope', { headers }), hook(webhookBody(), headers)]) {
                const result = await app(request);
                expect(result.statusCode).toBe(403);
                expect(parse(result)).toEqual({ error: 'forbidden' });
                expectJsonNoStore(result);
            }
            expect(calls).toHaveLength(0);
        });
    }

    test('a direct Function URL request (no CloudFront header at all) cannot bypass', async () => {
        const { app, calls } = buildApp({ routes: spamRoutes() });
        const direct = hook();
        delete direct.headers?.['x-origin-verify'];
        expect((await app(direct)).statusCode).toBe(403);
        expect(calls).toHaveLength(0);
    });

    test('newly forwarded viewer headers neither authenticate nor redirect Lambda processing', async () => {
        const { app, calls } = buildApp();
        const viewerHeaders = {
            host: 'viewer.invalid', 'x-forwarded-for': '54.71.178.94',
            'x-forwarded-host': 'viewer.invalid', 'x-forwarded-proto': 'http',
            'x-real-ip': '54.71.178.94', 'cloudfront-viewer-address': '54.71.178.94:443',
            authorization: 'viewer-token', cookie: 'viewer-cookie',
        };
        expect((await app(hook('{"ev":"deployment.probe"}', { ...viewerHeaders, 'x-origin-verify': '' }))).statusCode).toBe(403);
        const result = await app(hook('{"ev":"deployment.probe"}', viewerHeaders));
        expect(result.statusCode).toBe(200);
        expect(parse(result)).toEqual({ action: 'ignored' });
        expect(calls).toHaveLength(0);
    });

    test('origin secret unavailable fails closed with 503', async () => {
        const { app, calls } = buildApp({ origin: { verify: async () => 'unavailable' }, routes: spamRoutes() });
        for (const request of [event('/healthz'), hook()]) {
            expect((await app(request)).statusCode).toBe(503);
        }
        expect(calls).toHaveLength(0);
    });

    test('one request deadline, created before origin verification, governs every later step', async () => {
        let originSignal: AbortSignal | undefined;
        let keySignal: AbortSignal | undefined;
        const key = new FakeKey();
        key.get = async (signal?: AbortSignal) => { keySignal = signal; return key.value ?? undefined; };
        const { app, calls } = buildApp({ key, routes: spamRoutes(), origin: { verify: async (value, signal) => { originSignal = signal; return value === ORIGIN_SECRET ? 'ok' : 'mismatch'; } } });
        expect(parse(await app(hook(), { getRemainingTimeInMillis: () => 25_000 }))).toEqual({ action: 'trained' });
        expect(originSignal).toBeInstanceOf(AbortSignal);
        expect(keySignal).toBe(originSignal);
        // The .eml download uses the request deadline's signal directly. The learn upload's
        // signal follows the deadline and also aborts when the upload is interrupted (the
        // deadline half is covered by the learn-hang and mid-upload deadline tests).
        expect(calls[1]?.signal).toBe(originSignal);
        expect(calls[2]?.signal).toBeInstanceOf(AbortSignal);
        expect(calls[2]?.signal).not.toBe(originSignal);
        expect(calls[2]?.signal.aborted).toBe(false);
    });

    test('time spent verifying the origin counts against the request deadline', async () => {
        const hang = (call: { signal: AbortSignal }) => new Promise<Response>((_resolve, reject) => call.signal.addEventListener('abort', () => reject(call.signal.reason), { once: true }));
        const { app } = buildApp({ routes: spamRoutes({ mailbox: hang }), origin: { verify: async () => { await Bun.sleep(300); return 'ok'; } } });
        const started = Date.now();
        // 3.4 s remaining minus the 3 s reserve: a 400 ms budget for the whole request.
        const result = await app(hook(), { getRemainingTimeInMillis: () => 3_400 });
        expect(result.statusCode).toBe(503);
        expect(parse(result)).toEqual({ action: 'retry', reason: 'timeout' });
        // A deadline started after verification would end at about 700 ms.
        expect(Date.now() - started).toBeLessThan(650);
    });

    test('a hanging origin-secret load is cut off by the request deadline (fail closed, 503)', async () => {
        const logs = captureLogs();
        const hanging = { send: (_command: unknown, options?: { abortSignal?: AbortSignal }) => new Promise<never>((_resolve, reject) => options?.abortSignal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true })) };
        const origin = new OriginVerifier({ client: () => hanging, secretId: 'wildduck-spam-trainer/prod/origin-verify-key', log: logs.log, timeoutMs: 10_000 });
        const { app, calls } = buildApp({ routes: spamRoutes(), origin });
        const started = Date.now();
        const result = await app(hook(), { getRemainingTimeInMillis: () => 3_200 });
        expect(result.statusCode).toBe(503);
        expect(parse(result)).toEqual({ error: 'unavailable' });
        expect(Date.now() - started).toBeLessThan(2_000);
        expect(calls).toHaveLength(0);
    });

    test('header lookup is case-insensitive', async () => {
        const { app } = buildApp();
        const request = event('/healthz');
        delete request.headers?.['x-origin-verify'];
        request.headers = { ...request.headers, 'X-Origin-Verify': ORIGIN_SECRET };
        expect((await app(request)).statusCode).toBe(200);
    });
});

describe('routes', () => {
    test('health reports only service, version and status', async () => {
        const { app } = buildApp({ key: new FakeKey(null) });
        const result = await app(event('/healthz'));
        expect(result.statusCode).toBe(200);
        expect(parse(result)).toEqual({ service: 'wildduck-spam-trainer', version: packageJson.version, status: 'ok' });
        expect(SERVICE_VERSION).toBe(packageJson.version);
        expectJsonNoStore(result);
    });

    test('readiness is 200 only when the training key loads, revealing nothing else', async () => {
        expect(parse(await buildApp().app(event('/readyz')))).toEqual({ ready: true });
        const missing = await buildApp({ key: new FakeKey(null) }).app(event('/readyz'));
        expect(missing.statusCode).toBe(503);
        expect(parse(missing)).toEqual({ ready: false });
    });

    test('webhook path is exact; tricks are 404 after origin verification', async () => {
        const { app, calls } = buildApp({ routes: spamRoutes() });
        for (const path of ['/hooks/wildduck/', '/HOOKS/wildduck', '//hooks/wildduck', '/hooks%2Fwildduck', '/hooks/wildduck%00', '/hooks/./wildduck', '/', '/healthz/']) {
            const result = await app(event(path, { method: 'POST', body: webhookBody() }));
            expect(result.statusCode).toBe(404);
        }
        expect(calls).toHaveLength(0);
    });

    test('method is enforced per route', async () => {
        const { app } = buildApp();
        const get = await app(event('/hooks/wildduck'));
        expect(get.statusCode).toBe(405);
        expect(get.headers['allow']).toBe('POST');
        const post = await app(event('/healthz', { method: 'POST', body: '{}' }));
        expect(post.statusCode).toBe(405);
        expect(post.headers['allow']).toBe('GET, HEAD');
    });
});

describe('payload handling', () => {
    test('body size cap applies to raw and base64 bodies before parsing', async () => {
        const { app, calls } = buildApp({ routes: spamRoutes() });
        const big = webhookBody({ padding: 'x'.repeat(MAX_BODY_BYTES) });
        expect((await app(hook(big))).statusCode).toBe(413);
        expect((await app(event('/hooks/wildduck', { method: 'POST', body: big, base64: true }))).statusCode).toBe(413);
        expect(calls).toHaveLength(0);
    });

    test('base64-encoded bodies are decoded', async () => {
        const { app } = buildApp({ routes: spamRoutes() });
        const result = await app(event('/hooks/wildduck', { method: 'POST', body: webhookBody(), base64: true }));
        expect(parse(result)).toEqual({ action: 'trained' });
    });

    test('a typical tens-of-KB payload with a BIMI SVG is accepted', async () => {
        const { app } = buildApp({ routes: spamRoutes() });
        const result = await app(hook(webhookBody({ bimi: { image: `data:image/svg+xml;base64,${'A'.repeat(60_000)}` } })));
        expect(result.statusCode).toBe(200);
    });

    test('unsupported events are acknowledged without upstream calls', async () => {
        const { app, calls } = buildApp();
        for (const ev of ['messages.new', 'marked.other', 'MARKED.SPAM', '']) {
            const result = await app(hook(webhookBody({ ev })));
            expect(result.statusCode).toBe(200);
            expect(parse(result)).toEqual({ action: 'ignored' });
        }
        expect(calls).toHaveLength(0);
    });

    const malformed: [string, string][] = [
        ['invalid JSON', '{"ev":'],
        ['array', '[]'],
        ['null', 'null'],
        ['missing ev', JSON.stringify({ user: 'a', mailbox: 'b', message: 1 })],
        ['bad user', webhookBody({ user: 'not-an-object-id' })],
        ['user with path', webhookBody({ user: '../../../../admin/aaaaaaa' })],
        ['bad mailbox', webhookBody({ mailbox: `${'a'.repeat(23)}/` })],
        ['mailbox too long', webhookBody({ mailbox: 'a'.repeat(25) })],
        ['message zero', webhookBody({ message: 0 })],
        ['message negative', webhookBody({ message: -1 })],
        ['message fractional', webhookBody({ message: 1.5 })],
        ['message string', webhookBody({ message: '42' })],
        ['message unsafe', webhookBody({ message: 2 ** 53 })],
        ['message ObjectId', webhookBody({ message: '65a1b2c3d4e5f6a7b8c9d0e1' })],
    ];
    for (const [name, body] of malformed) {
        test(`malformed payload (${name}) is 400 with no upstream call`, async () => {
            const { app, calls } = buildApp({ routes: spamRoutes() });
            const result = await app(hook(body));
            expect(result.statusCode).toBe(400);
            expect(calls).toHaveLength(0);
        });
    }

    test('upper-case hex identifiers are accepted and normalized before interpolation', async () => {
        const { app, calls } = buildApp({ routes: spamRoutes() });
        const { USER, MAILBOX } = await import('./helpers');
        const result = await app(hook(webhookBody({ user: USER.toUpperCase(), mailbox: MAILBOX.toUpperCase() })));
        expect(parse(result)).toEqual({ action: 'trained' });
        expect(calls[0]?.url).toContain(`/users/${USER}/mailboxes/${MAILBOX}`);
    });
});

describe('source address is never a decision input', () => {
    test('requestContext.http.sourceIp and X-Forwarded-For do not change any outcome', async () => {
        for (const sourceIp of ['54.71.178.94', '203.0.113.9', '2600:1f14:e8d:b300:9114:71e8:b97:39c']) {
            for (const xff of ['54.71.178.94', '203.0.113.9, 54.71.178.94', '']) {
                const allowed = buildApp({ routes: spamRoutes() });
                const ok = await allowed.app({ ...hook(webhookBody(), { 'x-forwarded-for': xff }), requestContext: { requestId: 'r', http: { method: 'POST', sourceIp } as { method: string } } });
                expect(parse(ok)).toEqual({ action: 'trained' });
                const denied = buildApp({ routes: spamRoutes(), origin: staticOrigin(['SomeOtherValue0123456789SomeOtherValue0123']) });
                const no = await denied.app({ ...hook(webhookBody(), { 'x-forwarded-for': xff }), requestContext: { requestId: 'r', http: { method: 'POST', sourceIp } as { method: string } } });
                expect(no.statusCode).toBe(403);
            }
        }
    });

    test('source code never reads sourceIp or X-Forwarded-For', async () => {
        const glob = new Bun.Glob('src/**/*.ts');
        for await (const file of glob.scan('.')) {
            const text = await Bun.file(file).text();
            expect(text.toLowerCase()).not.toContain('x-forwarded-for');
            expect(text).not.toContain('sourceIp');
            expect(text.toLowerCase()).not.toContain('viewer-address');
        }
    });
});

describe('never 410', () => {
    test('central guard rewrites 410', () => {
        expect(neverGone({ statusCode: 410, headers: {}, body: '', isBase64Encoded: false }).statusCode).toBe(500);
        expect(neverGone({ statusCode: 200, headers: {}, body: 'x', isBase64Encoded: false }).statusCode).toBe(200);
    });

    test('upstream 410 at every step never becomes a 410 response', async () => {
        const gone = () => new Response('gone', { status: 410 });
        for (const routes of [
            spamRoutes({ mailbox: gone }),
            spamRoutes({ eml: gone }),
            spamRoutes({ learn: gone }),
            { mailbox: () => mailboxResponse(null), message: gone },
        ]) {
            const { app } = buildApp({ routes });
            for (const ev of ['marked.spam', 'marked.ham']) {
                const result = await app(hook(webhookBody({ ev })));
                expect(result.statusCode).not.toBe(410);
            }
        }
    });

    test('unexpected internal errors become 500, not 410, and are not serialized', async () => {
        const { app, lines } = buildApp({ origin: { verify: async () => { throw new Error(`boom ${ORIGIN_SECRET}`); } } });
        const result = await app(hook());
        expect(result.statusCode).toBe(500);
        expect(lines.join('\n')).not.toContain(ORIGIN_SECRET);
        expect(lines.join('\n')).not.toContain('boom');
    });

    test('no status table in the source maps to 410', async () => {
        const glob = new Bun.Glob('src/**/*.ts');
        for await (const file of glob.scan('.')) {
            const text = await Bun.file(file).text();
            const matches = text.match(/\b410\b/g) ?? [];
            // Only the guard itself mentions 410.
            expect(file === 'src/app.ts' ? matches.length <= 2 : matches.length === 0).toBe(true);
        }
    });

    test('every response type is small JSON with no-store', async () => {
        const { app } = buildApp({ routes: spamRoutes({ learn: () => jsonResponse(500, {}) , eml: () => emlResponse() }) });
        for (const request of [event('/healthz'), event('/readyz'), event('/x'), event('/hooks/wildduck'), hook('{'), hook(), hook(webhookBody({ ev: 'x.y' }))]) {
            const result = await app(request);
            expectJsonNoStore(result);
            expect(result.body.length).toBeLessThan(200);
        }
    });
});
