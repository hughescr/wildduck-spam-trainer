import { describe, expect, test } from 'bun:test';
import { MAX_MESSAGE_BYTES } from '../src/header-strip';
import {
    ADDRESS, BODY_MARKER, buildApp, emlResponse, FakeKey, hamHook, hamRoutes, hook, jsonResponse, KEY, LEARN, mailboxResponse, messageResponse, parse,
    RAW_MESSAGE, SENSITIVE, spamRoutes, status, STRIPPED_MESSAGE, SUBJECT, UID, USER, MAILBOX, webhookBody, type Routes,
} from './helpers';

const text = (bytes: Uint8Array | undefined) => new TextDecoder().decode(bytes);

describe('marked.spam', () => {
    test('trains only from \\Junk, streaming the stripped message to learn-spam', async () => {
        const { app, calls } = buildApp({ routes: spamRoutes() });
        const result = await app(hook());
        expect(result.statusCode).toBe(200);
        expect(parse(result)).toEqual({ action: 'trained' });
        expect(calls.map(call => call.url)).toEqual([
            `https://api.test/_mail-training/v1/users/${USER}/mailboxes/${MAILBOX}`,
            `https://api.test/_mail-training/v1/users/${USER}/mailboxes/${MAILBOX}/messages/${UID}/message.eml`,
            `${LEARN}/learn-spam`,
        ]);
        const learn = calls[2];
        expect(learn?.method).toBe('POST');
        expect(learn?.headers.get('content-type')).toBe('message/rfc822');
        expect(text(learn?.body)).toBe(STRIPPED_MESSAGE);
    });

    for (const specialUse of [null, '\\Inbox', '\\Trash', '\\junk', 'Junk', '\\Junk ', '\\Sent']) {
        test(`ignores a mailbox whose specialUse is ${JSON.stringify(specialUse)}`, async () => {
            const { app, calls } = buildApp({ routes: spamRoutes({ mailbox: () => mailboxResponse(specialUse) }) });
            const result = await app(hook());
            expect(parse(result)).toEqual({ action: 'ignored', reason: 'not_in_junk' });
            expect(calls).toHaveLength(1);
        });
    }
});

describe('marked.ham', () => {
    test('trains a non-flagged message outside Junk/Trash via learn-ham', async () => {
        const { app, calls } = buildApp({ routes: hamRoutes() });
        const result = await app(hamHook());
        expect(parse(result)).toEqual({ action: 'trained' });
        expect(calls.map(call => call.url.split('/').slice(-1)[0])).toEqual([MAILBOX, String(UID), 'message.eml', 'learn-ham']);
        expect(text(calls[3]?.body)).toBe(STRIPPED_MESSAGE);
    });

    test('a starred/flagged message is not a ham signal (flagged boolean)', async () => {
        const { app, calls } = buildApp({ routes: hamRoutes({ message: () => messageResponse({ flagged: true, flags: [] }) }) });
        expect(parse(await app(hamHook()))).toEqual({ action: 'ignored', reason: 'flagged' });
        expect(calls).toHaveLength(2);
    });

    for (const flag of ['\\Flagged', '\\flagged', '\\FLAGGED']) {
        test(`a message with flag ${flag} is not a ham signal`, async () => {
            const { app, calls } = buildApp({ routes: hamRoutes({ message: () => messageResponse({ flagged: false, flags: ['\\Seen', flag] }) }) });
            expect(parse(await app(hamHook()))).toEqual({ action: 'ignored', reason: 'flagged' });
            expect(calls).toHaveLength(2);
        });
    }

    test('ignored while in Junk or Trash', async () => {
        for (const [specialUse, reason] of [['\\Junk', 'in_junk'], ['\\Trash', 'in_trash']] as const) {
            const { app, calls } = buildApp({ routes: hamRoutes({ mailbox: () => mailboxResponse(specialUse) }) });
            expect(parse(await app(hamHook()))).toEqual({ action: 'ignored', reason });
            expect(calls).toHaveLength(1);
        }
    });

    const mismatches: [string, Record<string, unknown>][] = [
        ['user', { user: 'f'.repeat(24) }],
        ['mailbox', { mailbox: 'e'.repeat(24) }],
        ['uid', { id: UID + 1 }],
    ];
    for (const [field, override] of mismatches) {
        test(`identity mismatch on ${field} is a permanent skip without training`, async () => {
            const { app, calls } = buildApp({ routes: hamRoutes({ message: () => messageResponse(override) }) });
            expect(parse(await app(hamHook()))).toEqual({ action: 'skipped', reason: 'identity_mismatch' });
            expect(calls).toHaveLength(2);
        });
    }

    test('mailbox identity mismatch is a permanent skip', async () => {
        const { app, calls } = buildApp({ routes: hamRoutes({ mailbox: () => mailboxResponse(null, 'd'.repeat(24)) }) });
        expect(parse(await app(hamHook()))).toEqual({ action: 'skipped', reason: 'identity_mismatch' });
        expect(calls).toHaveLength(1);
    });

    test('message state without flags is not trusted (retryable invalid_response)', async () => {
        const { app } = buildApp({ routes: hamRoutes({ message: () => messageResponse({ flags: undefined }) }) });
        const result = await app(hamHook());
        expect(result.statusCode).toBe(502);
        expect(parse(result)).toEqual({ action: 'retry', reason: 'invalid_response' });
    });

    test('a message whose size exceeds 25 MiB is skipped before downloading', async () => {
        const { app, calls } = buildApp({ routes: hamRoutes({ message: () => messageResponse({ size: MAX_MESSAGE_BYTES + 1 }) }) });
        expect(parse(await app(hamHook()))).toEqual({ action: 'skipped', reason: 'too_large' });
        expect(calls).toHaveLength(2);
    });
});

describe('stale and temporary failures at each step', () => {
    const steps: [string, keyof Routes, () => Routes][] = [
        ['spam mailbox', 'mailbox', () => spamRoutes()],
        ['spam eml', 'eml', () => spamRoutes()],
        ['ham mailbox', 'mailbox', () => hamRoutes()],
        ['ham message', 'message', () => hamRoutes()],
        ['ham eml', 'eml', () => hamRoutes()],
    ];
    for (const [name, step, routes] of steps) {
        const hookFor = () => (name.startsWith('ham') ? hamHook() : hook());
        test(`${name}: 404 is a harmless stale no-op`, async () => {
            const { app, calls } = buildApp({ routes: { ...routes(), [step]: () => status(404) } });
            const result = await app(hookFor());
            expect(result.statusCode).toBe(200);
            expect(parse(result)).toEqual({ action: 'skipped', reason: 'stale' });
            expect(calls.some(call => call.url.startsWith(LEARN))).toBe(false);
        });
        for (const code of [408, 425, 429, 500, 502, 503, 504]) {
            test(`${name}: HTTP ${code} is retryable`, async () => {
                const { app, lines } = buildApp({ routes: { ...routes(), [step]: () => status(code) } });
                const result = await app(hookFor());
                expect(result.statusCode).toBe(502);
                expect(parse(result)).toEqual({ action: 'retry', reason: 'upstream_unavailable' });
                expect(lines.some(line => JSON.parse(line).level === 'error')).toBe(true);
            });
        }
        test(`${name}: network error is retryable`, async () => {
            const { app } = buildApp({ routes: { ...routes(), [step]: () => { throw new TypeError('fetch failed'); } } });
            const result = await app(hookFor());
            expect(result.statusCode).toBe(502);
            expect(parse(result)).toEqual({ action: 'retry', reason: 'upstream_unreachable' });
        });
        test(`${name}: timeout is retryable 503`, async () => {
            const { app } = buildApp({ routes: { ...routes(), [step]: () => { throw new DOMException('timed out', 'TimeoutError'); } } });
            const result = await app(hookFor());
            expect(result.statusCode).toBe(503);
            expect(parse(result)).toEqual({ action: 'retry', reason: 'timeout' });
        });
        for (const code of [401, 403]) {
            test(`${name}: proxy ${code} (misconfigured key) is retryable and invalidates the cached key`, async () => {
                const { app, key } = buildApp({ routes: { ...routes(), [step]: () => status(code) } });
                const result = await app(hookFor());
                expect(result.statusCode).toBe(502);
                expect(parse(result)).toEqual({ action: 'retry', reason: 'proxy_auth_failed' });
                expect(key.invalidations).toBe(1);
            });
        }
    }

    for (const [name, step, routes] of [['mailbox', 'mailbox', spamRoutes], ['message', 'message', hamRoutes]] as const) {
        test(`${name}: 200 with success !== true is retryable`, async () => {
            for (const body of [{ success: false }, { error: 'x' }, 'not json']) {
                const response = () => (typeof body === 'string' ? new Response(body, { status: 200 }) : jsonResponse(200, body));
                const { app } = buildApp({ routes: { ...routes(), [step]: response } });
                const result = await app(step === 'message' ? hamHook() : hook());
                expect(result.statusCode).toBe(502);
            }
        });
    }

    test('missing training key is 503 without any upstream request', async () => {
        const { app, calls } = buildApp({ routes: spamRoutes(), key: new FakeKey(null) });
        const result = await app(hook());
        expect(result.statusCode).toBe(503);
        expect(parse(result)).toEqual({ action: 'retry', reason: 'training_key_unavailable' });
        expect(calls).toHaveLength(0);
    });

    test('the request deadline (from the Lambda context) aborts a hanging upstream with a clean 503', async () => {
        // Hangs until the request signal aborts, like a real fetch.
        const hang = (call: { signal: AbortSignal }) => new Promise<Response>((_resolve, reject) => call.signal.addEventListener('abort', () => reject(call.signal.reason), { once: true }));
        for (const routes of [spamRoutes({ mailbox: hang }), spamRoutes({ eml: hang }), spamRoutes({ learn: hang })]) {
            const { app } = buildApp({ routes });
            const started = Date.now();
            // 3.2 s remaining minus the 3 s response reserve leaves a 200 ms budget.
            const result = await app(hook(), { getRemainingTimeInMillis: () => 3_200 });
            expect(result.statusCode).toBe(503);
            expect(parse(result)).toEqual({ action: 'retry', reason: 'timeout' });
            expect(Date.now() - started).toBeLessThan(2_000);
        }
    });
});

describe('learn outcomes', () => {
    const outcome = async (learn: NonNullable<Routes['learn']>, ev = 'marked.spam') => {
        const harness = buildApp({ routes: ev === 'marked.spam' ? spamRoutes({ learn }) : hamRoutes({ learn }) });
        const result = await harness.app(ev === 'marked.spam' ? hook() : hamHook());
        return { result, body: parse(result), ...harness };
    };

    const trainedAs = (outcome: string) => ({ webhook: 200, body: { action: 'trained' }, outcome, level: 'info' });
    const skippedAs = (reason: string) => ({ webhook: 200, body: { action: 'skipped', reason }, outcome: 'skipped', level: 'warn' });
    const retriedAs = (reason: string, webhook = 502) => ({ webhook, body: { action: 'retry', reason }, outcome: 'retry', level: 'error' });
    /** Learn status classification: the status alone decides; the body is never read. */
    const STATUS_TABLE: [number, ReturnType<typeof trainedAs>][] = [
        [200, trainedAs('trained')],
        [201, trainedAs('trained')],
        [202, trainedAs('trained')],
        [204, trainedAs('not_learnable')],
        [206, trainedAs('trained')],
        [208, trainedAs('already_learned')],
        [400, skippedAs('learn_rejected')],
        [404, skippedAs('learn_rejected')],
        [405, skippedAs('learn_rejected')],
        [409, skippedAs('learn_rejected')],
        [413, skippedAs('too_large')],
        [415, skippedAs('learn_rejected')],
        [422, skippedAs('learn_rejected')],
        [401, retriedAs('proxy_auth_failed')],
        [403, retriedAs('proxy_auth_failed')],
        [408, retriedAs('upstream_unavailable')],
        [425, retriedAs('upstream_unavailable')],
        [429, retriedAs('upstream_unavailable')],
        [500, retriedAs('upstream_unavailable')],
        [502, retriedAs('upstream_unavailable')],
        [503, retriedAs('upstream_unavailable')],
        [504, retriedAs('upstream_unavailable')],
    ];

    for (const [code, expected] of STATUS_TABLE) {
        test(`learn HTTP ${code} → webhook ${expected.webhook} ${JSON.stringify(expected.body)} (${expected.level})`, async () => {
            for (const ev of ['marked.spam', 'marked.ham']) {
                const { result, body, records, key } = await outcome(() => status(code), ev);
                expect(result.statusCode).toBe(expected.webhook);
                expect(body).toEqual(expected.body);
                expect(records().find(record => record['event'] === 'request_completed')).toMatchObject({ outcome: expected.outcome, level: expected.level, status: expected.webhook });
                expect(key.invalidations).toBe(code === 401 || code === 403 ? 1 : 0);
            }
        });
    }

    test('learn network error and timeout are retryable', async () => {
        const network = await outcome(() => { throw new TypeError('fetch failed'); });
        expect(network.result.statusCode).toBe(502);
        expect(network.body).toEqual({ action: 'retry', reason: 'upstream_unreachable' });
        const timeout = await outcome(() => { throw new DOMException('timed out', 'TimeoutError'); });
        expect(timeout.result.statusCode).toBe(503);
        expect(timeout.body).toEqual({ action: 'retry', reason: 'timeout' });
    });

    test('the 2xx learn body is never inspected: a 200 {"success":false} is a successful hand-off', async () => {
        for (const raw of ['{"success":false}', `{"success":false,"error":"${SUBJECT}"}`, '{"error":"x"}', 'not json', '']) {
            const { result, body, records } = await outcome(() => status(200, raw));
            expect(result.statusCode).toBe(200);
            expect(body).toEqual({ action: 'trained' });
            expect(records().find(record => record['event'] === 'request_completed')).toMatchObject({ outcome: 'trained', level: 'info' });
        }
        // A 404 carrying the "already learned" text is just a permanent 404.
        const { body } = await outcome(() => status(404, '{"error":"<x@y> has been already learned as ham, ignore it"}'), 'marked.ham');
        expect(body).toEqual({ action: 'skipped', reason: 'learn_rejected' });
    });

    test('the learn response body is cancelled unread (socket released)', async () => {
        for (const code of [200, 208, 400, 503]) {
            let pulled = 0;
            let cancelled = false;
            const endless = new ReadableStream<Uint8Array>({
                pull(controller) { pulled++; controller.enqueue(new Uint8Array(1024).fill(0x20)); },
                cancel() { cancelled = true; },
            }, { highWaterMark: 0 });
            await outcome(() => new Response(endless, { status: code }));
            expect(pulled).toBe(0);
            expect(cancelled).toBe(true);
        }
    });

    test('an eml Content-Length above 25 MiB is skipped without uploading', async () => {
        const harness = buildApp({ routes: spamRoutes({ eml: () => emlResponse('tiny', { 'content-length': String(MAX_MESSAGE_BYTES + 1) }) }) });
        expect(parse(await harness.app(hook()))).toEqual({ action: 'skipped', reason: 'too_large' });
        expect(harness.calls.some(call => call.url.startsWith(LEARN))).toBe(false);
    });

    test('a message that grows past 25 MiB while streaming is aborted and skipped', async () => {
        const chunk = new Uint8Array(1024 * 1024).fill(0x61);
        let produced = 0;
        const source = new ReadableStream<Uint8Array>({
            start(controller) { controller.enqueue(new TextEncoder().encode('Subject: x\r\n\r\n')); },
            pull(controller) { produced++; controller.enqueue(chunk); },
        });
        const harness = buildApp({ routes: spamRoutes({ eml: () => emlResponse(source) }) });
        const result = await harness.app(hook());
        expect(parse(result)).toEqual({ action: 'skipped', reason: 'too_large' });
        expect(produced).toBeLessThanOrEqual(27);
    });

    test('a header section over 1 MiB is a permanent skip without a learn request', async () => {
        const raw = `${'X-Long: '.padEnd(1024 * 1024 + 10, 'a')}\r\n\r\nbody`;
        const harness = buildApp({ routes: spamRoutes({ eml: () => emlResponse(raw) }) });
        expect(parse(await harness.app(hook()))).toEqual({ action: 'skipped', reason: 'header_too_large' });
        expect(harness.calls.some(call => call.url.startsWith(LEARN))).toBe(false);
    });

    test('an eml read failure inside the header section is retryable and never reaches the learn endpoint', async () => {
        const source = new ReadableStream<Uint8Array>({
            start(controller) { controller.enqueue(new TextEncoder().encode('Subject: x\r\nTo: y')); },
            pull(controller) { controller.error(new Error('connection reset')); },
        });
        const harness = buildApp({ routes: spamRoutes({ eml: () => emlResponse(source) }) });
        const result = await harness.app(hook());
        expect(result.statusCode).toBe(502);
        expect(parse(result)).toEqual({ action: 'retry', reason: 'eml_read_failed' });
        expect(harness.calls.some(call => call.url.startsWith(LEARN))).toBe(false);
    });

    test('an eml read failure mid-stream is retryable', async () => {
        const source = new ReadableStream<Uint8Array>({
            start(controller) { controller.enqueue(new TextEncoder().encode('Subject: x\r\n\r\npartial')); },
            pull(controller) { controller.error(new Error('connection reset')); },
        });
        const harness = buildApp({ routes: spamRoutes({ eml: () => emlResponse(source) }) });
        const result = await harness.app(hook());
        expect(result.statusCode).toBe(502);
        expect(parse(result)).toEqual({ action: 'retry', reason: 'eml_read_failed' });
    });
});

describe('malformed messages are skipped, never trained', () => {
    const CASES: [string, string, string][] = [
        ['bare CR in a field value', `Subject: ${SUBJECT}\rmore\r\n\r\n${BODY_MARKER}`, 'bare_cr'],
        ['bare CR line ending', `Subject: a\r\rTo: b\r\n\r\n${BODY_MARKER}`, 'bare_cr'],
        ['NUL in the header section', `Subject: a\u0000b\r\n\r\n${BODY_MARKER}`, 'nul'],
        ['a line that is not a field', `Subject: a\r\nnot a header ${ADDRESS}\r\n\r\n${BODY_MARKER}`, 'invalid_line'],
        ['space inside a field name', `Subject: a\r\nBad Name: x\r\n\r\n${BODY_MARKER}`, 'invalid_line'],
        ['body without a blank separator', `Subject: a\nThis is body text ${BODY_MARKER}\n`, 'invalid_line'],
        ['continuation before any field', ` folded\r\nSubject: a\r\n\r\n${BODY_MARKER}`, 'leading_continuation'],
        ['mbox From envelope line', `From ${ADDRESS} Mon Jan  1 00:00:00 2026\r\nSubject: a\r\n\r\n${BODY_MARKER}`, 'mbox_envelope'],
        ['empty message', '', 'empty'],
    ];
    for (const [name, raw, code] of CASES) {
        test(`${name}: no learn request, 200 skipped/malformed_message, warn log with code ${code} only`, async () => {
            for (const [routes, request] of [[spamRoutes({ eml: () => emlResponse(raw) }), hook()], [hamRoutes({ eml: () => emlResponse(raw) }), hamHook()]] as const) {
                const { app, calls, records, lines } = buildApp({ routes });
                const result = await app(request);
                expect(result.statusCode).toBe(200);
                expect(parse(result)).toEqual({ action: 'skipped', reason: 'malformed_message' });
                expect(calls.filter(call => call.url.startsWith(LEARN))).toHaveLength(0);
                expect(records().find(record => record['event'] === 'message_malformed')).toMatchObject({ level: 'warn', upstream: 'eml', reason: code });
                expect(records().find(record => record['event'] === 'request_completed')).toMatchObject({ level: 'warn', outcome: 'skipped', reason: 'malformed_message', status: 200 });
                const all = lines.join('\n');
                for (const marker of SENSITIVE) {
                    expect(all).not.toContain(marker);
                }
            }
        });
    }

    test('the source is cancelled without reading the rest of the message', async () => {
        let pulls = 0;
        let cancelled = false;
        const source = new ReadableStream<Uint8Array>({
            start(controller) { controller.enqueue(new TextEncoder().encode('Subject: a\r\nbroken line\r\n')); },
            pull(controller) { pulls++; controller.enqueue(new Uint8Array(64 * 1024).fill(0x61)); },
            cancel() { cancelled = true; },
        }, { highWaterMark: 0 });
        const { app, calls } = buildApp({ routes: spamRoutes({ eml: () => emlResponse(source) }) });
        expect(parse(await app(hook()))).toEqual({ action: 'skipped', reason: 'malformed_message' });
        expect(calls.filter(call => call.url.startsWith(LEARN))).toHaveLength(0);
        expect(cancelled).toBe(true);
        expect(pulls).toBeLessThanOrEqual(1);
    });

    test('valid edge cases are trained with exact bytes', async () => {
        const body = `${BODY_MARKER}\r\nX-Rspamd-Score: 9\r\n\u0000\r bare CR and NUL in the body are fine`;
        for (const [raw, expected] of [
            ['Delivered-To: a@b\nReturn-Path: <a@b>\nSubject: lf only\nX-Rspamd-Bar: +++\n\n' + body, 'Subject: lf only\n\n' + body],
            ['Subject: mixed\nTo: x\r\nX-Spam-Flag: YES\n\r\n' + body, 'Subject: mixed\nTo: x\r\nX-Spam-Flag: YES\n\r\n' + body],
            ['Subject: no body\r\nWD-Mail-Classification: spam\r\n', 'Subject: no body\r\n'],
            ['Subject: no newline at all', 'Subject: no newline at all'],
            [`Subject: 8-bit éÿ ${'v'.repeat(20_000)}\r\n\r\n${body}`, `Subject: 8-bit éÿ ${'v'.repeat(20_000)}\r\n\r\n${body}`],
        ] as const) {
            const { app, calls } = buildApp({ routes: spamRoutes({ eml: () => emlResponse(new Uint8Array(Buffer.from(raw, 'latin1'))) }) });
            expect(parse(await app(hook()))).toEqual({ action: 'trained' });
            expect(Buffer.from(calls[2]?.body ?? new Uint8Array(0)).equals(Buffer.from(expected, 'latin1'))).toBe(true);
        }
    });
});

describe('proxy request headers', () => {
    test('every proxy request carries X-Mail-Training-Key and never X-Access-Token or a password', async () => {
        for (const [routes, request] of [[spamRoutes(), hook()], [hamRoutes(), hamHook()]] as const) {
            const { app, calls } = buildApp({ routes });
            await app(request);
            expect(calls.length).toBeGreaterThan(2);
            for (const call of calls) {
                expect(call.headers.get('x-mail-training-key')).toBe(KEY);
                expect(call.headers.has('x-access-token')).toBe(false);
                expect(call.headers.has('password')).toBe(false);
                expect(call.headers.has('authorization')).toBe(false);
                expect(call.headers.has('x-origin-verify')).toBe(false);
            }
        }
    });
});

describe('logging never leaks sensitive data', () => {
    const scenarios: [string, Routes, 'spam' | 'ham'][] = [
        ['spam trained', spamRoutes(), 'spam'],
        ['ham trained', hamRoutes(), 'ham'],
        ['ham flagged', hamRoutes({ message: () => messageResponse({ flagged: true }) }), 'ham'],
        ['mailbox 500', spamRoutes({ mailbox: () => status(500) }), 'spam'],
        ['eml 404', spamRoutes({ eml: () => status(404) }), 'spam'],
        ['learn 400', spamRoutes({ learn: () => status(400) }), 'spam'],
        ['learn 208', spamRoutes({ learn: () => status(208) }), 'spam'],
        ['learn 200 error body', spamRoutes({ learn: () => status(200) }), 'spam'],
        ['malformed header section', spamRoutes({ eml: () => emlResponse(`Subject: ${SUBJECT}\r\nNot a header ${SENSITIVE.join(' ')}\r\n\r\n`) }), 'spam'],
        ['malformed bare CR', hamRoutes({ eml: () => emlResponse(`Subject: ${SUBJECT}\r${SENSITIVE.join(' ')}\r\n\r\n`) }), 'ham'],
        ['learn 401', hamRoutes({ learn: () => status(401) }), 'ham'],
        ['network', spamRoutes({ eml: () => { throw new TypeError(`fetch failed ${SENSITIVE.join(' ')}`); } }), 'spam'],
        ['eml stream error', spamRoutes({ eml: () => emlResponse(new ReadableStream({ pull(controller) { controller.error(new Error(SENSITIVE.join(' '))); } })) }), 'spam'],
        ['bad json', hamRoutes({ message: () => new Response(`not json ${SENSITIVE.join(' ')}`) }), 'ham'],
    ];
    for (const [name, routes, kind] of scenarios) {
        test(`${name}: no key, secret, subject, address, Message-ID or content in any log line`, async () => {
            const { app, lines } = buildApp({ routes });
            await app(kind === 'spam' ? hook() : hamHook());
            await app(hook('{"ev":'));
            await app(hook(webhookBody({ user: SENSITIVE[2] })));
            expect(lines.length).toBeGreaterThan(0);
            const all = lines.join('\n');
            for (const marker of SENSITIVE) {
                expect(all).not.toContain(marker);
            }
            for (const line of lines) {
                expect(line).not.toContain('\n');
                expect(line).not.toContain('https://');
                expect(line).not.toContain('wildduck/1.47.0');
                const record = JSON.parse(line) as Record<string, unknown>;
                expect(['info', 'warn', 'error']).toContain(record['level'] as string);
            }
        });
    }

    test('the raw message fixture really contains the markers (sanity)', () => {
        expect(RAW_MESSAGE).toContain(SENSITIVE[2] ?? '');
    });

    test('a successful request logs the allowed identifiers and outcome', async () => {
        const { app, records } = buildApp({ routes: spamRoutes() });
        await app(hook());
        const completed = records().find(record => record['event'] === 'request_completed');
        expect(completed).toMatchObject({ requestId: 'req-1', deliveryId: '65a1b2c3d4e5f6a7b8c9d0e1:1', ev: 'marked.spam', user: USER, mailbox: MAILBOX, uid: UID, route: '/hooks/wildduck', method: 'POST', status: 200, outcome: 'trained' });
        const upstreams = records().filter(record => record['event'] === 'upstream_response').map(record => record['upstream']);
        expect(upstreams).toEqual(['mailbox', 'eml', 'learn']);
        expect(records().find(record => record['event'] === 'message_streamed')).toMatchObject({ bytes: RAW_MESSAGE.length, removedHeaders: 4 });
    });
});
