// Smoke test of the built artifact under Node 26: fail-closed behaviour of the production
// wiring (no AWS calls), then spam-training passes (including learn answers sent before the
// body is read) and one malformed-message skip through Node's real fetch and streams against
// a loopback-only stand-in for the proxies.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

assert.equal(Number(process.versions.node.split('.')[0]), 26, 'Smoke test must execute under Node 26');
for (const name of ['TRAINING_PROXY_KEY_PARAMETER', 'ORIGIN_VERIFY_SECRET_ID', 'TRAINING_API_BASE_URL', 'TRAINING_LEARN_BASE_URL']) {
    delete process.env[name];
}
const { handler, createApp } = await import('../dist/handler.mjs');

const event = (path, { method = 'GET', headers = {}, body } = {}) => ({
    version: '2.0', routeKey: '$default', rawPath: path, rawQueryString: '', headers: { host: 'example.lambda-url.us-west-2.on.aws', ...headers },
    requestContext: { accountId: 'local', apiId: 'local', domainName: 'example.lambda-url.us-west-2.on.aws', domainPrefix: 'local', requestId: 'smoke', routeKey: '$default', stage: '$default', time: '', timeEpoch: 0, http: { method, path, protocol: 'HTTP/1.1', sourceIp: '54.71.178.94', userAgent: 'node-smoke' } },
    ...(body === undefined ? {} : { body }),
    isBase64Encoded: false,
});
const SECRET = 'S'.repeat(64);

// Production wiring with nothing configured: no header is 403, a well-formed header is 503.
assert.equal((await handler(event('/healthz'))).statusCode, 403);
assert.equal((await handler(event('/hooks/wildduck', { method: 'POST', body: '{}' }))).statusCode, 403);
assert.equal((await handler(event('/healthz', { headers: { 'x-origin-verify': SECRET } }))).statusCode, 503, 'Unconfigured origin secret must fail closed');

// Full pass through Node fetch (duplex streaming upload) against loopback stand-ins.
const USER = 'a'.repeat(24);
const MAILBOX = 'b'.repeat(24);
const KEY = 'smoke-training-key-0123456789';
const body = Buffer.alloc(3 * 1024 * 1024, 'x');
const raw = Buffer.concat([Buffer.from('Delivered-To: a@example.org\r\nReturn-Path: <b@example.org>\r\nReceived: from a\r\nX-Spam-Flag: YES\r\nX-Rspamd-Score: 9\r\n\tcontinued\r\nSubject: smoke\r\nWD-Mail-Classification: spam\r\n\r\n'), body]);
const expected = Buffer.concat([Buffer.from('Received: from a\r\nX-Spam-Flag: YES\r\nSubject: smoke\r\n\r\n'), body]);
const malformed = Buffer.concat([Buffer.from('Subject: smoke\r\nnot a header line\r\n\r\n'), body]);
let message = raw;
let learned;
// How the stand-in learn endpoint answers: 'after' the whole body (normal), 'headers-first'
// (200 headers before reading the body, the response ended after it), or 'end-first' (a
// complete 200 before reading the body).
let learnMode = 'after';
/** Settles with how the last learn upload ended on the server: { ended, bytes }. */
let uploadSeen;
const seen = [];
const server = createServer((req, res) => {
    seen.push({ url: req.url, key: req.headers['x-mail-training-key'], token: req.headers['x-access-token'] });
    const base = `/api/users/${USER}/mailboxes/${MAILBOX}`;
    if (req.url === base) {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ success: true, id: MAILBOX, path: 'Junk', specialUse: '\\Junk' }));
    } else if (req.url === `${base}/messages/7/message.eml`) {
        res.setHeader('content-type', 'message/rfc822');
        res.end(message);
    } else if (req.url === '/learn/learn-spam' && req.method === 'POST') {
        const parts = [];
        res.setHeader('content-type', 'application/json');
        if (learnMode === 'headers-first') {
            res.writeHead(200);
            res.flushHeaders();
        } else if (learnMode === 'end-first') {
            res.end('{"success":true}');
        }
        uploadSeen = new Promise(resolve => {
            req.on('data', chunk => parts.push(chunk));
            req.on('end', () => {
                learned = Buffer.concat(parts);
                resolve({ ended: true, bytes: learned });
                if (!res.writableEnded) {
                    res.end('{"success":true}');
                }
            });
            req.on('close', () => resolve({ ended: false, bytes: Buffer.concat(parts) }));
        });
    } else {
        res.statusCode = 500;
        res.end();
    }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
try {
    const { port } = server.address();
    const app = createApp({
        apiBaseUrl: `http://127.0.0.1:${port}/api`,
        learnBaseUrl: `http://127.0.0.1:${port}/learn`,
        origin: { verify: async value => (value === SECRET ? 'ok' : 'mismatch') },
        trainingKey: { get: async () => KEY, invalidate: () => undefined },
        fetch: (input, init) => fetch(input, init),
        log: { info: () => undefined, warn: () => undefined, error: () => undefined },
    });
    const health = await app(event('/healthz', { headers: { 'x-origin-verify': SECRET } }));
    assert.equal(health.statusCode, 200);
    assert.equal(JSON.parse(health.body).service, 'wildduck-spam-trainer');
    const spamHook = () => app(event('/hooks/wildduck', { method: 'POST', headers: { 'x-origin-verify': SECRET, 'content-type': 'application/json' }, body: JSON.stringify({ id: `${'c'.repeat(24)}:1`, ev: 'marked.spam', user: USER, mailbox: MAILBOX, message: 7 }) }), { getRemainingTimeInMillis: () => 25_000 });
    const result = await spamHook();
    assert.equal(result.statusCode, 200, result.body);
    assert.deepEqual(JSON.parse(result.body), { action: 'trained' });
    assert.ok(learned && learned.equals(expected), 'Learn endpoint must receive the header-stripped message byte-for-byte');
    assert.equal(seen.length, 3);
    for (const entry of seen) {
        assert.equal(entry.key, KEY, 'Every proxy request carries the training key');
        assert.equal(entry.token, undefined, 'No proxy request carries X-Access-Token');
    }
    const settledUpload = async () => {
        let timer;
        try {
            return await Promise.race([uploadSeen, new Promise((_resolve, reject) => {
                timer = setTimeout(() => reject(new Error('learn upload never settled on the server')), 10_000);
            })]);
        } finally {
            clearTimeout(timer);
        }
    };

    // The learn endpoint answers 200 before reading the body: the trainer waits for the
    // upload to complete, and the server still receives the whole message, properly ended.
    learnMode = 'headers-first';
    learned = undefined;
    const early = await spamHook();
    assert.equal(early.statusCode, 200, early.body);
    assert.deepEqual(JSON.parse(early.body), { action: 'trained' });
    const earlyUpload = await settledUpload();
    assert.ok(earlyUpload.ended, 'An early 200 must not cut the upload short: the server sees the request end');
    assert.ok(earlyUpload.bytes.equals(expected), 'An early 200 must still deliver the whole header-stripped message');

    // A complete 200 before the body is read: Node's fetch sometimes stops sending the body
    // (it then leaves the request open on the server). "trained" must mean the server got the
    // whole message; otherwise the answer is a retry.
    learnMode = 'end-first';
    const endFirst = await spamHook();
    if (JSON.parse(endFirst.body).action === 'trained') {
        const endFirstUpload = await settledUpload();
        assert.ok(endFirstUpload.ended && endFirstUpload.bytes.equals(expected), 'trained must mean the whole message reached the learn endpoint');
    } else {
        assert.equal(endFirst.statusCode, 502, endFirst.body);
        assert.deepEqual(JSON.parse(endFirst.body), { action: 'retry', reason: 'upload_incomplete' });
    }
    learnMode = 'after';

    // A malformed message is skipped without any learn request.
    message = malformed;
    seen.length = 0;
    const skipped = await spamHook();
    assert.equal(skipped.statusCode, 200, skipped.body);
    assert.deepEqual(JSON.parse(skipped.body), { action: 'skipped', reason: 'malformed_message' });
    assert.deepEqual(seen.map(entry => entry.url), [`/api/users/${USER}/mailboxes/${MAILBOX}`, `/api/users/${USER}/mailboxes/${MAILBOX}/messages/7/message.eml`], 'A malformed message never reaches the learn endpoint');
} finally {
    server.close();
    server.closeAllConnections();
}
process.stdout.write('smoke: ok\n');
