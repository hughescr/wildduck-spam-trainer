import { describe, expect, test } from 'bun:test';
import { GetParameterCommand } from '@aws-sdk/client-ssm';
import { GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { matchesAnyDigest, OriginVerifier, TrainingKeyStore } from '../src/secrets';
import { createApp } from '../src/app';
import { API, captureLogs, event, FakeKey, hook, KEY, LEARN, mockFetch, spamRoutes } from './helpers';
import { createHash } from 'node:crypto';

const CURRENT = 'CurrentOriginSecret0123456789abcdefABCDEF0123456789';
const PREVIOUS = 'PreviousOriginSecret0123456789abcdefABCDEF012345678';
const ROTATED = 'RotatedOriginSecret0123456789abcdefABCDEF0123456789';
const WRONG = 'WrongOriginSecret00123456789abcdefABCDEF0123456789';

class Clock {
    constructor(public value = 1_000_000) {}
    now = () => this.value;
    advance(ms: number) { this.value += ms; }
}

/** Secrets Manager double keyed by version stage. */
function secretsClient(stages: { AWSCURRENT?: string | Error; AWSPREVIOUS?: string | Error }, delayMs = 0) {
    const calls: { stage: string | undefined; id: string | undefined }[] = [];
    const client = {
        send: async (command: GetSecretValueCommand) => {
            calls.push({ stage: command.input.VersionStage, id: command.input.SecretId });
            if (delayMs) { await Bun.sleep(delayMs); }
            const value = stages[command.input.VersionStage as 'AWSCURRENT' | 'AWSPREVIOUS'];
            if (value instanceof Error) { throw value; }
            if (value === undefined) { throw Object.assign(new Error('not found'), { name: 'ResourceNotFoundException' }); }
            return { SecretString: value };
        },
    };
    return { client, calls, stages };
}

const verifier = (stages: Parameters<typeof secretsClient>[0], clock = new Clock(), delayMs = 0) => {
    const sm = secretsClient(stages, delayMs);
    const logs = captureLogs();
    const origin = new OriginVerifier({ client: () => sm.client, secretId: 'wildduck-spam-trainer/prod/origin-verify-key', log: logs.log, now: clock.now });
    return { origin, sm, clock, logs };
};

describe('constant-time digest comparison', () => {
    test('matches any configured digest', () => {
        const digests = [CURRENT, PREVIOUS].map(value => createHash('sha256').update(value).digest());
        expect(matchesAnyDigest(CURRENT, digests)).toBe(true);
        expect(matchesAnyDigest(PREVIOUS, digests)).toBe(true);
        expect(matchesAnyDigest(WRONG, digests)).toBe(false);
        expect(matchesAnyDigest('', digests)).toBe(false);
    });
});

describe('OriginVerifier', () => {
    test('accepts AWSCURRENT and AWSPREVIOUS, rejects wrong values', async () => {
        const { origin, sm } = verifier({ AWSCURRENT: CURRENT, AWSPREVIOUS: PREVIOUS });
        expect(await origin.verify(CURRENT)).toBe('ok');
        expect(await origin.verify(PREVIOUS)).toBe('ok');
        expect(await origin.verify(WRONG)).toBe('mismatch');
        expect(sm.calls.every(call => call.id === 'wildduck-spam-trainer/prod/origin-verify-key')).toBe(true);
    });

    test('a never-rotated secret (no AWSPREVIOUS) works', async () => {
        const { origin } = verifier({ AWSCURRENT: CURRENT });
        expect(await origin.verify(CURRENT)).toBe('ok');
        expect(await origin.verify(PREVIOUS)).toBe('mismatch');
    });

    test('missing or malformed headers are rejected without any Secrets Manager call', async () => {
        const { origin, sm } = verifier({ AWSCURRENT: CURRENT });
        for (const value of [undefined, '', 'short', `${CURRENT}!`, `${CURRENT}, ${CURRENT}`, `${CURRENT}\n`, `${CURRENT}\r\n`, ' '.repeat(40), 'é'.repeat(40)]) {
            expect(await origin.verify(value)).toBe('mismatch');
        }
        expect(sm.calls).toHaveLength(0);
    });

    test('concurrent first requests coalesce into one load', async () => {
        const { origin, sm } = verifier({ AWSCURRENT: CURRENT }, new Clock(), 10);
        const results = await Promise.all(Array.from({ length: 20 }, () => origin.verify(CURRENT)));
        expect(results.every(result => result === 'ok')).toBe(true);
        expect(sm.calls).toHaveLength(2); // one AWSCURRENT + one AWSPREVIOUS
    });

    test('public mismatches refresh at most once per interval, coalesced', async () => {
        const { origin, sm, clock } = verifier({ AWSCURRENT: CURRENT }, new Clock(), 5);
        expect(await origin.verify(CURRENT)).toBe('ok');
        const loads = () => sm.calls.length / 2;
        expect(loads()).toBe(1);
        clock.advance(60_000);
        const flood = await Promise.all(Array.from({ length: 50 }, () => origin.verify(WRONG)));
        expect(flood.every(result => result === 'mismatch')).toBe(true);
        expect(loads()).toBe(2);
        for (let i = 0; i < 100; i++) { expect(await origin.verify(WRONG)).toBe('mismatch'); clock.advance(100); }
        expect(loads()).toBe(2);
        clock.advance(60_000);
        await origin.verify(WRONG);
        expect(loads()).toBe(3);
    });

    test('rotation: a new CloudFront value is accepted after one mismatch-triggered refresh', async () => {
        const { origin, sm, clock } = verifier({ AWSCURRENT: CURRENT });
        expect(await origin.verify(CURRENT)).toBe('ok');
        sm.stages.AWSPREVIOUS = CURRENT;
        sm.stages.AWSCURRENT = ROTATED;
        clock.advance(61_000);
        expect(await origin.verify(ROTATED)).toBe('ok');
        expect(await origin.verify(CURRENT)).toBe('ok'); // still AWSPREVIOUS
        // After the following rotation the old value is gone.
        sm.stages.AWSPREVIOUS = ROTATED;
        sm.stages.AWSCURRENT = 'ThirdOriginSecret0123456789abcdefABCDEF0123456789zz';
        clock.advance(300_000);
        expect(await origin.verify(CURRENT)).toBe('mismatch');
    });

    test('fails closed (unavailable) when the secret cannot be loaded, and retries are rate-limited', async () => {
        const { origin, sm, clock, logs } = verifier({ AWSCURRENT: new Error('AccessDenied') });
        expect(await origin.verify(CURRENT)).toBe('unavailable');
        expect(await origin.verify(CURRENT)).toBe('unavailable');
        expect(sm.calls.length).toBe(2);
        clock.advance(10_000);
        expect(await origin.verify(CURRENT)).toBe('unavailable');
        expect(sm.calls.length).toBe(4);
        expect(logs.lines.join('')).not.toContain('AccessDenied');
    });

    test('an invalid stored value (not alphanumeric) is treated as unavailable', async () => {
        const { origin } = verifier({ AWSCURRENT: 'has spaces and punctuation!!!!!!!!!!!!!!!!!!!' });
        expect(await origin.verify(CURRENT)).toBe('unavailable');
    });

    test('values past their TTL are never used when the reload fails (fail closed)', async () => {
        const { origin, sm, clock } = verifier({ AWSCURRENT: CURRENT });
        expect(await origin.verify(CURRENT)).toBe('ok');
        sm.stages.AWSCURRENT = new Error('throttled');
        clock.advance(299_000);
        expect(await origin.verify(CURRENT)).toBe('ok');
        clock.advance(1_000);
        expect(await origin.verify(CURRENT)).toBe('unavailable');
        sm.stages.AWSCURRENT = CURRENT;
        clock.advance(10_000);
        expect(await origin.verify(CURRENT)).toBe('ok');
    });

    test('a deleted or invalid secret stops authenticating at the TTL', async () => {
        const { origin, sm, clock } = verifier({ AWSCURRENT: CURRENT });
        expect(await origin.verify(CURRENT)).toBe('ok');
        sm.stages.AWSCURRENT = 'not alphanumeric !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!';
        clock.advance(300_000);
        expect(await origin.verify(CURRENT)).toBe('unavailable');
    });

    test('a failed mismatch-triggered refresh within the TTL keeps the working cache', async () => {
        const { origin, sm, clock } = verifier({ AWSCURRENT: CURRENT });
        expect(await origin.verify(CURRENT)).toBe('ok');
        sm.stages.AWSCURRENT = new Error('throttled');
        clock.advance(61_000);
        expect(await origin.verify(WRONG)).toBe('mismatch');
        expect(await origin.verify(CURRENT)).toBe('ok');
    });

    test('unconfigured secret id fails closed with no SDK client', async () => {
        let constructed = 0;
        const logs = captureLogs();
        const origin = new OriginVerifier({ client: () => { constructed++; throw new Error('no'); }, secretId: undefined, log: logs.log });
        expect(await origin.verify(CURRENT)).toBe('unavailable');
        expect(constructed).toBe(0);
    });

    test('end to end: direct Function URL traffic without the header gets 403 and drives no Secrets Manager call', async () => {
        const { origin, sm } = verifier({ AWSCURRENT: CURRENT, AWSPREVIOUS: PREVIOUS });
        const { fetch, calls } = mockFetch(spamRoutes());
        const logs = captureLogs();
        const app = createApp({ apiBaseUrl: API, learnBaseUrl: LEARN, origin, trainingKey: new FakeKey(), fetch, log: logs.log });
        const direct = hook();
        delete direct.headers?.['x-origin-verify'];
        for (let i = 0; i < 25; i++) { expect((await app(direct)).statusCode).toBe(403); }
        const health = event('/healthz');
        delete health.headers?.['x-origin-verify'];
        expect((await app(health)).statusCode).toBe(403);
        expect(sm.calls).toHaveLength(0);
        expect(calls).toHaveLength(0);
        expect((await app(event('/healthz', { headers: { 'x-origin-verify': PREVIOUS } }))).statusCode).toBe(200);
        expect((await app(hook(undefined, { 'x-origin-verify': CURRENT }))).statusCode).toBe(200);
        expect((await app(hook(undefined, { 'x-origin-verify': WRONG }))).statusCode).toBe(403);
        expect(logs.lines.join('')).not.toContain(CURRENT);
    });
});

function ssmClient(responses: (unknown | Error)[]) {
    const calls: GetParameterCommand[] = [];
    const client = {
        send: async (command: GetParameterCommand) => {
            calls.push(command);
            const next = responses.length > 1 ? responses.shift() : responses[0];
            if (next instanceof Error) { throw next; }
            return next;
        },
    };
    return { client, calls };
}

const secure = (value: string) => ({ Parameter: { Name: '/wildduck-spam-trainer/prod/training-proxy-key', Type: 'SecureString', Value: value } });

describe('TrainingKeyStore', () => {
    const store = (responses: (unknown | Error)[], clock = new Clock()) => {
        const ssm = ssmClient(responses);
        const logs = captureLogs();
        const keys = new TrainingKeyStore({ client: () => ssm.client, parameterName: '/wildduck-spam-trainer/prod/training-proxy-key', log: logs.log, now: clock.now });
        return { keys, ssm, clock, logs };
    };

    test('loads the SecureString with decryption and caches it for the TTL', async () => {
        const { keys, ssm, clock } = store([secure(KEY)]);
        expect(await keys.get()).toBe(KEY);
        expect(await keys.get()).toBe(KEY);
        expect(ssm.calls).toHaveLength(1);
        expect(ssm.calls[0]?.input).toEqual({ Name: '/wildduck-spam-trainer/prod/training-proxy-key', WithDecryption: true });
        clock.advance(299_000);
        await keys.get();
        expect(ssm.calls).toHaveLength(1);
        clock.advance(2_000);
        await keys.get();
        expect(ssm.calls).toHaveLength(2);
    });

    test('rotation is picked up after the TTL without a deploy', async () => {
        const { keys, clock } = store([secure(KEY), secure('rotated-training-key-0123456789')]);
        expect(await keys.get()).toBe(KEY);
        clock.advance(300_000);
        expect(await keys.get()).toBe('rotated-training-key-0123456789');
    });

    test('missing parameter means no key (503 upstream), with rate-limited retries', async () => {
        const notFound = Object.assign(new Error('ParameterNotFound'), { name: 'ParameterNotFound' });
        const { keys, ssm, clock, logs } = store([notFound]);
        expect(await keys.get()).toBeUndefined();
        expect(await keys.get()).toBeUndefined();
        expect(ssm.calls).toHaveLength(1);
        clock.advance(10_000);
        expect(await keys.get()).toBeUndefined();
        expect(ssm.calls).toHaveLength(2);
        expect(logs.records().some(record => record['reason'] === 'parameter_not_found')).toBe(true);
    });

    test('non-SecureString, empty, whitespace or control-character values are rejected', async () => {
        for (const response of [{ Parameter: { Type: 'String', Value: KEY } }, secure(''), secure('short'), secure('has a space in it here'), secure(`${KEY}\u0000`), {}]) {
            const { keys } = store([response]);
            expect(await keys.get()).toBeUndefined();
        }
    });

    test('one trailing newline from file-based provisioning is tolerated', async () => {
        const { keys } = store([secure(`${KEY}\n`)]);
        expect(await keys.get()).toBe(KEY);
        const crlf = store([secure(`${KEY}\r\n`)]);
        expect(await crlf.keys.get()).toBe(KEY);
        // Only one: a remaining line terminator must not pass the end anchor.
        for (const value of [`${KEY}\n\n`, `${KEY}\r\n\r\n`, `${KEY}\n\r\n`]) {
            const doubled = store([secure(value)]);
            expect(await doubled.keys.get()).toBeUndefined();
        }
    });

    test('a transient failure keeps the loaded key within the stale window', async () => {
        const { keys, clock } = store([secure(KEY), new Error('ThrottlingException')]);
        expect(await keys.get()).toBe(KEY);
        clock.advance(300_000);
        expect(await keys.get()).toBe(KEY);
        clock.advance(600_000);
        expect(await keys.get()).toBeUndefined();
    });

    test('invalidate() forces one rate-limited reload', async () => {
        const { keys, ssm, clock } = store([secure(KEY), secure('rotated-training-key-0123456789')]);
        expect(await keys.get()).toBe(KEY);
        keys.invalidate();
        clock.advance(10_000);
        expect(await keys.get()).toBe('rotated-training-key-0123456789');
        expect(ssm.calls).toHaveLength(2);
        expect(await keys.get()).toBe('rotated-training-key-0123456789');
        expect(ssm.calls).toHaveLength(2);
    });

    test('concurrent loads coalesce', async () => {
        const { keys, ssm } = store([secure(KEY)]);
        const values = await Promise.all(Array.from({ length: 10 }, () => keys.get()));
        expect(values.every(value => value === KEY)).toBe(true);
        expect(ssm.calls).toHaveLength(1);
    });

    test('unconfigured parameter name never calls SSM', async () => {
        let constructed = 0;
        const keys = new TrainingKeyStore({ client: () => { constructed++; throw new Error('no'); }, parameterName: undefined, log: captureLogs().log });
        expect(await keys.get()).toBeUndefined();
        expect(constructed).toBe(0);
    });

    test('the key never appears in logs on any path', async () => {
        for (const responses of [[secure(KEY)], [new Error(KEY)], [{ Parameter: { Type: 'String', Value: KEY } }]]) {
            const { keys, logs } = store(responses);
            await keys.get();
            expect(logs.lines.join('')).not.toContain(KEY);
        }
    });
});
