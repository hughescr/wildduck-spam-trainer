import { describe, expect, test } from 'bun:test';
import { createStrippedBody, HeaderSectionTooLarge, HeaderStripper, isStrippedHeaderName, MessageTooLarge, stripHeaders } from '../src/header-strip';

const enc = (value: string) => new TextEncoder().encode(value);
const dec = (value: Uint8Array) => new TextDecoder().decode(value);
const strip = (value: string) => dec(stripHeaders(enc(value)));

function chunked(input: Uint8Array, sizes: number[]): Uint8Array {
    const stripper = new HeaderStripper();
    const out: Uint8Array[] = [];
    let offset = 0;
    let index = 0;
    while (offset < input.length) {
        const size = Math.max(1, sizes[index++ % sizes.length] ?? 1);
        out.push(...stripper.push(input.subarray(offset, offset + size)));
        offset += size;
    }
    out.push(...stripper.end());
    return Buffer.concat(out);
}

const PRESERVED = [
    'Return-Path: <bounce@example.org>',
    'Received: from mx.example.org (mx.example.org [192.0.2.1])',
    '\tby mail.example.com with ESMTPS id abc',
    '\tfor <me@example.com>; Mon, 1 Jan 2026 00:00:00 +0000',
    'Received-SPF: pass (example.org: 192.0.2.1 is authorized)',
    'Authentication-Results: mail.example.com; dkim=pass header.d=example.org;',
    ' spf=pass smtp.mailfrom=example.org',
    'DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=s1;',
    '\tb=AbCdEf==',
    'ARC-Seal: i=1; a=rsa-sha256; cv=none',
    'ARC-Message-Signature: i=1; a=rsa-sha256',
    'ARC-Authentication-Results: i=1; mx.example.com',
    'X-Spamming: not a spam header',
    'X-Spam: no dash, not matched',
    'WD-Mail-Classification-Other: keep',
    'Subject: hello',
];
const REMOVED = [
    'X-Spam-Flag: YES',
    'x-spam-status: Yes, score=12',
    '\ttests=FOO,BAR',
    'X-SPAM-LEVEL: ********',
    'X-Spamd-Bar: +++++',
    'X-Spamd-Result: default: False [9.1 / 15.0];',
    ' R_SPF_ALLOW(-0.2)[+ip4:192.0.2.1];',
    '\tR_DKIM_ALLOW(-0.2)[example.org:s=s1]',
    'X-Rspamd-Queue-Id: ABC123',
    'X-Rspamd-Server: rspamd1',
    'X-Rspamd-Action: add header',
    'WD-Mail-Classification: spam',
    'wd-mail-classification-source: user',
    'WD-MAIL-CLASSIFICATION-INFO: moved to junk',
    '  folded continuation of the info header',
];

/** Interleaves removed and preserved fields, keeping each folded group together. */
function sampleMessage(eol: string | ((index: number) => string)): { raw: string; expected: string } {
    const groups = (lines: string[]) => lines.reduce<string[][]>((acc, line) => {
        if (/^[ \t]/.test(line)) { acc[acc.length - 1]?.push(line); } else { acc.push([line]); }
        return acc;
    }, []);
    const keep = groups(PRESERVED);
    const drop = groups(REMOVED);
    const rawLines: string[] = [];
    const expectedLines: string[] = [];
    let index = 0;
    const end = () => (typeof eol === 'string' ? eol : eol(index++));
    const max = Math.max(keep.length, drop.length);
    for (let i = 0; i < max; i++) {
        for (const line of keep[i] ?? []) { const e = end(); rawLines.push(line + e); expectedLines.push(line + e); }
        for (const line of drop[i] ?? []) { rawLines.push(line + end()); }
    }
    const separator = end();
    const body = `Body line one${end()}X-Spam-Flag: YES${end()}X-Rspamd-Score: 99${end()}\tindented body line${end()}\xe9\xff binary-ish`;
    return { raw: rawLines.join('') + separator + body, expected: expectedLines.join('') + separator + body };
}

describe('header classification', () => {
    test('stripped names: exact WD-Mail-Classification family and X-Rspamd-/X-Spamd-/X-Spam- prefixes', () => {
        for (const name of ['wd-mail-classification', 'wd-mail-classification-source', 'wd-mail-classification-info', 'x-rspamd-score', 'x-spamd-bar', 'x-spam-flag']) {
            expect(isStrippedHeaderName(name)).toBe(true);
        }
        for (const name of ['wd-mail-classification-other', 'x-spam', 'x-spamming', 'x-rspamd', 'received', 'authentication-results', 'dkim-signature', 'arc-seal']) {
            expect(isStrippedHeaderName(name)).toBe(false);
        }
    });
});

describe('stripHeaders', () => {
    test('CRLF message: removes classification fields with all folded lines, preserves everything else byte-for-byte', () => {
        const { raw, expected } = sampleMessage('\r\n');
        expect(strip(raw)).toBe(expected);
    });

    test('bare LF message', () => {
        const { raw, expected } = sampleMessage('\n');
        expect(strip(raw)).toBe(expected);
    });

    test('mixed line endings are preserved exactly', () => {
        const { raw, expected } = sampleMessage(index => (index % 3 === 0 ? '\n' : '\r\n'));
        expect(strip(raw)).toBe(expected);
    });

    test('body lines that look like headers survive', () => {
        const raw = 'Subject: a\r\n\r\nX-Spam-Flag: YES\r\nWD-Mail-Classification: spam\r\n';
        expect(strip(raw)).toBe(raw);
    });

    test('obsolete whitespace before the colon is still matched', () => {
        expect(strip('X-Spam-Flag \t: YES\r\nSubject: a\r\n\r\nb')).toBe('Subject: a\r\n\r\nb');
    });

    test('very long stripped names (beyond the inspected bytes) are still removed', () => {
        expect(strip(`X-Spam-${'a'.repeat(300)}: v\r\nSubject: a\r\n\r\n`)).toBe('Subject: a\r\n\r\n');
        expect(strip(`X-Keep-${'a'.repeat(300)}: v\r\n\r\n`)).toBe(`X-Keep-${'a'.repeat(300)}: v\r\n\r\n`);
    });

    test('edge cases: empty input, no body, no blank line, no trailing newline, leading blank line, leading continuation', () => {
        expect(strip('')).toBe('');
        expect(strip('Subject: a\r\nX-Spam-Flag: YES\r\n\r\n')).toBe('Subject: a\r\n\r\n');
        expect(strip('Subject: a\r\nX-Spam-Flag: YES\r\n')).toBe('Subject: a\r\n');
        expect(strip('Subject: a\r\nX-Spam-Flag: YES')).toBe('Subject: a\r\n');
        expect(strip('X-Spam-Flag: YES\r\n\tmore')).toBe('');
        expect(strip('\r\nX-Spam-Flag: YES\r\n')).toBe('\r\nX-Spam-Flag: YES\r\n');
        expect(strip(' orphan continuation\r\nSubject: a\r\n\r\n')).toBe(' orphan continuation\r\nSubject: a\r\n\r\n');
        expect(strip('From someone mbox-line\r\nX-Spam-Flag: YES\r\n\r\nb')).toBe('From someone mbox-line\r\n\r\nb');
    });

    test('a continuation after a kept header stays with it; after a removed one it goes', () => {
        expect(strip('Subject: a\r\n b\r\nX-Spam-Flag: Y\r\n c\r\n\td\r\nTo: x\r\n e\r\n\r\n')).toBe('Subject: a\r\n b\r\nTo: x\r\n e\r\n\r\n');
    });

    test('binary body bytes are untouched (never decoded)', () => {
        const head = enc('X-Spam-Flag: YES\r\nSubject: a\r\n\r\n');
        const body = new Uint8Array(512).map((_, index) => index % 256);
        const out = stripHeaders(Buffer.concat([head, body]));
        expect(Buffer.from(out)).toEqual(Buffer.concat([enc('Subject: a\r\n\r\n'), body]));
    });
});

describe('chunk boundaries', () => {
    const cases = [sampleMessage('\r\n'), sampleMessage('\n'), sampleMessage(index => (index % 2 ? '\n' : '\r\n'))];

    test('split into two chunks at every byte offset produces identical output', () => {
        for (const { raw, expected } of cases) {
            const input = enc(raw);
            const whole = Buffer.from(stripHeaders(input));
            expect(dec(whole)).toBe(expected);
            for (let offset = 0; offset <= input.length; offset++) {
                const stripper = new HeaderStripper();
                const out = Buffer.concat([...stripper.push(input.subarray(0, offset)), ...stripper.push(input.subarray(offset)), ...stripper.end()]);
                if (!out.equals(whole)) {
                    throw new Error(`mismatch when split at offset ${offset}`);
                }
            }
        }
    });

    test('one byte at a time produces identical output', () => {
        for (const { raw, expected } of cases) {
            expect(dec(chunked(enc(raw), [1]))).toBe(expected);
        }
    });

    test('seeded random chunkings produce identical output', () => {
        let seed = 0x2545f491;
        const random = () => {
            seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5;
            return (seed >>> 0) / 0x1_0000_0000;
        };
        for (const { raw, expected } of cases) {
            const input = enc(raw);
            for (let round = 0; round < 300; round++) {
                const sizes = Array.from({ length: 16 }, () => 1 + Math.floor(random() * 40));
                expect(dec(chunked(input, sizes))).toBe(expected);
            }
        }
    });

    test('a caller reusing its chunk buffer cannot corrupt pending header bytes', () => {
        const input = enc('Subject: hello world\r\nX-Spam-Flag: YES\r\n\r\nbody');
        const stripper = new HeaderStripper();
        const buffer = new Uint8Array(5);
        const out: Uint8Array[] = [];
        for (let offset = 0; offset < input.length; offset += 5) {
            const piece = input.subarray(offset, offset + 5);
            buffer.fill(0);
            buffer.set(piece);
            // Copy emitted output immediately, as a stream consumer would.
            for (const chunk of stripper.push(buffer.subarray(0, piece.length))) { out.push(chunk.slice()); }
        }
        out.push(...stripper.end());
        expect(dec(Buffer.concat(out))).toBe('Subject: hello world\r\n\r\nbody');
    });
});

describe('limits', () => {
    test('header section over the cap throws HeaderSectionTooLarge', () => {
        const stripper = new HeaderStripper({ maxHeaderBytes: 64 });
        expect(() => stripper.push(enc(`Subject: ${'a'.repeat(100)}\r\n`))).toThrow(HeaderSectionTooLarge);
        const unterminated = new HeaderStripper({ maxHeaderBytes: 64 });
        expect(() => { for (let i = 0; i < 100; i++) { unterminated.push(enc('a')); } }).toThrow(HeaderSectionTooLarge);
    });

    test('the cap applies to headers only; a large body passes', () => {
        const stripper = new HeaderStripper({ maxHeaderBytes: 64 });
        stripper.push(enc('Subject: a\r\n\r\n'));
        expect(() => stripper.push(new Uint8Array(10_000))).not.toThrow();
    });

    test('message over the cap throws MessageTooLarge', () => {
        const stripper = new HeaderStripper({ maxMessageBytes: 100 });
        stripper.push(enc('Subject: a\r\n\r\n'));
        expect(() => stripper.push(new Uint8Array(200))).toThrow(MessageTooLarge);
    });
});

describe('streaming', () => {
    test('a large body is streamed with bounded buffering and arrives intact', async () => {
        const chunkSize = 64 * 1024;
        const chunks = 320; // 20 MiB
        let produced = 0;
        let consumed = 0;
        let maxOutstanding = 0;
        const head = enc('X-Spam-Flag: YES\r\nX-Rspamd-Score: 1\r\n\tfolded\r\nSubject: big\r\n\r\n');
        let sent = 0;
        const source = new ReadableStream<Uint8Array>({
            pull(controller) {
                if (sent === 0) {
                    controller.enqueue(head);
                } else if (sent <= chunks) {
                    const chunk = new Uint8Array(chunkSize).fill(sent % 251);
                    produced += chunk.length;
                    controller.enqueue(chunk);
                } else {
                    controller.close();
                }
                sent++;
            },
        }, { highWaterMark: 0 });
        const stripped = createStrippedBody(source);
        const reader = stripped.stream.getReader();
        let outputBytes = 0;
        let checksum = 0;
        for (;;) {
            const { done, value } = await reader.read();
            if (done) { break; }
            outputBytes += value.length;
            if (outputBytes > 'Subject: big\r\n\r\n'.length) { consumed = outputBytes - 'Subject: big\r\n\r\n'.length; }
            checksum = (checksum + (value[value.length - 1] ?? 0)) % 1_000_003;
            maxOutstanding = Math.max(maxOutstanding, produced - consumed);
        }
        expect(outputBytes).toBe('Subject: big\r\n\r\n'.length + chunkSize * chunks);
        expect(stripped.stripper.removedFields).toBe(2);
        // Never more than a couple of chunks are held between source and consumer.
        expect(maxOutstanding).toBeLessThanOrEqual(2 * chunkSize);
        expect(checksum).toBeGreaterThan(0);
    });

    test('nothing is read from the source until the consumer pulls', async () => {
        let pulls = 0;
        const source = new ReadableStream<Uint8Array>({ pull(controller) { pulls++; controller.enqueue(enc('Subject: a\r\n\r\nbody')); controller.close(); } }, { highWaterMark: 0 });
        const stripped = createStrippedBody(source);
        await Bun.sleep(5);
        expect(pulls).toBe(0);
        expect(dec(new Uint8Array(await new Response(stripped.stream).arrayBuffer()))).toBe('Subject: a\r\n\r\nbody');
        expect(pulls).toBe(1);
    });

    test('failure() distinguishes our own limits from source errors', async () => {
        const tooLarge = createStrippedBody(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(200)); c.close(); } }), { maxMessageBytes: 100 });
        await expect(new Response(tooLarge.stream).arrayBuffer()).rejects.toThrow();
        expect(tooLarge.failure()).toBe('message_too_large');
        const broken = createStrippedBody(new ReadableStream({ pull(c) { c.error(new Error('reset')); } }));
        await expect(new Response(broken.stream).arrayBuffer()).rejects.toThrow();
        expect(broken.failure()).toBe('source_error');
        const header = createStrippedBody(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(200).fill(0x61)); c.close(); } }), { maxHeaderBytes: 100 });
        await expect(new Response(header.stream).arrayBuffer()).rejects.toThrow();
        expect(header.failure()).toBe('header_too_large');
    });
});
