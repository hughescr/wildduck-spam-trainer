import { describe, expect, test } from 'bun:test';
import {
    HeaderSectionTooLarge, HeaderStripper, isPostScanHeaderName, LEADING_DELIVERY_HEADER_NAMES, MalformedMessage, MAX_HEADER_SECTION_BYTES, MessageTooLarge,
    openStrippedBody, POST_SCAN_HEADER_NAMES, POST_SCAN_HEADER_PREFIXES, stripHeaders, type HeaderStripperOptions, type MalformedReason,
} from '../src/header-strip';

const latin1 = (value: string) => new Uint8Array(Buffer.from(value, 'latin1'));
const text = (value: Uint8Array) => Buffer.from(value).toString('latin1');
const strip = (value: string) => text(stripHeaders(latin1(value)));

type Outcome = Buffer | 'malformed' | 'header_too_large';

function malformedReason(value: string): MalformedReason | undefined {
    try {
        stripHeaders(latin1(value));
        return undefined;
    } catch (error) {
        if (error instanceof MalformedMessage) {
            return error.reason;
        }
        throw error;
    }
}

/** Feeds `input` in chunks of the given sizes (cycled) and maps the result like the reference does. */
function run(input: Uint8Array, sizes: readonly number[], options?: HeaderStripperOptions): Outcome {
    const stripper = new HeaderStripper(options);
    const out: Uint8Array[] = [];
    try {
        let offset = 0;
        let index = 0;
        while (offset < input.length) {
            const size = Math.max(1, sizes[index++ % sizes.length] ?? 1);
            out.push(...stripper.push(input.subarray(offset, offset + size)));
            offset += size;
        }
        out.push(...stripper.end());
    } catch (error) {
        if (error instanceof MalformedMessage) {
            return 'malformed';
        }
        if (error instanceof HeaderSectionTooLarge) {
            return 'header_too_large';
        }
        throw error;
    }
    return Buffer.concat(out);
}

const POST_SCAN_EXACT = ['wd-mail-classification', 'wd-mail-classification-source', 'wd-mail-classification-info', 'bimi-location', 'bimi-indicator'];
const POST_SCAN_PREFIXES = ['x-rspamd-', 'x-spamd-', 'x-spam-'];
const LEADING = ['delivered-to', 'return-path'];

/**
 * Whole-buffer reference for every rule, written independently of the
 * implementation: regular expressions over latin1 text of the complete input.
 */
function reference(input: Uint8Array, cap = MAX_HEADER_SECTION_BYTES): Outcome {
    if (input.length === 0) {
        return 'malformed';
    }
    const raw = text(input);
    const blank = /(^|\n)\r?\n/.exec(raw);
    const end = blank ? blank.index + (blank[1] ?? '').length : raw.length;
    const fields: { name: string; text: string }[] = [];
    let lineEnd = 0;
    // Lines are judged in order; one that ends beyond the cap makes the section too large.
    for (const line of raw.slice(0, end).match(/[^\n]*\n|[^\n]+$/g) ?? []) {
        lineEnd += line.length;
        if (lineEnd > cap) {
            return 'header_too_large';
        }
        const content = line.replace(/\r?\n$/, '');
        if (/[\r\0]/.test(content)) {
            return 'malformed';
        }
        const last = fields.at(-1);
        if (/^[ \t]/.test(content)) {
            if (!last) {
                return 'malformed';
            }
            last.text += line;
            continue;
        }
        const field = /^([\x21-\x39\x3b-\x7e]+)[ \t]*:/.exec(content);
        if (!field) {
            return 'malformed';
        }
        fields.push({ name: (field[1] ?? '').toLowerCase(), text: line });
    }
    // No header field at all (judged on the original message, before removals).
    if (fields.length === 0) {
        return 'malformed';
    }
    const drop = fields.map(field => POST_SCAN_EXACT.includes(field.name) || POST_SCAN_PREFIXES.some(prefix => field.name.startsWith(prefix)));
    const [first, second] = fields;
    if (first && LEADING.includes(first.name)) {
        drop[0] = true;
        if (second && second.name !== first.name && LEADING.includes(second.name)) {
            drop[1] = true;
        }
    }
    return Buffer.from(fields.filter((_field, index) => !drop[index]).map(field => field.text).join('') + raw.slice(end), 'latin1');
}

/** Deterministic xorshift32 in [0, 1). */
function seeded(seed: number): () => number {
    let state = seed;
    return () => {
        state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
        return (state >>> 0) / 0x1_0000_0000;
    };
}

const describeOutcome = (outcome: Outcome) => (typeof outcome === 'string' ? outcome : JSON.stringify(text(outcome)));
const same = (a: Outcome, b: Outcome) => (typeof a === 'string' || typeof b === 'string' ? a === b : a.equals(b));

const PRESERVED = [
    'Received: from mx.example.org (mx.example.org [192.0.2.1])',
    '\tby mail.example.com with ESMTPS id abc',
    'Received-SPF: pass (example.org: 192.0.2.1 is authorized)',
    'Authentication-Results: mail.example.com; dkim=pass header.d=example.org;',
    ' spf=pass smtp.mailfrom=example.org',
    'DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=s1;',
    '\tb=AbCdEf==',
    'Original-Authentication-Results: mx.example.org; dkim=pass',
    'ARC-Seal: i=1; a=rsa-sha256; d=example.org; s=arc; cv=none;',
    '\tb=Seal+Seal==',
    'ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed;',
    ' b=Msg+Msg==',
    'ARC-Authentication-Results: i=1; mx.example.org;',
    ' dkim=pass header.d=example.org',
    'X-Spam: kept (no hyphen suffix)',
    'X-Spammy: kept',
    'X-Spamd: kept',
    'X-Spamming-Status: kept',
    'X-Rspamd: 1',
    'X-Rspamdx-Foo: kept',
    'XSpam-Status: kept',
    'X-Not-Spam-Status: kept',
    'WD-Mail-Classification-Other: kept',
    'WD-Mail-Classificatio: kept',
    'X-WD-Mail-Classification: kept',
    'BIMI-Location-Other: kept',
    'BIMI-Indicators: kept',
    'X-BIMI-Indicator: kept',
    'X-Original-Rcpt: me@example.com',
    'X-Zone-Original-Rcpt: me@zone.example.com',
    'Delivered-To: not leading, kept',
    'Return-Path: <not-leading@example.org>',
    'Subject: hello',
];
const REMOVED = [
    'X-Rspamd-Bar: +++',
    'x-rspamd-report: SPF_FAIL(1) R_DKIM_REJECT(1)',
    '\tFOLDED_REPORT(1)',
    'X-RSPAMD-SCORE: 15.2',
    'X-Rspamd-Score \t: 9 (whitespace before the colon)',
    'X-Spam-Status: Yes, score=12',
    '\ttests=FOO,BAR',
    'X-Spam-Flag: YES',
    'X-Spam-Level: ********',
    'X-Spamd-Result: default: False [9.1 / 15.0];',
    ' R_SPF_ALLOW(-0.2)[+ip4:192.0.2.1]',
    'x-spamd-bar: +++++',
    'X-Rspamd-Queue-Id: ABC123',
    'X-Rspamd-Server: rspamd1',
    'X-Rspamd-Action: add header',
    'X-Rspamd-Score-Extra: 1',
    'X-RSPAMD-Spam: yes',
    'X-Spam-: empty suffix',
    `X-Spam-${'long'.repeat(100)}: a name past the exact-name length limit`,
    'BIMI-Location: v=BIMI1; l=https://example.org/logo.svg',
    'bimi-indicator: PHN2Zz4=',
    '\tQUJDREVGR0g=',
    ' SUpLTE1OT1A=',
    'WD-Mail-Classification: spam',
    'wd-mail-classification-source: user',
    'WD-MAIL-CLASSIFICATION-INFO: moved to junk',
    '  folded continuation of the info header',
    ' and another',
];

/** Interleaves removed and preserved fields, keeping each folded group together. */
function sampleMessage(eol: string | ((index: number) => string)): { raw: string; expected: string } {
    const groups = (lines: string[]) => lines.reduce<string[][]>((acc, line) => {
        if (/^[ \t]/.test(line)) { acc[acc.length - 1]?.push(line); } else { acc.push([line]); }
        return acc;
    }, []);
    const keep = groups(PRESERVED);
    const drop = groups(REMOVED);
    let index = 0;
    const end = () => (typeof eol === 'string' ? eol : eol(index++));
    let raw = `Delivered-To: me@example.com${end()}Return-Path: <bounce@example.org>${end()}`;
    let expected = '';
    for (let i = 0; i < Math.max(keep.length, drop.length); i++) {
        for (const line of keep[i] ?? []) { const e = end(); raw += line + e; expected += line + e; }
        for (const line of drop[i] ?? []) { raw += line + end(); }
    }
    const separator = end();
    const body = `Body line one${end()}X-Rspamd-Score: 99${end()}WD-Mail-Classification: spam${end()}Delivered-To: x${end()}\tindented body line${end()}\xe9\xff\x00\r binary-ish`;
    return { raw: raw + separator + body, expected: expected + separator + body };
}

describe('post-scan header names (rule A)', () => {
    test('exactly the five exact names and three prefixes, in exported constants', () => {
        expect([...POST_SCAN_HEADER_NAMES].sort()).toEqual([...POST_SCAN_EXACT].sort());
        expect([...POST_SCAN_HEADER_PREFIXES]).toEqual(POST_SCAN_PREFIXES);
        expect([...LEADING_DELIVERY_HEADER_NAMES]).toEqual(LEADING);
        for (const name of [...POST_SCAN_EXACT, 'x-rspamd-bar', 'x-rspamd-report', 'x-rspamd-score', 'x-rspamd-spam', 'x-spamd-result', 'x-spam-status', 'x-spam-flag']) {
            expect(isPostScanHeaderName(name)).toBe(true);
        }
        for (const name of ['x-spam', 'x-spammy', 'x-spamd', 'x-rspamd', 'x-rspamdx-foo', 'wd-mail-classification-other', 'bimi-location-other', 'x-original-rcpt', 'x-zone-original-rcpt',
            'authentication-results', 'original-authentication-results', 'received', 'received-spf', 'dkim-signature', 'arc-seal', 'arc-message-signature', 'arc-authentication-results', 'delivered-to', 'return-path']) {
            expect(isPostScanHeaderName(name)).toBe(false);
        }
    });

    test('CRLF: removes listed fields with their folded lines, preserves look-alikes and everything else byte-for-byte', () => {
        const { raw, expected } = sampleMessage('\r\n');
        expect(strip(raw)).toBe(expected);
        expect(reference(latin1(raw)).toString('latin1')).toBe(expected);
    });

    test('bare LF and mixed line endings', () => {
        for (const eol of ['\n', (index: number) => (index % 3 === 0 ? '\n' : '\r\n')]) {
            const { raw, expected } = sampleMessage(eol);
            expect(strip(raw)).toBe(expected);
        }
    });

    test('every occurrence is removed, wherever it appears in the header section', () => {
        expect(strip('Subject: a\r\nX-Rspamd-Score: 1\r\nTo: b\r\nX-Rspamd-Score: 2\r\n\tfold\r\nX-RSPAMD-SCORE: 3\r\n\r\nbody')).toBe('Subject: a\r\nTo: b\r\n\r\nbody');
    });

    test('a continuation after a kept field stays with it; after a removed one it goes', () => {
        expect(strip('Subject: a\r\n b\r\nX-Rspamd-Bar: Y\r\n c\r\n\td\r\nTo: x\r\n e\r\n\r\n')).toBe('Subject: a\r\n b\r\nTo: x\r\n e\r\n\r\n');
    });

    test('very long names match only through a prefix family', () => {
        const family = `X-Rspamd-Score-${'a'.repeat(300)}: v\r\n`;
        expect(strip(`Subject: s\r\n${family}\r\nbody`)).toBe('Subject: s\r\n\r\nbody');
        const other = `Received-${'a'.repeat(300)}: v\r\nX-Spam${'a'.repeat(300)}: v\r\nBIMI-Indicator${'a'.repeat(300)}: v\r\n`;
        expect(strip(`${other}\r\nbody`)).toBe(`${other}\r\nbody`);
    });
});

describe('post-scan header families and BIMI fields', () => {
    const BODY = 'Body line\r\nX-Spam-Status: body\r\nBIMI-Indicator: body\r\n\tcontinued\r\n\x00\xe9\xff\r bare';
    const message = (...fields: string[]) => `Received: from a\r\n${fields.join('')}Subject: s\r\n\r\n${BODY}`;
    const clean = `Received: from a\r\nSubject: s\r\n\r\n${BODY}`;

    test('BIMI-Location is removed', () => {
        expect(strip(message('BIMI-Location: v=BIMI1; l=https://example.org/logo.svg\r\n'))).toBe(clean);
        expect(strip(message('bimi-location : v=BIMI1; l=https://example.org/logo.svg\r\n'))).toBe(clean);
    });

    test('a multiline BIMI-Indicator is removed completely, in every line-ending style', () => {
        const indicator = (eol: string) => `BIMI-Indicator: PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv${eol} \tMjAwMC9zdmciPjwvc3ZnPg==${eol}\tQUJD${eol}`;
        expect(strip(message(indicator('\r\n')))).toBe(clean);
        expect(strip(message(indicator('\r\n'), 'X-Original-Rcpt: a@b\r\n', indicator('\r\n')))).toBe(message('X-Original-Rcpt: a@b\r\n'));
        expect(strip('Received: from a\nBIMI-Indicator: AAAA\n BBBB\nSubject: s\n\nbody')).toBe('Received: from a\nSubject: s\n\nbody');
        expect(strip('Subject: s\r\nBIMI-INDICATOR: AAAA\r\n BBBB\r\n')).toBe('Subject: s\r\n');
    });

    test('a very large folded BIMI-Indicator under the header cap is removed completely', () => {
        const lines = Array.from({ length: 12_000 }, (_unused, index) => ` ${'A1b2'.repeat(15)}${index % 10}\r\n`);
        const indicator = `BIMI-Indicator: PHN2Zz4=\r\n${lines.join('')}`;
        expect(indicator.length).toBeGreaterThan(700_000);
        expect(indicator.length).toBeLessThan(MAX_HEADER_SECTION_BYTES);
        const raw = `Received: from a\r\n${indicator}Subject: s\r\n\r\n${BODY}`;
        expect(strip(raw)).toBe(clean);
        // The same result when fed in small chunks.
        const out = run(latin1(raw), [1000, 7, 65_536]);
        expect(typeof out === 'string' ? out : out.toString('latin1')).toBe(clean);
        // Over the cap it is refused like any large header section.
        const oversized = `Received: from a\r\nBIMI-Indicator: x\r\n${lines.join('')}${lines.join('')}Subject: s\r\n\r\nbody`;
        expect(oversized.length).toBeGreaterThan(MAX_HEADER_SECTION_BYTES);
        expect(run(latin1(oversized), [4096])).toBe('header_too_large');
    });

    test('X-Original-Rcpt and X-Zone-Original-Rcpt are preserved', () => {
        const raw = message('X-Original-Rcpt: me@example.com\r\n', 'X-Zone-Original-Rcpt: me@zone.example.com\r\n\t(folded)\r\n', 'x-original-rcpt: second\r\n');
        expect(strip(raw)).toBe(raw);
    });

    test('Authentication-Results and Original-Authentication-Results are preserved', () => {
        const raw = message('Authentication-Results: mail.example.com; dkim=pass header.d=example.org;\r\n spf=pass smtp.mailfrom=example.org\r\n', 'Original-Authentication-Results: mx.example.org; spf=fail\r\n\tdmarc=fail\r\n');
        expect(strip(raw)).toBe(raw);
    });

    test('DKIM-Signature, ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results, Received and Received-SPF are preserved byte-for-byte, folds included', () => {
        const raw = message(
            'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org;\r\n\ts=s1; h=from:to:subject;\r\n\tb=AbCdEf+/==\r\n',
            'ARC-Seal: i=1; a=rsa-sha256; t=1767225600; cv=none; d=example.com;\r\n s=arc; b=SEAL\r\n \tMORE==\r\n',
            'ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed;\r\n\td=example.com; s=arc; b=MSG==\r\n',
            'ARC-Authentication-Results: i=1; mail.example.com;\r\n dkim=pass header.d=example.org;\r\n spf=pass\r\n',
            'Received-SPF: pass (example.org: 192.0.2.1 is authorized)\r\n',
            'Received: from mx.example.org (mx.example.org [192.0.2.1])\r\n\tby mail.example.com with ESMTPS id abc\r\n',
        );
        expect(strip(raw)).toBe(raw);
    });

    test('the observed X-Rspamd result headers are removed with their folds', () => {
        const raw = message('X-Rspamd-Bar: ++++++\r\n', 'X-Rspamd-Report: BAYES_SPAM(5.1) R_DKIM_NA(0.1)\r\n\tMIME_GOOD(-0.1)\r\n', 'X-Rspamd-Score: 15.2\r\n');
        expect(strip(raw)).toBe(clean);
    });

    test('prefix matching removes future fields in any case, with their folds', () => {
        const raw = message(
            'X-Rspamd-Spam: yes\r\n', 'X-Rspamd-Queue-Id: ABC123\r\n', 'x-rspamd-server: rspamd1\r\n', 'X-RSPAMD-FUTURE-THING: 1\r\n\tfolded\r\n',
            'X-Spamd-Result: default: False [9.1 / 15.0];\r\n R_SPF_ALLOW(-0.2)[+ip4:192.0.2.1]\r\n', 'X-SPAMD-Bar: +++\r\n', 'x-spamd-new: 1\r\n',
            'X-Spam-Status: Yes, score=12\r\n\ttests=FOO,BAR\r\n', 'x-spam-flag: YES\r\n', 'X-SpAm-LeVeL: ***\r\n', 'X-Spam-Checker-Version: SpamAssassin\r\n', 'X-Spam-\t: x\r\n',
        );
        expect(strip(raw)).toBe(clean);
    });

    test('names that only look like a family are preserved: X-Spam, X-Spammy and other near misses', () => {
        const raw = message(
            'X-Spam: yes\r\n', 'X-Spammy: yes\r\n', 'X-Spamd: yes\r\n', 'X-Spamming-Status: yes\r\n', 'X-Rspamd: 1\r\n', 'X-Rspamdx-Foo: 1\r\n',
            'XSpam-Status: 1\r\n', 'X-Not-Spam-Status: 1\r\n', 'Spam-Status: 1\r\n', 'WD-Mail-Classification-Other: 1\r\n', 'BIMI-Location-Other: 1\r\n', 'BIMI-Indicators: 1\r\n',
        );
        expect(strip(raw)).toBe(raw);
    });

    test('a continuation line after a preserved near-miss stays with it', () => {
        const raw = 'X-Spammy: a\r\n b\r\nX-Spam-Status: c\r\n d\r\n\te\r\nX-Spam: f\r\n g\r\n\r\nbody';
        expect(strip(raw)).toBe('X-Spammy: a\r\n b\r\nX-Spam: f\r\n g\r\n\r\nbody');
    });

    test('the body is byte-identical when fields are removed, including header-like body lines', () => {
        const head = latin1('X-Spam-Status: Yes\r\nBIMI-Indicator: AAAA\r\n BBBB\r\nX-Rspamd-Score: 1\r\nSubject: s\r\n\r\n');
        const body = new Uint8Array(4096).map((_unused, index) => (index * 13) % 256);
        const out = stripHeaders(new Uint8Array(Buffer.concat([head, body])));
        expect(Buffer.from(out).equals(Buffer.concat([latin1('Subject: s\r\n\r\n'), body]))).toBe(true);
        expect(strip(`Subject: s\r\n\r\nX-Spam-Status: no\r\nBIMI-Location: x\r\n`)).toBe('Subject: s\r\n\r\nX-Spam-Status: no\r\nBIMI-Location: x\r\n');
    });
});

describe('leading delivery headers (rule B)', () => {
    const CASES: [string, string, string][] = [
        ['Delivered-To then Return-Path', 'Delivered-To: a@b\r\nReturn-Path: <a@b>\r\nSubject: s\r\n\r\nbody', 'Subject: s\r\n\r\nbody'],
        ['Return-Path then Delivered-To', 'Return-Path: <a@b>\r\nDelivered-To: a@b\r\nSubject: s\r\n\r\nbody', 'Subject: s\r\n\r\nbody'],
        ['case-insensitive, LF, whitespace before colon', 'DELIVERED-TO : a@b\nreturn-path:<a@b>\nSubject: s\n\nbody', 'Subject: s\n\nbody'],
        ['folded', 'Delivered-To: a@b\r\n\tfolded\r\nReturn-Path:\r\n <a@b>\r\nSubject: s\r\n\r\n', 'Subject: s\r\n\r\n'],
        ['only Delivered-To leading', 'Delivered-To: a@b\r\nSubject: s\r\nReturn-Path: <kept>\r\n\r\n', 'Subject: s\r\nReturn-Path: <kept>\r\n\r\n'],
        ['only Return-Path leading', 'Return-Path: <a@b>\r\nSubject: s\r\nDelivered-To: kept\r\n\r\n', 'Subject: s\r\nDelivered-To: kept\r\n\r\n'],
        ['absent: nothing removed', 'Received: x\r\nDelivered-To: kept\r\nReturn-Path: <kept>\r\n\r\n', 'Received: x\r\nDelivered-To: kept\r\nReturn-Path: <kept>\r\n\r\n'],
        ['at most one of each: a second Delivered-To is kept', 'Delivered-To: a\r\nDelivered-To: b\r\nReturn-Path: <c>\r\n\r\n', 'Delivered-To: b\r\nReturn-Path: <c>\r\n\r\n'],
        ['a third leading field is kept', 'Delivered-To: a\r\nReturn-Path: <b>\r\nDelivered-To: c\r\nReturn-Path: <d>\r\n\r\n', 'Delivered-To: c\r\nReturn-Path: <d>\r\n\r\n'],
        ['combined with post-scan removal', 'Return-Path: <a>\r\nX-Rspamd-Score: 1\r\nDelivered-To: kept\r\n\r\n', 'Delivered-To: kept\r\n\r\n'],
        ['a message of only the leading pair', 'Delivered-To: a\r\nReturn-Path: <b>\r\n', ''],
        ['in the body they are body', 'Subject: s\r\n\r\nDelivered-To: a\r\nReturn-Path: <b>\r\n', 'Subject: s\r\n\r\nDelivered-To: a\r\nReturn-Path: <b>\r\n'],
    ];
    for (const [name, raw, expected] of CASES) {
        test(name, () => {
            expect(strip(raw)).toBe(expected);
            expect(reference(latin1(raw)).toString('latin1')).toBe(expected);
        });
    }
});

describe('malformed messages (rule C)', () => {
    const CASES: [string, string, MalformedReason][] = [
        ['bare CR inside a value', 'Subject: a\rb\r\n\r\nbody', 'bare_cr'],
        ['bare-CR line endings', 'Subject: keep\rTo: x\r\rbody', 'bare_cr'],
        ['CR CR LF', 'Subject: a\r\r\n\r\n', 'bare_cr'],
        ['bare CR inside a removed field continuation', 'X-Rspamd-Score: 1\r\n\tfold\rbare\r\n\r\n', 'bare_cr'],
        ['bare CR at the end of input', 'Subject: a\r', 'bare_cr'],
        ['blank line made of a bare CR', 'Subject: a\r\n\rTo: b\r\n\r\n', 'bare_cr'],
        ['NUL in a value', 'Subject: a\x00b\r\n\r\n', 'nul'],
        ['NUL in a field name', 'Sub\x00ject: a\r\n\r\n', 'nul'],
        ['line without a colon', 'Subject: a\r\nX-Spam-Flag\r\n\r\n', 'invalid_line'],
        ['body without a separator', 'Subject: a\nThis is the body\n', 'invalid_line'],
        ['space inside a field name', 'Bad Name: x\r\n\r\n', 'invalid_line'],
        ['leading colon', ':x\r\n\r\n', 'invalid_line'],
        ['8-bit field name', '\xe9t\xe9: x\r\n\r\n', 'invalid_line'],
        ['control byte in a field name', 'Na\x01me: x\r\n\r\n', 'invalid_line'],
        ['incomplete field name at the end of input', 'Subject: a\r\nSubject', 'invalid_line'],
        ['mbox From line later on', 'Subject: a\r\nFrom sender later\r\n\r\n', 'invalid_line'],
        ['continuation before any field', ' leading continuation\r\nSubject: a\r\n\r\n', 'leading_continuation'],
        ['tab continuation first', '\tx\r\n\r\n', 'leading_continuation'],
        ['mbox From envelope line first', 'From sender@example.org Mon Jan  1 00:00:00 2026\r\nSubject: s\r\n\r\nb', 'mbox_envelope'],
        ['bare mbox From line', 'From ', 'mbox_envelope'],
        ['empty message', '', 'empty'],
        ['starts with the blank line (CRLF)', '\r\nbody', 'no_headers'],
        ['starts with the blank line (LF)', '\nbody', 'no_headers'],
        ['starts with the blank line, header-like body', '\r\nX-Rspamd-Score: 1\r\n', 'no_headers'],
        ['a lone CRLF', '\r\n', 'no_headers'],
        ['a lone LF', '\n', 'no_headers'],
        ['only blank lines', '\r\n\r\n\n\r\n', 'no_headers'],
    ];
    for (const [name, raw, reason] of CASES) {
        test(`${name} → ${reason}`, () => {
            expect(malformedReason(raw)).toBe(reason);
            expect(reference(latin1(raw))).toBe('malformed');
        });
    }

    test('a malformed line at any position rejects the whole message (nothing is emitted)', () => {
        const fields = ['Delivered-To: a\r\n', 'Received: from a\r\n', '\tby b\r\n', 'X-Rspamd-Score: 1\r\n', ' folded\r\n', 'Subject: s\r\n'];
        for (const bad of ['not a header\r\n', 'X-Spam-Flag: bare\rCR\r\n', 'Bad Name: x\r\n', ':x\r\n', '\xe9: x\r\n', 'X: a\x00\r\n']) {
            for (let position = 1; position <= fields.length; position++) {
                const raw = fields.slice(0, position).join('') + bad + fields.slice(position).join('') + '\r\nbody\r\n';
                const input = latin1(raw);
                for (const size of [input.length, 1, 3, 7]) {
                    const stripper = new HeaderStripper();
                    const emitted: Uint8Array[] = [];
                    expect(() => {
                        for (let offset = 0; offset < input.length; offset += size) {
                            emitted.push(...stripper.push(input.subarray(offset, offset + size)));
                        }
                        stripper.end();
                    }).toThrow(MalformedMessage);
                    expect(emitted).toHaveLength(0);
                }
            }
            // After the blank separator the same line is ordinary body.
            expect(strip(`${fields.join('')}\r\n${bad}`)).toBe(`Received: from a\r\n\tby b\r\nSubject: s\r\n\r\n${bad}`);
        }
    });
});

describe('valid edge cases', () => {
    test('a message with headers but no blank line or body, with or without a final newline', () => {
        expect(strip('Subject: a\r\nX-Rspamd-Bar: +\r\n')).toBe('Subject: a\r\n');
        expect(strip('Subject: a\r\nX-Rspamd-Bar: +')).toBe('Subject: a\r\n');
        expect(strip('X-Rspamd-Bar: +\r\n\tmore')).toBe('');
        expect(strip('Subject: a')).toBe('Subject: a');
    });

    test('8-bit bytes in values and very long lines are preserved', () => {
        const raw = `Subject: caf\xe9 \xff\xfe\x80\r\nX-Long: ${'v'.repeat(200_000)}\r\nX-Rspamd-Score: 1\r\n\r\nbody`;
        expect(strip(raw)).toBe(`Subject: caf\xe9 \xff\xfe\x80\r\nX-Long: ${'v'.repeat(200_000)}\r\n\r\nbody`);
    });

    test('the no-header rule is judged before removals: a message of only removed fields is valid', () => {
        expect(strip('Delivered-To: a\r\nReturn-Path: <b>\r\n\r\nbody')).toBe('\r\nbody');
        expect(strip('X-Rspamd-Score: 1\n\nbody')).toBe('\nbody');
    });

    test('a message with nothing to remove is returned unchanged', () => {
        const raw = 'Received: x\r\nSubject: y\r\n\r\nbody';
        expect(strip(raw)).toBe(raw);
    });
});

describe('body byte identity', () => {
    test('binary bodies (every byte value, NUL, bare CR) are untouched', () => {
        const head = latin1('Delivered-To: a\r\nReturn-Path: <b>\r\nX-Rspamd-Score: 1\r\nSubject: a\r\n\r\n');
        const body = new Uint8Array(4096).map((_, index) => (index * 7) % 256);
        const out = stripHeaders(new Uint8Array(Buffer.concat([head, body])));
        expect(Buffer.from(out).equals(Buffer.concat([latin1('Subject: a\r\n\r\n'), body]))).toBe(true);
    });

    test('a body line that looks like a removable header survives', () => {
        const raw = 'Subject: a\r\n\r\nX-Rspamd-Score: 99\r\nWD-Mail-Classification: spam\r\n\tcontinued\r\n';
        expect(strip(raw)).toBe(raw);
    });
});

describe('chunk boundaries against the whole-buffer reference', () => {
    const cases = [
        sampleMessage('\r\n').raw,
        sampleMessage('\n').raw,
        sampleMessage(index => (index % 2 ? '\n' : '\r\n')).raw,
        'Delivered-To: a\r\nReturn-Path: <b>\r\n',
        'Subject: a\r\nX-Rspamd-Bar: +',
        'Subject: a\r\n\r',
        'Subject: a\n\r\n',
        'Subject: a\r\n\r\n',
        '\r\n\r\n',
        '\r\nbody',
        '\nbody',
        'Delivered-To: a\r\nReturn-Path: <b>\r\n\r\nbody',
        'Subject: a\r\nnot a header\r\n\r\nbody',
        'Subject: a\rb\r\n\r\nbody',
        'Subject: a\r',
        ' lead\r\n\r\n',
        'From x\r\n\r\n',
        'Subject: a\x00\r\n\r\n',
    ];

    test('split into two chunks at every byte offset matches the reference', () => {
        for (const raw of cases) {
            const input = latin1(raw);
            const expected = reference(input);
            for (let offset = 0; offset <= input.length; offset++) {
                const stripper = new HeaderStripper();
                let outcome: Outcome;
                try {
                    outcome = Buffer.concat([...stripper.push(input.subarray(0, offset)), ...stripper.push(input.subarray(offset)), ...stripper.end()]);
                } catch (error) {
                    outcome = error instanceof MalformedMessage ? 'malformed' : 'header_too_large';
                }
                if (!same(outcome, expected)) {
                    throw new Error(`mismatch for ${JSON.stringify(raw)} split at ${offset}: ${describeOutcome(outcome)} vs ${describeOutcome(expected)}`);
                }
            }
            expect(same(run(input, [1]), expected)).toBe(true);
        }
    });

    test('seeded randomized messages and chunkings match the reference (valid, malformed and oversized)', () => {
        const random = seeded(0x5eed_1234);
        const pick = <T,>(items: readonly T[]): T => items[Math.floor(random() * items.length)] as T;
        const names = ['Subject', 'X-Spam-Flag', 'X-Spam-Status', 'X-Spamd-Result', 'X-Rspamd-Queue-Id', 'X-Rspamd-Server', 'X-Rspamd-Score', 'x-rspamd-bar', 'X-RSPAMD-REPORT',
            'X-Spam', 'X-Spammy', 'X-Rspamd', 'BIMI-Location', 'bimi-indicator', 'BIMI-Indicators', 'X-Original-Rcpt', 'DKIM-Signature', `X-Spam-${'n'.repeat(40)}`,
            'WD-Mail-Classification', 'wd-mail-classification-source', 'WD-MAIL-CLASSIFICATION-INFO', 'WD-Mail-Classification-Other', 'Received', 'Delivered-To', 'Return-Path', 'From', 'To'];
        const values = ['', ' v', ' value with spaces', '\tTAB value', ' caf\xe9 \xff', ' a:b:c', ` ${'x'.repeat(90)}`];
        const malformed = ['no colon here', ':leading colon', 'Bad Name: x', 'Subject', 'From sender date', 'Na\x00me: x', 'X: a\x00b', '\xe9name: x', ' '];
        const counts = { ok: 0, malformed: 0, header_too_large: 0 };
        let noHeaders = 0;
        for (let round = 0; round < 4000; round++) {
            const clean = random() < 0.5;
            const eol = () => (clean ? pick(['\r\n', '\n']) : pick(['\r\n', '\r\n', '\n', '\n', '\r']));
            const field = () => `${pick(names)}${pick(['', '', ' ', '\t '])}:${pick(values)}`;
            let raw = '';
            const leading = random();
            if (leading < 0.25) { raw += `Delivered-To: a@b${eol()}Return-Path: <a@b>${eol()}`; }
            else if (leading < 0.35) { raw += `Return-Path: <a@b>${eol()}Delivered-To: a@b${eol()}`; }
            else if (leading < 0.4) { raw += `Delivered-To: a${eol()}\tfolded${eol()}Delivered-To: b${eol()}`; }
            const count = Math.floor(random() * 10);
            for (let index = 0; index < count; index++) {
                const roll = random();
                let line: string;
                if (roll < 0.6 || (clean && roll >= 0.85)) { line = field(); }
                else if (roll < 0.85) { line = `${pick([' ', '\t'])}${pick(['more', 'folded value', ''])}`; }
                else if (roll < 0.93) { line = pick(malformed); }
                else { const base = field(); const at = Math.floor(random() * (base.length + 1)); line = `${base.slice(0, at)}\r${base.slice(at)}`; }
                raw += line + eol();
            }
            const ending = random();
            if (ending < 0.6) {
                raw += `${pick(['\r\n', '\n'])}body line${eol()}X-Rspamd-Score: 1${eol()}\tindented\xe9\x00\r${pick(['', '\r\n'])}`;
            } else if (ending < 0.8 && raw.length > 0) {
                raw = raw.slice(0, -1);
            } else if (ending < 0.82) {
                raw = '';
            }
            const input = latin1(raw);
            const cap = pick([MAX_HEADER_SECTION_BYTES, MAX_HEADER_SECTION_BYTES, 40, 120, 300]);
            const expected = reference(input, cap);
            const sizes = Array.from({ length: 8 }, () => 1 + Math.floor(random() * (random() < 0.5 ? 4 : 64)));
            const outcome = run(input, sizes, { maxHeaderBytes: cap });
            if (!same(outcome, expected)) {
                throw new Error(`round ${round} (cap ${cap}, sizes ${sizes.join(',')}): ${JSON.stringify(raw)} → ${describeOutcome(outcome)}, reference ${describeOutcome(expected)}`);
            }
            counts[typeof expected === 'string' ? expected : 'ok']++;
            if (expected === 'malformed' && malformedReason(raw) === 'no_headers') {
                noHeaders++;
            }
        }
        // The generator exercises every path substantially, including messages with no header field.
        expect(counts.ok).toBeGreaterThan(1000);
        expect(counts.malformed).toBeGreaterThan(1000);
        expect(counts.header_too_large).toBeGreaterThan(200);
        expect(noHeaders).toBeGreaterThan(50);
    });

    test('a caller reusing its chunk buffer cannot corrupt buffered header bytes', () => {
        const input = latin1('Subject: hello world\r\nX-Rspamd-Score: 1\r\n\r\nbody');
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
        expect(text(Buffer.concat(out))).toBe('Subject: hello world\r\n\r\nbody');
    });
});

describe('limits', () => {
    test('a header section over the cap throws HeaderSectionTooLarge, with or without a separator', () => {
        expect(() => new HeaderStripper({ maxHeaderBytes: 64 }).push(latin1(`Subject: ${'a'.repeat(100)}\r\n\r\n`))).toThrow(HeaderSectionTooLarge);
        const unterminated = new HeaderStripper({ maxHeaderBytes: 64 });
        expect(() => { for (let i = 0; i < 100; i++) { unterminated.push(latin1('a')); } }).toThrow(HeaderSectionTooLarge);
        // Refused as soon as the incomplete line passes the cap, without waiting for its end.
        const incomplete = new HeaderStripper({ maxHeaderBytes: 64 });
        incomplete.push(latin1(`S:${'a'.repeat(62)}`));
        expect(() => incomplete.push(latin1('a'))).toThrow(HeaderSectionTooLarge);
        // A malformed line within the cap is refused at once, even with more input to come.
        const early = new HeaderStripper({ maxHeaderBytes: 64 });
        expect(() => early.push(latin1('Subject: a\r\nnot a header\r\n'))).toThrow(MalformedMessage);
    });

    test('a header section of exactly the cap is accepted', () => {
        const head = `S:${'a'.repeat(60)}\r\n`;
        expect(head.length).toBe(64);
        expect(text(stripHeaders(latin1(`${head}\r\nbody`), { maxHeaderBytes: 64 }))).toBe(`${head}\r\nbody`);
        expect(text(stripHeaders(latin1(head), { maxHeaderBytes: 64 }))).toBe(head);
    });

    test('the cap applies to headers only; a large body passes', () => {
        const stripper = new HeaderStripper({ maxHeaderBytes: 64 });
        stripper.push(latin1('Subject: a\r\n\r\n'));
        expect(() => stripper.push(new Uint8Array(10_000))).not.toThrow();
    });

    test('message over the cap throws MessageTooLarge', () => {
        const stripper = new HeaderStripper({ maxMessageBytes: 100 });
        stripper.push(latin1('Subject: a\r\n\r\n'));
        expect(() => stripper.push(new Uint8Array(200))).toThrow(MessageTooLarge);
    });
});

describe('openStrippedBody', () => {
    const sourceOf = (chunks: Uint8Array[], onCancel?: () => void) => {
        let index = 0;
        return new ReadableStream<Uint8Array>({
            pull(controller) {
                const chunk = chunks[index++];
                if (chunk) { controller.enqueue(chunk); } else { controller.close(); }
            },
            cancel() { onCancel?.(); },
        }, { highWaterMark: 0 });
    };

    test('a large body is streamed with bounded buffering and arrives intact', async () => {
        const chunkSize = 64 * 1024;
        const chunks = 320; // 20 MiB
        let produced = 0;
        let consumed = 0;
        let maxOutstanding = 0;
        const head = latin1('Delivered-To: a\r\nX-Rspamd-Score: 1\r\n\tfolded\r\nSubject: big\r\n\r\n');
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
        const opened = await openStrippedBody(source);
        if (!opened.ok) { throw new Error('expected ok'); }
        const reader = opened.body.stream.getReader();
        const headerOut = 'Subject: big\r\n\r\n'.length;
        let outputBytes = 0;
        let checksum = 0;
        for (;;) {
            const { done, value } = await reader.read();
            if (done) { break; }
            outputBytes += value.length;
            consumed = Math.max(0, outputBytes - headerOut);
            checksum = (checksum + (value[value.length - 1] ?? 0)) % 1_000_003;
            maxOutstanding = Math.max(maxOutstanding, produced - consumed);
        }
        expect(outputBytes).toBe(headerOut + chunkSize * chunks);
        expect(opened.body.stripper.removedFields).toBe(2);
        // Never more than a couple of chunks are held between source and consumer.
        expect(maxOutstanding).toBeLessThanOrEqual(2 * chunkSize);
        expect(checksum).toBeGreaterThan(0);
    });

    test('reads exactly the header section before returning; the body only when the consumer pulls', async () => {
        let pulls = 0;
        const parts = [latin1('Subject: a\r\nX-Rspamd-'), latin1('Bar: +\r\n'), latin1('\r\nbody one'), latin1(' body two')];
        const source = new ReadableStream<Uint8Array>({ pull(controller) { const part = parts[pulls++]; if (part) { controller.enqueue(part); } else { controller.close(); } } }, { highWaterMark: 0 });
        const opened = await openStrippedBody(source);
        if (!opened.ok) { throw new Error('expected ok'); }
        expect(pulls).toBe(3);
        await Bun.sleep(5);
        expect(pulls).toBe(3);
        expect(text(new Uint8Array(await new Response(opened.body.stream).arrayBuffer()))).toBe('Subject: a\r\n\r\nbody one body two');
    });

    test('a malformed or oversized header section is refused and the source cancelled', async () => {
        for (const [chunks, failure, malformed] of [
            [[latin1('Subject: a\r\nbad line\r\n\r\n'), new Uint8Array(1024)], 'malformed_message', 'invalid_line'],
            [[latin1('Subject: a\r'), latin1('x\r\n\r\n')], 'malformed_message', 'bare_cr'],
            [[], 'malformed_message', 'empty'],
            [[latin1('\r\nbody'), new Uint8Array(1024)], 'malformed_message', 'no_headers'],
            [[latin1(`S: ${'a'.repeat(200)}`)], 'header_too_large', undefined],
        ] as const) {
            let cancelled = false;
            const opened = await openStrippedBody(sourceOf([...chunks], () => { cancelled = true; }), { maxHeaderBytes: 100 });
            expect(opened).toEqual({ ok: false, failure, ...(malformed ? { malformed } : {}) });
            expect(cancelled || chunks.length === 0).toBe(true);
        }
    });

    test('source errors: in the header section the open fails; in the body failure() says source_error', async () => {
        const headFails = await openStrippedBody(new ReadableStream({ pull(controller) { controller.error(new Error('reset')); } }));
        expect(headFails).toEqual({ ok: false, failure: 'source_error' });
        const nonBytes = await openStrippedBody(new ReadableStream({ start(controller) { controller.enqueue('text' as unknown as Uint8Array); } }));
        expect(nonBytes).toEqual({ ok: false, failure: 'source_error' });
        let sent = false;
        const bodyFails = await openStrippedBody(new ReadableStream({ pull(controller) { if (sent) { controller.error(new Error('reset')); } else { sent = true; controller.enqueue(latin1('Subject: a\r\n\r\nx')); } } }));
        if (!bodyFails.ok) { throw new Error('expected ok'); }
        await expect(new Response(bodyFails.body.stream).arrayBuffer()).rejects.toThrow();
        expect(bodyFails.body.failure()).toBe('source_error');
        const tooLarge = await openStrippedBody(sourceOf([latin1('Subject: a\r\n\r\n'), new Uint8Array(200)]), { maxMessageBytes: 100 });
        if (!tooLarge.ok) { throw new Error('expected ok'); }
        await expect(new Response(tooLarge.body.stream).arrayBuffer()).rejects.toThrow();
        expect(tooLarge.body.failure()).toBe('message_too_large');
    });

    test('an aborted signal stops a hanging header read', async () => {
        const controller = new AbortController();
        const hanging = new ReadableStream<Uint8Array>({ start(c) { c.enqueue(latin1('Subject: a\r\n')); } });
        setTimeout(() => controller.abort(), 20);
        const started = Date.now();
        expect(await openStrippedBody(hanging, { signal: controller.signal })).toEqual({ ok: false, failure: 'source_error' });
        expect(Date.now() - started).toBeLessThan(1_000);
        const already = await openStrippedBody(sourceOf([latin1('Subject: a\r\n\r\n')]), { signal: AbortSignal.abort() });
        expect(already).toEqual({ ok: false, failure: 'source_error' });
    });
});

describe('openStrippedBody upload state', () => {
    const open = async (source: ReadableStream<Uint8Array>, options?: Parameters<typeof openStrippedBody>[1]) => {
        const opened = await openStrippedBody(source, options);
        if (!opened.ok) { throw new Error('expected ok'); }
        return opened.body;
    };
    /** A source that serves `chunks`, then ends (or stalls when `stall` is set). */
    const sourceOf = (chunks: Uint8Array[], options: { stall?: boolean; onCancel?: () => void } = {}) => {
        let index = 0;
        return new ReadableStream<Uint8Array>({
            pull(controller) {
                const chunk = chunks[index++];
                if (chunk) { controller.enqueue(chunk); return undefined; }
                return options.stall ? new Promise<void>(() => undefined) : controller.close();
            },
            cancel() { options.onCancel?.(); },
        }, { highWaterMark: 0 });
    };
    /** Reads `count` chunks (all when undefined) and reports how the read ended. */
    const consume = async (reader: ReadableStreamDefaultReader<Uint8Array>, count = Infinity) => {
        const parts: Uint8Array[] = [];
        try {
            while (parts.length < count) {
                const { done, value } = await reader.read();
                if (done) { return { text: text(new Uint8Array(Buffer.concat(parts))), end: 'eof' as const }; }
                parts.push(value);
            }
        } catch {
            return { text: text(new Uint8Array(Buffer.concat(parts))), end: 'error' as const };
        }
        return { text: text(new Uint8Array(Buffer.concat(parts))), end: undefined };
    };

    test('complete only once the consumer has pulled every byte and the end', async () => {
        const body = await open(sourceOf([latin1('X-Rspamd-Score: 1\r\nSubject: a\r\n\r\none'), latin1(' two'), latin1(' three')]));
        const reader = body.stream.getReader();
        const first = await consume(reader, 3);
        expect(first).toEqual({ text: 'Subject: a\r\n\r\none two', end: undefined });
        await Bun.sleep(5);
        expect(body.state()).toBe('pending');
        expect(await consume(reader, 1)).toEqual({ text: ' three', end: undefined });
        // Every byte pulled, but not yet the end.
        expect(body.state()).toBe('pending');
        expect(await consume(reader)).toEqual({ text: '', end: 'eof' });
        expect(body.state()).toBe('complete');
        expect(await body.settled).toBe('complete');
        expect(body.signal.aborted).toBe(false);
        // abort() after completion changes nothing.
        body.abort();
        expect(body.state()).toBe('complete');
        expect(body.signal.aborted).toBe(false);
    });

    test('a header-only message completes after its single chunk', async () => {
        const body = await open(sourceOf([latin1('Subject: a\r\nX-Rspamd-Bar: +\r\n')]));
        expect(await consume(body.stream.getReader())).toEqual({ text: 'Subject: a\r\n', end: 'eof' });
        expect(await body.settled).toBe('complete');
    });

    test('abort() mid-upload ends the stream by error, never a clean end, cancels the source and aborts the signal', async () => {
        let cancelled = false;
        const body = await open(sourceOf([latin1('Subject: x\r\n\r\npartial'), latin1('more')], { stall: true, onCancel: () => { cancelled = true; } }));
        const reader = body.stream.getReader();
        // The normalized header section, then the rest of that chunk from the separator on.
        expect(await consume(reader, 2)).toEqual({ text: 'Subject: x\r\n\r\npartial', end: undefined });
        body.abort();
        expect(await consume(reader)).toEqual({ text: '', end: 'error' });
        expect(body.state()).toBe('failed');
        expect(body.failure()).toBeUndefined();
        expect(body.signal.aborted).toBe(true);
        expect(cancelled).toBe(true);
        expect(await body.settled).toBe('failed');
    });

    test('abort() while a source read is in flight: the cancelled source end is not the message end', async () => {
        const body = await open(sourceOf([latin1('Subject: x\r\n\r\n')], { stall: true }));
        const reader = body.stream.getReader();
        expect(await consume(reader, 2)).toEqual({ text: 'Subject: x\r\n\r\n', end: undefined });
        const pending = consume(reader);
        await Bun.sleep(5);
        body.abort();
        expect(await pending).toEqual({ text: '', end: 'error' });
        expect(body.state()).toBe('failed');
    });

    test('a source error mid-body errors the upload and aborts the signal', async () => {
        let sent = false;
        const body = await open(new ReadableStream({ pull(controller) { if (sent) { controller.error(new Error('reset')); } else { sent = true; controller.enqueue(latin1('Subject: x\r\n\r\npartial')); } } }));
        expect(await consume(body.stream.getReader())).toEqual({ text: 'Subject: x\r\n\r\npartial', end: 'error' });
        expect(body.failure()).toBe('source_error');
        expect(body.signal.aborted).toBe(true);
        expect(await body.settled).toBe('failed');
    });

    test('the size cap mid-body errors the upload and aborts the signal', async () => {
        const body = await open(sourceOf([latin1('Subject: a\r\n\r\n'), new Uint8Array(60), new Uint8Array(60)]), { maxMessageBytes: 100 });
        expect((await consume(body.stream.getReader())).end).toBe('error');
        expect(body.failure()).toBe('message_too_large');
        expect(body.signal.aborted).toBe(true);
    });

    test('the signal fails an unfinished upload even while the consumer is not reading', async () => {
        const deadline = new AbortController();
        let cancelled = false;
        const body = await open(sourceOf([latin1('Subject: a\r\n\r\nbody')], { onCancel: () => { cancelled = true; } }), { signal: deadline.signal });
        const reader = body.stream.getReader();
        expect(await consume(reader, 1)).toEqual({ text: 'Subject: a\r\n', end: undefined });
        deadline.abort();
        expect(body.state()).toBe('failed');
        expect(body.failure()).toBe('source_error');
        expect(body.signal.aborted).toBe(true);
        expect(cancelled).toBe(true);
        expect(await consume(reader)).toEqual({ text: '', end: 'error' });
    });

    test('a consumer cancel fails the upload (it never completed)', async () => {
        const body = await open(sourceOf([latin1('Subject: a\r\n\r\nbody'), latin1('more')]));
        const reader = body.stream.getReader();
        await consume(reader, 1);
        await reader.cancel();
        expect(body.state()).toBe('failed');
        expect(body.failure()).toBeUndefined();
        expect(body.signal.aborted).toBe(true);
    });

    test('a source whose cancel never settles does not block abort()', async () => {
        const source = new ReadableStream<Uint8Array>({
            start(controller) { controller.enqueue(latin1('Subject: a\r\n\r\nbody')); },
            cancel: () => new Promise<void>(() => undefined),
        }, { highWaterMark: 0 });
        const body = await open(source);
        body.abort();
        expect(await body.settled).toBe('failed');
    });
});
