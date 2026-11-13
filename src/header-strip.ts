/**
 * Byte-level header normalization for Bayes training.
 *
 * Principle: reconstruct the message as it was when Rspamd originally scanned
 * it. Only header fields that our own pipeline adds after the scan are removed;
 * every header field that was (or may have been) present at scan time, and the
 * body, are preserved byte for byte. When unsure, preserve. A message that looks
 * malformed is not trained at all.
 *
 * Rules:
 * 1. Every field named in {@link POST_SCAN_HEADER_NAMES} (exact, case-insensitive
 *    name; whitespace before the colon allowed) is removed wherever it appears in
 *    the header section, together with its folded continuation lines.
 * 2. WildDuck prepends `Delivered-To` and `Return-Path` to every stored message.
 *    They are removed only while they are the leading fields: the first field if
 *    it is one of them, then the second if it is the other one (either order, at
 *    most one of each). Later occurrences are preserved.
 * 3. The header section is validated before anything is emitted. It is malformed
 *    (see {@link MalformedReason}) on a bare CR, a NUL byte, a line that is neither
 *    a field start (`name[WSP]:`, name bytes 33-126 except `:`) nor a continuation
 *    line after a field, a continuation line before any field, an mbox `From `
 *    envelope line, or an empty message. CRLF, bare LF and mixed line endings,
 *    8-bit bytes in field values, long lines and a message without a blank line
 *    or body are valid.
 *
 * The output is the input minus exactly the removed fields: nothing is
 * reordered, re-folded, decoded or re-encoded. The header section is buffered
 * and validated line by line before anything is emitted; a header line ending
 * beyond {@link MAX_HEADER_SECTION_BYTES} makes it too large. The body is
 * streamed through unchanged without buffering, whatever it contains.
 */

export const MAX_HEADER_SECTION_BYTES = 1024 * 1024;
/** The Nginx training proxy accepts at most 25 MiB. */
export const MAX_MESSAGE_BYTES = 25 * 1024 * 1024;

/**
 * Lower-cased names of the header fields added after the Rspamd scan, removed
 * wherever they appear:
 * - `X-Rspamd-Bar`, `X-Rspamd-Report`, `X-Rspamd-Score`: added by Haraka from the scan result
 * - `WD-Mail-Classification`, `-Source`, `-Info`: the only fields WildDuck's filter handler adds
 */
export const POST_SCAN_HEADER_NAMES: ReadonlySet<string> = new Set([
    'x-rspamd-bar',
    'x-rspamd-report',
    'x-rspamd-score',
    'wd-mail-classification',
    'wd-mail-classification-source',
    'wd-mail-classification-info',
]);

/** Lower-cased names of the delivery fields WildDuck prepends; removed only as the leading fields. */
export const LEADING_DELIVERY_HEADER_NAMES: readonly string[] = ['delivered-to', 'return-path'];

/** Category codes for a malformed message (never content). */
export type MalformedReason = 'empty' | 'bare_cr' | 'nul' | 'invalid_line' | 'leading_continuation' | 'mbox_envelope';

export class HeaderSectionTooLarge extends Error {
    override readonly name = 'HeaderSectionTooLarge';
}

export class MessageTooLarge extends Error {
    override readonly name = 'MessageTooLarge';
}

export class MalformedMessage extends Error {
    override readonly name = 'MalformedMessage';
    constructor(readonly reason: MalformedReason) {
        super(reason);
    }
}

const NUL = 0x00;
const LF = 0x0a;
const CR = 0x0d;
const SP = 0x20;
const HTAB = 0x09;
const COLON = 0x3a;
/** `From `: an mbox envelope line. */
const MBOX_FROM = [0x46, 0x72, 0x6f, 0x6d, SP] as const;
/** No listed name is longer; longer names are never lower-cased. */
const MAX_LISTED_NAME_BYTES = 32;

/** RFC 5322 field-name byte: printable US-ASCII except the colon. */
const isNameByte = (byte: number) => byte >= 0x21 && byte <= 0x7e && byte !== COLON;
const isWsp = (byte: number | undefined) => byte === SP || byte === HTAB;

/** True when a lower-cased header field name is one of the post-scan fields removed everywhere. */
export function isPostScanHeaderName(lowerName: string): boolean {
    return POST_SCAN_HEADER_NAMES.has(lowerName);
}

function lowerAscii(bytes: Uint8Array, start: number, end: number): string {
    let name = '';
    for (let index = start; index < end; index++) {
        const byte = bytes[index] ?? 0;
        name += String.fromCharCode(byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte);
    }
    return name;
}

function startsWithMboxFrom(bytes: Uint8Array, start: number, end: number): boolean {
    return end - start >= MBOX_FROM.length && MBOX_FROM.every((byte, offset) => bytes[start + offset] === byte);
}

interface Field {
    start: number;
    end: number;
    /** Lower-cased name, or '' when it is too long to be a listed name. */
    name: string;
}

export interface NormalizedHeaders {
    /** The header section minus the removed fields (the input itself when nothing was removed). */
    readonly output: Uint8Array;
    readonly removedFields: number;
}

/**
 * Validates one non-blank header line bytes[start, end), its LF included when it
 * has one, and records it in `fields`. Throws MalformedMessage.
 */
function acceptLine(bytes: Uint8Array, start: number, end: number, fields: Field[]): void {
    // Content excludes the line terminator (LF or CRLF); any other CR in it is bare.
    const terminated = bytes[end - 1] === LF;
    const contentEnd = !terminated ? end : end - 1 > start && bytes[end - 2] === CR ? end - 2 : end - 1;
    const content = bytes.subarray(start, contentEnd);
    if (content.includes(NUL)) {
        throw new MalformedMessage('nul');
    }
    if (content.includes(CR)) {
        throw new MalformedMessage('bare_cr');
    }
    if (isWsp(bytes[start])) {
        const last = fields.at(-1);
        if (!last) {
            throw new MalformedMessage('leading_continuation');
        }
        last.end = end;
        return;
    }
    let index = start;
    while (index < contentEnd && isNameByte(bytes[index] ?? 0)) {
        index++;
    }
    const nameEnd = index;
    while (index < contentEnd && isWsp(bytes[index])) {
        index++;
    }
    if (nameEnd === start || index >= contentEnd || bytes[index] !== COLON) {
        throw new MalformedMessage(fields.length === 0 && startsWithMboxFrom(bytes, start, contentEnd) ? 'mbox_envelope' : 'invalid_line');
    }
    fields.push({ start, end, name: nameEnd - start <= MAX_LISTED_NAME_BYTES ? lowerAscii(bytes, start, nameEnd) : '' });
}

/** Applies rules A and B to a validated header section. */
function removeFields(section: Uint8Array, fields: readonly Field[]): NormalizedHeaders {
    const removed = new Set<number>();
    const first = fields[0];
    if (first && LEADING_DELIVERY_HEADER_NAMES.includes(first.name)) {
        removed.add(0);
        const second = fields[1];
        if (second && second.name !== first.name && LEADING_DELIVERY_HEADER_NAMES.includes(second.name)) {
            removed.add(1);
        }
    }
    fields.forEach((field, index) => {
        if (isPostScanHeaderName(field.name)) {
            removed.add(index);
        }
    });
    if (removed.size === 0) {
        return { output: section, removedFields: 0 };
    }
    const kept = fields.filter((_field, index) => !removed.has(index));
    const output = new Uint8Array(kept.reduce((sum, field) => sum + field.end - field.start, 0));
    let offset = 0;
    for (const field of kept) {
        output.set(section.subarray(field.start, field.end), offset);
        offset += field.end - field.start;
    }
    return { output, removedFields: removed.size };
}

export interface HeaderStripperOptions {
    maxHeaderBytes?: number;
    maxMessageBytes?: number;
}

/**
 * Incremental stripper: feed arbitrary chunks, collect output chunks. Nothing is
 * emitted until the whole header section has been received and validated; after
 * that, input chunks pass through unchanged. push() and end() throw
 * MalformedMessage, HeaderSectionTooLarge or MessageTooLarge.
 *
 * Header lines are validated in order as each one completes, so a malformed
 * message is refused without reading further. A header line that ends beyond
 * the cap makes the header section too large.
 */
export class HeaderStripper {
    private readonly maxHeaderBytes: number;
    private readonly maxMessageBytes: number;
    private buffer = new Uint8Array(0);
    private length = 0;
    private fields: Field[] = [];
    /** Start of the first line not yet validated. */
    private lineStart = 0;
    /** Where the search for that line's LF resumes. */
    private searchFrom = 0;
    private finished = false;
    /** True until the header section has been validated and emitted. */
    inHeaderSection = true;
    /** Input bytes consumed so far. */
    inputBytes = 0;
    /** Output bytes produced so far. */
    outputBytes = 0;
    /** Header fields removed. */
    removedFields = 0;

    constructor(options: HeaderStripperOptions = {}) {
        this.maxHeaderBytes = options.maxHeaderBytes ?? MAX_HEADER_SECTION_BYTES;
        this.maxMessageBytes = options.maxMessageBytes ?? MAX_MESSAGE_BYTES;
    }

    /** Processes one input chunk and returns zero or more output chunks. */
    push(chunk: Uint8Array): Uint8Array[] {
        if (this.finished) {
            throw new Error('HeaderStripper already ended');
        }
        this.inputBytes += chunk.length;
        if (this.inputBytes > this.maxMessageBytes) {
            throw new MessageTooLarge();
        }
        if (!this.inHeaderSection) {
            return this.emit(chunk.length > 0 ? [chunk] : []);
        }
        // Copy: the caller may reuse its buffer.
        this.append(chunk);
        const separator = this.scanLines();
        if (separator === -1) {
            // The incomplete line ends beyond the cap, unless it is a lone CR that may
            // still start the separator (validated lines all end within the cap).
            const loneCr = this.length - this.lineStart === 1 && this.buffer[this.lineStart] === CR;
            if (!loneCr && this.length > this.maxHeaderBytes) {
                throw new HeaderSectionTooLarge();
            }
            return [];
        }
        return this.complete(separator);
    }

    /** Ends the input; a message with no blank line is all header section. */
    end(): Uint8Array[] {
        if (this.finished) {
            return [];
        }
        this.finished = true;
        if (!this.inHeaderSection) {
            return [];
        }
        if (this.length === 0) {
            throw new MalformedMessage('empty');
        }
        if (this.lineStart < this.length) {
            // A final header line without a line terminator.
            if (this.length > this.maxHeaderBytes) {
                throw new HeaderSectionTooLarge();
            }
            acceptLine(this.buffer, this.lineStart, this.length, this.fields);
        }
        return this.complete(this.length);
    }

    private append(chunk: Uint8Array): void {
        if (this.length + chunk.length > this.buffer.length) {
            const grown = new Uint8Array(Math.max(this.length + chunk.length, this.buffer.length * 2, 4096));
            grown.set(this.buffer.subarray(0, this.length));
            this.buffer = grown;
        }
        this.buffer.set(chunk, this.length);
        this.length += chunk.length;
    }

    /**
     * Validates every newly completed header line. Returns the index where the blank
     * separator line starts, or -1 when more input is needed.
     */
    private scanLines(): number {
        const buffer = this.buffer;
        for (;;) {
            const start = this.lineStart;
            if (start >= this.length) {
                return -1;
            }
            const first = buffer[start];
            if (first === LF) {
                return start;
            }
            if (first === CR) {
                if (start + 1 >= this.length) {
                    return -1;
                }
                if (buffer[start + 1] === LF) {
                    return start;
                }
            }
            const lf = buffer.subarray(0, this.length).indexOf(LF, Math.max(this.searchFrom, start));
            if (lf === -1) {
                this.searchFrom = this.length;
                return -1;
            }
            if (lf + 1 > this.maxHeaderBytes) {
                throw new HeaderSectionTooLarge();
            }
            acceptLine(buffer, start, lf + 1, this.fields);
            this.lineStart = lf + 1;
            this.searchFrom = lf + 1;
        }
    }

    /** Emits the validated header section buffer[0, end), normalized, and whatever follows it. */
    private complete(end: number): Uint8Array[] {
        const { output, removedFields } = removeFields(this.buffer.subarray(0, end), this.fields);
        this.removedFields = removedFields;
        this.inHeaderSection = false;
        const rest = this.buffer.subarray(end, this.length);
        this.buffer = new Uint8Array(0);
        this.length = 0;
        this.fields = [];
        return this.emit([output, rest].filter(part => part.length > 0));
    }

    private emit(chunks: Uint8Array[]): Uint8Array[] {
        for (const chunk of chunks) {
            this.outputBytes += chunk.length;
        }
        return chunks;
    }
}

/** Convenience for whole buffers (tests and small inputs); throws like HeaderStripper. */
export function stripHeaders(input: Uint8Array, options?: HeaderStripperOptions): Uint8Array {
    const stripper = new HeaderStripper(options);
    const parts = [...stripper.push(input), ...stripper.end()];
    const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

export type StripFailure = 'message_too_large' | 'header_too_large' | 'malformed_message' | 'source_error';

export interface StrippedBody {
    readonly stream: ReadableStream<Uint8Array>;
    readonly stripper: HeaderStripper;
    /** Why the stream errored, when the failure originated here rather than downstream. */
    failure(): StripFailure | undefined;
    /** Stops reading the source (idempotent, never throws). */
    release(): void;
}

export type OpenedBody =
    | { readonly ok: true; readonly body: StrippedBody }
    | { readonly ok: false; readonly failure: StripFailure; readonly malformed?: MalformedReason };

export interface OpenOptions extends HeaderStripperOptions {
    /** Aborts reading the source (the request deadline). */
    signal?: AbortSignal;
}

function classify(error: unknown): StripFailure {
    if (error instanceof MalformedMessage) {
        return 'malformed_message';
    }
    if (error instanceof MessageTooLarge) {
        return 'message_too_large';
    }
    return error instanceof HeaderSectionTooLarge ? 'header_too_large' : 'source_error';
}

/**
 * Reads and validates the whole header section of `source`, then returns a
 * pull-driven stream of the normalized message: the normalized header section,
 * then the rest of the source unchanged. On failure the source is cancelled and
 * nothing is returned to send. After the header section, nothing is read from
 * the source until the consumer pulls, so the body is never buffered.
 */
export async function openStrippedBody(source: ReadableStream<Uint8Array>, options: OpenOptions = {}): Promise<OpenedBody> {
    const stripper = new HeaderStripper(options);
    const reader = source.getReader();
    let released = false;
    const release = () => {
        if (!released) {
            released = true;
            reader.cancel().catch(() => undefined);
        }
    };
    const { signal } = options;
    let aborted: Promise<never> | undefined;
    if (signal) {
        aborted = new Promise<never>((_resolve, reject) => {
            if (signal.aborted) {
                reject(new Error('aborted'));
            }
            signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
        });
        aborted.catch(() => undefined);
    }
    const read = async (): Promise<Uint8Array | undefined> => {
        if (signal?.aborted) {
            throw new Error('aborted');
        }
        const result = await (aborted ? Promise.race([reader.read(), aborted]) : reader.read());
        if (result.done) {
            return undefined;
        }
        const value: unknown = result.value;
        if (!(value instanceof Uint8Array)) {
            throw new TypeError('Message source produced a non-byte chunk');
        }
        return value;
    };

    let head: Uint8Array[] = [];
    let sourceDone = false;
    try {
        while (stripper.inHeaderSection) {
            const value = await read();
            if (value === undefined) {
                head.push(...stripper.end());
                sourceDone = true;
                break;
            }
            head.push(...stripper.push(value));
        }
    } catch (error) {
        release();
        const failure = classify(error);
        return failure === 'malformed_message' && error instanceof MalformedMessage ? { ok: false, failure, malformed: error.reason } : { ok: false, failure };
    }

    let failure: StripFailure | undefined;
    const stream = new ReadableStream<Uint8Array>({
        async pull(controller) {
            if (head.length > 0) {
                for (const chunk of head) {
                    controller.enqueue(chunk);
                }
                head = [];
                if (sourceDone) {
                    controller.close();
                }
                return;
            }
            if (sourceDone) {
                controller.close();
                return;
            }
            for (;;) {
                let value: Uint8Array | undefined;
                try {
                    value = await read();
                } catch (error) {
                    failure = 'source_error';
                    release();
                    throw error;
                }
                if (value === undefined) {
                    controller.close();
                    return;
                }
                let out: Uint8Array[];
                try {
                    out = stripper.push(value);
                } catch (error) {
                    failure = classify(error);
                    release();
                    throw error;
                }
                if (out.length > 0) {
                    for (const chunk of out) {
                        controller.enqueue(chunk);
                    }
                    return;
                }
            }
        },
        cancel() {
            release();
        },
    }, { highWaterMark: 0 });
    return { ok: true, body: { stream, stripper, failure: () => failure, release } };
}
