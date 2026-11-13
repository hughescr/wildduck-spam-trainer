/**
 * Byte-level RFC 5322 header normalization for Bayes training.
 *
 * Removes classification header fields (and all of their folded continuation
 * lines) that a previous scan or WildDuck added, so the classifier learns from
 * the message rather than from its own verdict. Everything else is preserved
 * byte-for-byte: other header fields and their order, original line endings
 * (CRLF, bare LF or mixed), the blank separator line and the body. Bytes are
 * never decoded or re-encoded.
 *
 * Only the header section is inspected; the body passes through untouched. Only
 * the current (incomplete) header line is buffered, and the header section as a
 * whole is capped.
 */

export const MAX_HEADER_SECTION_BYTES = 1024 * 1024;
/** The Nginx training proxy accepts at most 25 MiB. */
export const MAX_MESSAGE_BYTES = 25 * 1024 * 1024;

export class HeaderSectionTooLarge extends Error {
    override readonly name = 'HeaderSectionTooLarge';
}

export class MessageTooLarge extends Error {
    override readonly name = 'MessageTooLarge';
}

const LF = 0x0a;
const CR = 0x0d;
const SP = 0x20;
const HTAB = 0x09;
const COLON = 0x3a;

const EXACT_NAMES: ReadonlySet<string> = new Set(['wd-mail-classification', 'wd-mail-classification-source', 'wd-mail-classification-info']);
const PREFIXES = ['x-rspamd-', 'x-spamd-', 'x-spam-'] as const;
/** Every exact name is shorter and every prefix decision is made within this many bytes. */
const INSPECTED_NAME_BYTES = 64;

/** True when a lower-cased header field name must be removed. */
export function isStrippedHeaderName(lowerName: string): boolean {
    return EXACT_NAMES.has(lowerName) || PREFIXES.some(prefix => lowerName.startsWith(prefix));
}

function concat(parts: readonly Uint8Array[], length: number): Uint8Array {
    if (parts.length === 1 && parts[0]) {
        return parts[0];
    }
    const out = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

/** True when the header field on this (complete, unfolded-start) line must be removed. */
function isStrippedLine(line: Uint8Array): boolean {
    const colon = line.indexOf(COLON);
    if (colon <= 0) {
        return false;
    }
    let end = colon;
    // Obsolete syntax permits whitespace between the field name and the colon.
    while (end > 0 && (line[end - 1] === SP || line[end - 1] === HTAB)) {
        end--;
    }
    // Lower-case ASCII only; other bytes are copied as-is and can never match.
    let name = '';
    for (let index = 0; index < Math.min(end, INSPECTED_NAME_BYTES); index++) {
        const byte = line[index] ?? 0;
        name += String.fromCharCode(byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte);
    }
    return end > INSPECTED_NAME_BYTES ? PREFIXES.some(prefix => name.startsWith(prefix)) : isStrippedHeaderName(name);
}

const isBlankLine = (line: Uint8Array) => (line.length === 1 && line[0] === LF) || (line.length === 2 && line[0] === CR && line[1] === LF);

export interface HeaderStripperOptions {
    maxHeaderBytes?: number;
    maxMessageBytes?: number;
}

/** Incremental stripper: feed arbitrary chunks, collect output chunks. */
export class HeaderStripper {
    private readonly maxHeaderBytes: number;
    private readonly maxMessageBytes: number;
    private inHeaders = true;
    private dropping = false;
    private pending: Uint8Array[] = [];
    private pendingLength = 0;
    private headerBytes = 0;
    private finished = false;
    /** Input bytes consumed so far. */
    inputBytes = 0;
    /** Output bytes produced so far. */
    outputBytes = 0;
    /** Header fields removed so far. */
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
        if (!this.inHeaders) {
            return this.emit(chunk.length > 0 ? [chunk] : []);
        }
        const kept: Uint8Array[] = [];
        let keptLength = 0;
        let position = 0;
        while (position < chunk.length) {
            const lf = chunk.indexOf(LF, position);
            const end = lf === -1 ? chunk.length : lf + 1;
            const piece = chunk.subarray(position, end);
            this.headerBytes += piece.length;
            if (this.headerBytes > this.maxHeaderBytes) {
                throw new HeaderSectionTooLarge();
            }
            position = end;
            if (lf === -1) {
                // Copy: the caller may reuse its buffer before the line completes.
                this.pending.push(piece.slice());
                this.pendingLength += piece.length;
                break;
            }
            const line = this.pendingLength > 0 ? concat([...this.pending, piece], this.pendingLength + piece.length) : piece;
            this.pending = [];
            this.pendingLength = 0;
            if (isBlankLine(line)) {
                kept.push(line);
                keptLength += line.length;
                this.inHeaders = false;
                break;
            }
            if (this.keep(line)) {
                kept.push(line);
                keptLength += line.length;
            }
        }
        const out: Uint8Array[] = [];
        if (keptLength > 0) {
            out.push(concat(kept, keptLength));
        }
        if (!this.inHeaders && position < chunk.length) {
            out.push(chunk.subarray(position));
        }
        return this.emit(out);
    }

    /** Flushes a final unterminated header line (a message with no blank line). */
    end(): Uint8Array[] {
        if (this.finished) {
            return [];
        }
        this.finished = true;
        if (!this.inHeaders || this.pendingLength === 0) {
            return [];
        }
        const line = concat(this.pending, this.pendingLength);
        this.pending = [];
        this.pendingLength = 0;
        return this.emit(this.keep(line) ? [line] : []);
    }

    private emit(chunks: Uint8Array[]): Uint8Array[] {
        for (const chunk of chunks) {
            this.outputBytes += chunk.length;
        }
        return chunks;
    }

    private keep(line: Uint8Array): boolean {
        const first = line[0];
        if (first === SP || first === HTAB) {
            // Folded continuation: follows the decision for its field.
            return !this.dropping;
        }
        this.dropping = isStrippedLine(line);
        if (this.dropping) {
            this.removedFields++;
        }
        return !this.dropping;
    }
}

/** Convenience for whole buffers (tests and small inputs). */
export function stripHeaders(input: Uint8Array, options?: HeaderStripperOptions): Uint8Array {
    const stripper = new HeaderStripper(options);
    const parts = [...stripper.push(input), ...stripper.end()];
    return concat(parts, parts.reduce((sum, part) => sum + part.length, 0));
}

export type StripFailure = 'message_too_large' | 'header_too_large' | 'source_error';

export interface StrippedBody {
    readonly stream: ReadableStream<Uint8Array>;
    readonly stripper: HeaderStripper;
    /** Why the stream errored, when the failure originated here rather than downstream. */
    failure(): StripFailure | undefined;
    /** Stops reading the source (idempotent, never throws). */
    release(): void;
}

/**
 * Wraps a source byte stream in a pull-driven header-stripping stream.
 * Nothing is read from the source until the consumer pulls, so a slow or
 * failed consumer never causes the whole message to be buffered.
 */
export function createStrippedBody(source: ReadableStream<Uint8Array>, options?: HeaderStripperOptions): StrippedBody {
    const stripper = new HeaderStripper(options);
    const reader = source.getReader();
    let failure: StripFailure | undefined;
    let released = false;
    const release = () => {
        if (!released) {
            released = true;
            reader.cancel().catch(() => undefined);
        }
    };
    const stream = new ReadableStream<Uint8Array>({
        async pull(controller) {
            for (;;) {
                let result: Awaited<ReturnType<typeof reader.read>>;
                try {
                    result = await reader.read();
                } catch (error) {
                    failure = 'source_error';
                    throw error;
                }
                if (result.done) {
                    for (const chunk of stripper.end()) {
                        controller.enqueue(chunk);
                    }
                    controller.close();
                    return;
                }
                const value: unknown = result.value;
                if (!(value instanceof Uint8Array)) {
                    failure = 'source_error';
                    release();
                    throw new TypeError('Message source produced a non-byte chunk');
                }
                let out: Uint8Array[];
                try {
                    out = stripper.push(value);
                } catch (error) {
                    failure = error instanceof MessageTooLarge ? 'message_too_large' : 'header_too_large';
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
    return { stream, stripper, failure: () => failure, release };
}
