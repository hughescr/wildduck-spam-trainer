/**
 * Structured, privacy-allowlisted operational logging.
 *
 * Every line is one JSON object written to stdout. Only the fields declared in
 * {@link LogFields} can ever be emitted, and each value is re-validated against a
 * narrow shape before it is written. Secrets, keys, header values, query strings,
 * URLs, message metadata (subject, addresses, Message-ID), header or body content,
 * upstream response bodies and thrown error objects have no field and therefore
 * cannot be logged, even by mistake.
 */
export type LogLevel = 'info' | 'warn' | 'error';

export type UpstreamName = 'mailbox' | 'message' | 'eml' | 'learn' | 'ssm' | 'secretsmanager';

export interface LogFields {
    requestId?: string;
    deliveryId?: string;
    ev?: string;
    user?: string;
    mailbox?: string;
    uid?: number;
    route?: string;
    method?: string;
    status?: number;
    outcome?: string;
    reason?: string;
    upstream?: UpstreamName;
    upstreamStatus?: number;
    durationMs?: number;
    bytes?: number;
    removedHeaders?: number;
}

export interface Logger {
    info(event: string, fields?: LogFields): void;
    warn(event: string, fields?: LogFields): void;
    error(event: string, fields?: LogFields): void;
}

export type LogSink = (line: string) => void;

const TOKEN = /^[a-z][a-z0-9_]{0,63}$/;
const OBJECT_ID = /^[0-9a-f]{24}$/;
const UPSTREAMS: ReadonlySet<string> = new Set(['mailbox', 'message', 'eml', 'learn', 'ssm', 'secretsmanager']);
const ROUTES: ReadonlySet<string> = new Set(['/healthz', '/readyz', '/hooks/wildduck', 'other']);
const METHODS: ReadonlySet<string> = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'other']);

const nonNegativeInteger = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const httpStatus = (value: unknown): value is number => typeof value === 'number' && Number.isInteger(value) && value >= 100 && value <= 599;

const validators: { readonly [K in keyof LogFields]-?: (value: unknown) => boolean } = {
    requestId: value => typeof value === 'string' && /^[A-Za-z0-9-]{1,128}$/.test(value),
    deliveryId: value => typeof value === 'string' && /^[0-9a-f]{24}:[0-9]{1,10}$/.test(value),
    ev: value => typeof value === 'string' && /^[a-z]{1,32}(?:\.[a-z]{1,32}){0,3}$/.test(value),
    user: value => typeof value === 'string' && OBJECT_ID.test(value),
    mailbox: value => typeof value === 'string' && OBJECT_ID.test(value),
    uid: nonNegativeInteger,
    route: value => typeof value === 'string' && ROUTES.has(value),
    method: value => typeof value === 'string' && METHODS.has(value),
    status: httpStatus,
    outcome: value => typeof value === 'string' && TOKEN.test(value),
    reason: value => typeof value === 'string' && TOKEN.test(value),
    upstream: value => typeof value === 'string' && UPSTREAMS.has(value),
    upstreamStatus: httpStatus,
    durationMs: nonNegativeInteger,
    bytes: nonNegativeInteger,
    removedHeaders: nonNegativeInteger,
};
const FIELD_NAMES = Object.keys(validators) as (keyof LogFields)[];

const stdoutSink: LogSink = line => {
    process.stdout.write(`${line}\n`);
};

/** Builds a log record containing only allowlisted, shape-validated fields. */
export function buildRecord(level: LogLevel, event: string, fields: LogFields = {}, time = Date.now()): Record<string, unknown> {
    const record: Record<string, unknown> = { level, event: TOKEN.test(event) ? event : 'invalid_event', time: new Date(time).toISOString() };
    for (const name of FIELD_NAMES) {
        const value = fields[name];
        if (value !== undefined && validators[name](value)) {
            record[name] = value;
        }
    }
    return record;
}

export function createLogger(sink: LogSink = stdoutSink, now: () => number = Date.now): Logger {
    const write = (level: LogLevel, event: string, fields?: LogFields) => {
        try {
            sink(JSON.stringify(buildRecord(level, event, fields, now())));
        } catch {
            // Diagnostics must never change request handling.
        }
    };
    return {
        info: (event, fields) => write('info', event, fields),
        warn: (event, fields) => write('warn', event, fields),
        error: (event, fields) => write('error', event, fields),
    };
}

/** Binds request-scoped fields so every line of one request carries them. */
export function withFields(logger: Logger, base: LogFields): Logger {
    return {
        info: (event, fields) => logger.info(event, { ...base, ...fields }),
        warn: (event, fields) => logger.warn(event, { ...base, ...fields }),
        error: (event, fields) => logger.error(event, { ...base, ...fields }),
    };
}
