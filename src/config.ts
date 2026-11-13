/** Production resource names (not values). Deployment refuses any other value (scripts/deploy.sh, CI). */
export const TRAINING_PROXY_KEY_PARAMETER = '/wildduck-spam-trainer/prod/training-proxy-key';
/** Bootstrap-created secret. Its name deliberately avoids a trailing "-xxxxxx" (ARN-suffix lookalike). */
export const ORIGIN_VERIFY_SECRET_ID = 'wildduck-spam-trainer/prod/origin-verify-key';
/** CloudFront origin custom header carrying the origin secret. */
export const ORIGIN_VERIFY_HEADER = 'x-origin-verify';
/** Every proxy request carries the training key in this header. */
export const TRAINING_KEY_HEADER = 'X-Mail-Training-Key';

/** Fixed upstream bases. Overridable only through the environment, for tests and local work. */
export const DEFAULT_API_BASE_URL = 'https://wildduck-api.rungie.com/_mail-training/v1';
export const DEFAULT_LEARN_BASE_URL = 'https://spam.rungie.com/_mail-training/v1';

export interface Config {
    readonly trainingProxyKeyParameter?: string;
    readonly originVerifySecretId?: string;
    readonly apiBaseUrl: string;
    readonly learnBaseUrl: string;
}

const PARAMETER_NAME = /^\/(?!aws(?:\/|$)|ssm(?:\/|$))[A-Za-z0-9_./-]{1,1000}$/;
const SECRET_ID = /^[A-Za-z0-9/_+=.@-]{1,512}$/;
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(['localhost', '127.0.0.1', '[::1]']);

export function isValidParameterName(name: string): boolean {
    return PARAMETER_NAME.test(name) && !name.includes('//');
}

/** Validates an upstream base URL: HTTPS, or plain HTTP to a loopback host for local work. */
export function normalizeBaseUrl(raw: string, key: string): string {
    let url: URL;
    try {
        url = new URL(raw);
    } catch {
        throw new Error(`${key} must be an absolute URL`);
    }
    const loopback = url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname);
    if ((url.protocol !== 'https:' && !loopback) || url.username || url.password || url.search || url.hash) {
        throw new Error(`${key} must be an HTTPS base URL without credentials, query or fragment`);
    }
    return url.href.replace(/\/+$/, '');
}

/** Reads names and base URLs from the environment. Unset names leave the service fail-closed (503). */
export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
    const parameter = env['TRAINING_PROXY_KEY_PARAMETER'];
    if (parameter !== undefined && parameter !== '' && !isValidParameterName(parameter)) {
        throw new Error('TRAINING_PROXY_KEY_PARAMETER must be an SSM parameter name');
    }
    const secretId = env['ORIGIN_VERIFY_SECRET_ID'];
    if (secretId !== undefined && secretId !== '' && !SECRET_ID.test(secretId)) {
        throw new Error('ORIGIN_VERIFY_SECRET_ID must be a Secrets Manager secret name or ARN');
    }
    const apiOverride = env['TRAINING_API_BASE_URL'];
    const learnOverride = env['TRAINING_LEARN_BASE_URL'];
    return {
        ...(parameter ? { trainingProxyKeyParameter: parameter } : {}),
        ...(secretId ? { originVerifySecretId: secretId } : {}),
        apiBaseUrl: apiOverride ? normalizeBaseUrl(apiOverride, 'TRAINING_API_BASE_URL') : DEFAULT_API_BASE_URL,
        learnBaseUrl: learnOverride ? normalizeBaseUrl(learnOverride, 'TRAINING_LEARN_BASE_URL') : DEFAULT_LEARN_BASE_URL,
    };
}
