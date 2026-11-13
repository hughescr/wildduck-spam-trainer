import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { SSMClient } from '@aws-sdk/client-ssm';
import { createApp, type FunctionUrlEvent, type HttpResult, type LambdaContextLike } from './app';
import { DEFAULT_API_BASE_URL, DEFAULT_LEARN_BASE_URL, loadConfig, type Config } from './config';
import { createLogger } from './log';
import { OriginVerifier, TrainingKeyStore } from './secrets';

export { createApp } from './app';
export { OriginVerifier, TrainingKeyStore } from './secrets';
export { createLogger } from './log';

const log = createLogger();

function configuration(): Config {
    try {
        return loadConfig();
    } catch {
        // Invalid names or base URLs: fail closed (503) instead of crashing every cold start.
        log.error('invalid_configuration');
        return { apiBaseUrl: DEFAULT_API_BASE_URL, learnBaseUrl: DEFAULT_LEARN_BASE_URL };
    }
}

const config = configuration();
// SDK clients are created on first use only, so unauthenticated traffic never constructs one.
let ssm: SSMClient | undefined;
let secrets: SecretsManagerClient | undefined;

const app = createApp({
    apiBaseUrl: config.apiBaseUrl,
    learnBaseUrl: config.learnBaseUrl,
    origin: new OriginVerifier({ client: () => (secrets ??= new SecretsManagerClient({})), secretId: config.originVerifySecretId, log }),
    trainingKey: new TrainingKeyStore({ client: () => (ssm ??= new SSMClient({})), parameterName: config.trainingProxyKeyParameter, log }),
    fetch: (input, init) => fetch(input, init),
    log,
});

export const handler = (event: FunctionUrlEvent, context?: LambdaContextLike): Promise<HttpResult> => app(event, context);
