import { describe, expect, test } from 'bun:test';
import assert from 'node:assert/strict';
import { BlockList, isIP } from 'node:net';

const deploySource = await Bun.file('scripts/deploy.sh').text();
const verifySource = await Bun.file('scripts/verify-deployment.mjs').text();
const bootstrap = Bun.YAML.parse(await Bun.file('infra/bootstrap.yml').text()) as { Parameters: Record<string, { AllowedPattern: string }> };
const template = Bun.YAML.parse(await Bun.file('serverless.yml').text()) as { resources: { Resources: { ViewerRequestFunction: { Properties: { FunctionCode: string } } } } };
const environment = {
    AWS_DEPLOYMENT_BUCKET_NAME: 'test-bucket', AWS_EXECUTION_ROLE_ARN: 'test-role', SERVERLESS_ACCESS_KEY: 'test-key',
    TRAINING_PROXY_KEY_PARAMETER: '/wildduck-spam-trainer/prod/training-proxy-key',
    ORIGIN_VERIFY_SECRET_ID: 'wildduck-spam-trainer/prod/origin-verify-key',
};

async function runDeploy(allowlist: unknown, serial: unknown = '1', awsStatus = 0) {
    const source = deploySource.replace('[[ -f dist/function.zip ]]', 'true').replace('node_modules/.bin/serverless deploy --stage prod', 'printf \'DEPLOYED:%s:%s\\n\' "$ALLOWED_SOURCE_IPS" "$ORIGIN_SECRET_ROTATION_SERIAL"');
    const mockAws = `aws() {
        case "$*" in
            *allowed-source-ips*) printf '%s' "$MOCK_ALLOWED" ;;
            *origin-secret-rotation-serial*) printf '%s' "$MOCK_SERIAL" ;;
            *) return 99 ;;
        esac
        printf '%s' 'PRIVATE_AWS_ERROR' >&2
        return "$MOCK_AWS_STATUS"
    }`;
    const process = Bun.spawn(['bash', '-c', `${mockAws}\n${source}`], {
        env: { ...environment, PATH: Bun.env['PATH'] ?? '', MOCK_ALLOWED: JSON.stringify(allowlist), MOCK_SERIAL: JSON.stringify(serial), MOCK_AWS_STATUS: String(awsStatus), ALLOWED_SOURCE_IPS: "unvalidated';code", ORIGIN_SECRET_ROTATION_SERIAL: 'unvalidated' },
        stdout: 'pipe', stderr: 'pipe',
    });
    const [status, stdout, stderr] = await Promise.all([process.exited, new Response(process.stdout).text(), new Response(process.stderr).text()]);
    return { status, stdout, stderr };
}

describe('deploy-time SSM validation with a mocked AWS CLI', () => {
    test('uses exactly the bootstrap patterns and deploys the validated snapshot', async () => {
        for (const name of ['AllowedSourceIps', 'OriginSecretRotationSerial']) {
            expect(deploySource).toContain(`'${bootstrap.Parameters[name]?.AllowedPattern}'`);
        }
        expect(deploySource.indexOf('aws ssm get-parameter')).toBeLessThan(deploySource.indexOf('node_modules/.bin/serverless deploy'));
        expect(deploySource).toContain('export ALLOWED_SOURCE_IPS ORIGIN_SECRET_ROTATION_SERIAL');
        expect(await runDeploy('192.0.2.1,2001:db8::1', '123456789')).toEqual({ status: 0, stdout: 'DEPLOYED:192.0.2.1,2001:db8::1:123456789\n', stderr: '' });
        expect((await runDeploy(Array.from({ length: 50 }, () => '::1').join(','))).status).toBe(0);
    });

    test('rejects injection, malformed values, trailing newlines, excess entries and non-strings without disclosure', async () => {
        for (const value of ["1.2.3.4';throw 1;//", '1.2.3.4\n', '1.2.3.4\r', '1.2.3.4, 5.6.7.8', '1.2.3.4/32', '', 'a'.repeat(46), Array.from({ length: 51 }, () => '::1').join(','), null, 123]) {
            const result = await runDeploy(value);
            expect(result).toEqual({ status: 1, stdout: '', stderr: 'Invalid or unreadable source-IP allowlist\n' });
        }
    });

    test('rejects invalid rotation serials and AWS failures without disclosure', async () => {
        for (const serial of ['', '1234567890', '1\n', '-1', '1;code', null, 1]) {
            expect(await runDeploy('192.0.2.1', serial)).toEqual({ status: 1, stdout: '', stderr: 'Invalid or unreadable origin rotation serial\n' });
        }
        expect(await runDeploy('192.0.2.1', '1', 1)).toEqual({ status: 1, stdout: '', stderr: 'Invalid or unreadable source-IP allowlist\n' });
    });
});

type ViewerEvent = { viewer: { ip: string }; request: { method: string; uri: string } };
type ViewerResult = { statusCode?: number; method?: string; uri?: string };
interface VerifyOptions {
    allowlist?: string;
    healthBody?: string;
    networkError?: boolean;
    awsError?: boolean;
    testError?: boolean;
    malformedOutput?: boolean;
    rejectAllowed?: boolean;
    acceptDenied?: boolean;
}
const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor as new (...args: string[]) => (...args: unknown[]) => Promise<void>;

async function runVerify(options: VerifyOptions = {}) {
    const allowlist = options.allowlist ?? '192.0.2.1,2001:db8::1,::ffff:192.0.2.2,010.000.000.001';
    const functionCode = template.resources.Resources.ViewerRequestFunction.Properties.FunctionCode.replace(/\$\{[^}]+\}/g, () => allowlist);
    const handler = new Function(`${functionCode}\nreturn handler;`)() as (event: ViewerEvent) => ViewerResult;
    const tested: string[] = [];
    const calls: string[][] = [];
    const logs: string[] = [];
    let healthAttempts = 0;
    let fetchCount = 0;
    const aws = (command: string, args: string[], config: unknown) => {
        expect(command).toBe('aws');
        expect(config).toMatchObject({ stdio: ['pipe', 'pipe', 'pipe'] });
        calls.push(args);
        if (options.awsError) { throw new Error('PRIVATE_AWS_ERROR'); }
        const operation = args[1];
        let result: unknown;
        switch (operation) {
            case 'get-function-configuration':
                result = { Runtime: 'nodejs26.x', Architectures: ['arm64'], MemorySize: 1024, Timeout: 25, Description: 'wildduck-spam-trainer 0.0.0', Environment: { Variables: { TRAINING_PROXY_KEY_PARAMETER: environment.TRAINING_PROXY_KEY_PARAMETER, ORIGIN_VERIFY_SECRET_ID: environment.ORIGIN_VERIFY_SECRET_ID } } };
                break;
            case 'get-function-concurrency': result = { ReservedConcurrentExecutions: 5 }; break;
            case 'get-function-url-config': result = { AuthType: 'NONE', FunctionUrl: 'https://direct.example/' }; break;
            case 'describe-stacks':
                result = { Stacks: [{ Outputs: Object.entries({ PublicWebhookUrl: 'https://public.example/hooks/wildduck', DistributionId: 'distribution-id', DistributionDomainName: 'distribution.example', WebhookLambdaFunctionUrl: 'https://direct.example/' }).map(([OutputKey, OutputValue]) => ({ OutputKey, OutputValue })) }] };
                break;
            case 'get-parameter':
                expect(args).toContain('/wildduck-spam-trainer/prod/allowed-source-ips');
                result = { Parameter: { Value: allowlist } };
                break;
            case 'describe-function':
                expect(args).toContain('wildduck-spam-trainer-prod-viewer-request');
                expect(args[args.indexOf('--stage') + 1]).toBe('LIVE');
                result = { ETag: 'live-version' };
                break;
            case 'test-function': {
                expect(args[args.indexOf('--stage') + 1]).toBe('LIVE');
                expect(args[args.indexOf('--if-match') + 1]).toBe('live-version');
                expect(args[args.indexOf('--cli-binary-format') + 1]).toBe('base64');
                const event = JSON.parse(Buffer.from(args[args.indexOf('--event-object') + 1] ?? '', 'base64').toString()) as ViewerEvent;
                expect(event.request).toMatchObject({ method: 'POST', uri: '/hooks/wildduck' });
                tested.push(event.viewer.ip);
                let output = handler(event);
                if (options.rejectAllowed) { output = { statusCode: 403 }; }
                if (options.acceptDenied) { output = event.request; }
                result = { TestResult: { FunctionErrorMessage: options.testError ? 'PRIVATE_FUNCTION_ERROR' : '', FunctionExecutionLogs: ['PRIVATE_FUNCTION_LOG'], FunctionOutput: options.malformedOutput ? 'PRIVATE_INVALID_OUTPUT' : JSON.stringify(output.statusCode === undefined ? { request: output } : { response: output }) } };
                break;
            }
            default: throw new Error(`Unexpected mock AWS operation ${operation}`);
        }
        return JSON.stringify(result);
    };
    const fetch = (url: URL | string) => {
        fetchCount += 1;
        const parsed = new URL(url);
        if (parsed.hostname === 'direct.example') { return Promise.resolve(new Response('{"error":"forbidden"}', { status: 403 })); }
        if (parsed.pathname === '/healthz') {
            healthAttempts += 1;
            if (healthAttempts === 1 && options.networkError) { throw new Error('PRIVATE_NETWORK_ERROR'); }
            return Promise.resolve(new Response(healthAttempts === 1 && options.healthBody !== undefined ? options.healthBody : '{"service":"wildduck-spam-trainer","version":"0.0.0","status":"ok"}'));
        }
        return Promise.resolve(new Response('', { status: parsed.pathname === '/readyz' ? 503 : 403 }));
    };
    const source = verifySource.replace(/^import .*;\n/gm, '').replaceAll('import.meta.url', '"file:///mock/scripts/verify-deployment.mjs"');
    const run = new AsyncFunction('execFileSync', 'randomBytes', 'readFile', 'sleep', 'assert', 'BlockList', 'isIP', 'fetch', 'process', source);
    let error: string | undefined;
    try {
        await run(aws, () => Buffer.alloc(48), async () => '{"version":"0.0.0"}', async () => {}, assert, BlockList, isIP, fetch, { env: environment, stdout: { write: (message: string) => logs.push(message) } });
    } catch (failure) {
        error = failure instanceof Error ? failure.message : 'unexpected failure';
    }
    return { error, tested, calls, logs: logs.join(''), healthAttempts, fetchCount };
}

describe('post-deploy verification with mocked AWS and HTTP', () => {
    test('tests every SSM address and a semantically non-listed address using LIVE TestFunction without extra HTTP requests', async () => {
        const result = await runVerify();
        expect(result.error).toBeUndefined();
        expect(result.tested).toEqual(['192.0.2.1', '2001:db8::1', '::ffff:192.0.2.2', '010.000.000.001', '192.0.2.3']);
        expect(result.fetchCount).toBe(6);
        expect(result.logs).toContain('all allowlisted webhook POSTs accepted; non-allowlisted POST rejected with HTTP 403');
        expect(result.logs).not.toContain('PRIVATE_');
        expect(result.logs).not.toContain('192.0.2.');
    });

    test('finds a rejected probe even when the first 50 candidates are allowlisted', async () => {
        const result = await runVerify({ allowlist: Array.from({ length: 50 }, (_, index) => `192.0.2.${index + 1}`).join(',') });
        expect(result.error).toBeUndefined();
        expect(result.tested).toHaveLength(51);
        expect(result.tested.at(-1)).toBe('192.0.2.51');
    });

    test('fails on rejected allowlisted requests, accepted outsiders, function errors and malformed output without leaking it', async () => {
        for (const options of [{ rejectAllowed: true }, { acceptDenied: true }, { testError: true }, { malformedOutput: true }, { awsError: true }, { allowlist: 'not-an-ip' }]) {
            const result = await runVerify(options);
            expect(result.error).toBeDefined();
            expect(`${result.error}${result.logs}`).not.toContain('PRIVATE_');
            expect(result.fetchCount).toBe(0);
        }
    });

    test('JSON null, arrays, primitives and invalid JSON are failed health checks, not network errors', async () => {
        for (const healthBody of ['null', '[]', '42', '"PRIVATE_BODY"', 'PRIVATE_INVALID_JSON']) {
            const result = await runVerify({ healthBody });
            expect(result.error).toBeUndefined();
            expect(result.healthAttempts).toBe(2);
            expect(result.logs).toContain('HTTP 200 with an unexpected body');
            expect(result.logs).not.toContain('network error');
            expect(result.logs).not.toContain('PRIVATE_');
        }
    });

    test('network errors are fixed messages without exception details', async () => {
        const result = await runVerify({ networkError: true });
        expect(result.error).toBeUndefined();
        expect(result.logs).toContain('network error');
        expect(result.logs).not.toContain('PRIVATE_');
    });
});
