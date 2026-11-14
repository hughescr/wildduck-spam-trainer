// Post-deploy verification. Never triggers learning: probe requests carry no valid origin
// header (direct) or come from a non-allowlisted GitHub runner address (edge), and their body
// is an unsupported event in any case. Only statuses and fixed messages are logged, never bodies.
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { setTimeout as sleep } from 'node:timers/promises';
import assert from 'node:assert/strict';
import { BlockList, isIP } from 'node:net';

const FUNCTION_NAME = 'wildduck-spam-trainer-prod-webhook';
const STACK_NAME = 'wildduck-spam-trainer-prod';
const WEBHOOK_PATH = '/hooks/wildduck';
const FORBIDDEN_BODY = '{"error":"forbidden"}';
const PROBE_BODY = JSON.stringify({ ev: 'deployment.probe' });
// A first deploy creates the distribution and DNS records; they can take minutes to resolve.
const HEALTH_WAIT_MS = 10 * 60_000;
const HEALTH_RETRY_MS = 15_000;
const { version } = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const aws = (...args) => {
    try {
        return JSON.parse(execFileSync('aws', [...args, '--output', 'json'], { encoding: 'utf8', timeout: 30_000, stdio: ['pipe', 'pipe', 'pipe'] }));
    } catch {
        throw new Error('AWS verification request failed');
    }
};
const request = (url, options = {}) => fetch(url, { ...options, redirect: 'manual', signal: AbortSignal.timeout(15_000) });
const log = message => process.stdout.write(`${message}\n`);
// assert.* would print the compared values on failure; response bodies must never reach the log.
const check = (condition, message) => assert.ok(condition, message);

// 1. Deployed Lambda configuration and version.
const deployed = aws('lambda', 'get-function-configuration', '--function-name', FUNCTION_NAME);
check(deployed.Runtime === 'nodejs26.x', 'Expected Node 26 runtime');
check(JSON.stringify(deployed.Architectures) === '["arm64"]', 'Expected arm64 architecture');
check(deployed.MemorySize >= 1024, 'Memory must stay at or above the 1024 MB floor');
check(deployed.Timeout === 25, 'Expected 25 second timeout');
check(deployed.Description === `wildduck-spam-trainer ${version}`, 'Live Lambda must run the checked-out release');
check(JSON.stringify(Object.keys(deployed.Environment?.Variables ?? {}).sort()) === '["ORIGIN_VERIFY_SECRET_ID","TRAINING_PROXY_KEY_PARAMETER"]', 'Only resource names are configured');
check(deployed.Environment.Variables.TRAINING_PROXY_KEY_PARAMETER === process.env.TRAINING_PROXY_KEY_PARAMETER, 'Unexpected training key parameter name');
check(deployed.Environment.Variables.ORIGIN_VERIFY_SECRET_ID === process.env.ORIGIN_VERIFY_SECRET_ID, 'Unexpected origin secret name');
const concurrency = aws('lambda', 'get-function-concurrency', '--function-name', FUNCTION_NAME);
check(concurrency.ReservedConcurrentExecutions === 5, 'Expected reserved concurrency 5');
const urlConfig = aws('lambda', 'get-function-url-config', '--function-name', FUNCTION_NAME);
check(urlConfig.AuthType === 'NONE', 'Expected public Function URL authentication mode');

// 2. Public and direct URLs come from the Serverless stack outputs.
const [stack] = aws('cloudformation', 'describe-stacks', '--stack-name', STACK_NAME).Stacks;
const outputs = new Map((stack.Outputs ?? []).map(output => [output.OutputKey, output.OutputValue]));
for (const name of ['PublicWebhookUrl', 'DistributionId', 'DistributionDomainName']) {
    check(outputs.get(name), `Stack output ${name} is missing`);
}
const publicWebhookUrl = new URL(outputs.get('PublicWebhookUrl'));
check(publicWebhookUrl.protocol === 'https:' && publicWebhookUrl.pathname === WEBHOOK_PATH, 'PublicWebhookUrl must be the https webhook URL');
const publicBaseUrl = publicWebhookUrl.origin;
// The framework names its Function URL output "<FunctionName>LambdaFunctionUrl".
const functionUrlKeys = [...outputs.keys()].filter(key => key.endsWith('LambdaFunctionUrl'));
check(functionUrlKeys.length === 1, 'Expected exactly one Function URL stack output');
const functionUrl = outputs.get(functionUrlKeys[0]);
check(functionUrl === urlConfig.FunctionUrl, 'The Function URL output must match the deployed Function URL');

// TestFunction evaluates LIVE code in isolation; it never forwards a request to Lambda.
const viewerFunctionName = 'wildduck-spam-trainer-prod-viewer-request';
const allowlist = aws('ssm', 'get-parameter', '--region', 'us-west-2', '--name', '/wildduck-spam-trainer/prod/allowed-source-ips').Parameter?.Value;
const allowlistMatch = typeof allowlist === 'string' && /^[0-9A-Fa-f.:]{2,45}(,[0-9A-Fa-f.:]{2,45}){0,49}$/.exec(allowlist);
check(allowlistMatch && allowlistMatch[0] === allowlist, 'Invalid source-IP allowlist');
const addresses = allowlist.split(',');
const allowed = new BlockList();
for (const address of addresses) {
    const normalized = address.replace(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/, tail => tail.split('.').map(Number).join('.'));
    const family = isIP(normalized);
    check(family !== 0, 'Invalid source-IP allowlist address');
    allowed.addAddress(normalized, family === 4 ? 'ipv4' : 'ipv6');
}
// At most 50 allowlisted addresses cannot cover these 51 distinct probe addresses.
const deniedAddress = Array.from({ length: 51 }, (_, index) => `192.0.2.${index + 1}`).find(address => !allowed.check(address, 'ipv4'));
check(deniedAddress, 'Could not select a non-allowlisted probe address');
const { ETag } = aws('cloudfront', 'describe-function', '--name', viewerFunctionName, '--stage', 'LIVE');
check(typeof ETag === 'string' && ETag.length > 0, 'Missing LIVE viewer function version');
const testViewer = address => {
    const event = {
        version: '1.0', context: { eventType: 'viewer-request' }, viewer: { ip: address },
        request: { method: 'POST', uri: WEBHOOK_PATH, querystring: {}, headers: { host: { value: publicWebhookUrl.hostname } }, cookies: {} },
    };
    const { TestResult } = aws('cloudfront', 'test-function', '--name', viewerFunctionName, '--if-match', ETag, '--stage', 'LIVE', '--cli-binary-format', 'base64', '--event-object', Buffer.from(JSON.stringify(event)).toString('base64'));
    check(TestResult && !TestResult.FunctionErrorMessage, 'LIVE viewer function test failed');
    try {
        return JSON.parse(TestResult.FunctionOutput);
    } catch {
        throw new Error('Invalid LIVE viewer function test output');
    }
};
for (const address of addresses) {
    const result = testViewer(address);
    check(result?.request?.method === 'POST' && result.request.uri === WEBHOOK_PATH && result.response === undefined, 'LIVE viewer function rejected an allowlisted webhook POST');
}
const denied = testViewer(deniedAddress);
check(denied?.response?.statusCode === 403 && denied.request === undefined, 'LIVE viewer function must reject a non-allowlisted webhook POST');
log('LIVE viewer function: all allowlisted webhook POSTs accepted; non-allowlisted POST rejected with HTTP 403');

// 3. Direct Function URL requests are rejected without (or with a wrong) origin header.
const fabricated = randomBytes(48).toString('base64').replace(/[^A-Za-z0-9]/g, '').padEnd(64, 'a');
for (const [path, method, headers] of [
    ['/healthz', 'GET', {}],
    ['/healthz', 'GET', { 'X-Origin-Verify': fabricated }],
    [WEBHOOK_PATH, 'POST', { 'Content-Type': 'application/json' }],
]) {
    const response = await request(new URL(path, functionUrl), { method, headers, ...(method === 'POST' ? { body: PROBE_BODY } : {}) });
    const body = await response.text();
    check(response.status === 403, `Direct Function URL ${method} ${path} must be rejected (HTTP ${response.status})`);
    // The service's own body proves the function ran and rejected it (not an AWS-side authorization failure).
    check(body === FORBIDDEN_BODY, `Direct Function URL ${method} ${path} must be rejected by the origin check`);
}
log('direct Function URL: rejected without a valid origin header');

// 4. Public domain: /healthz must answer 200 for the checked-out release (CloudFront -> origin header -> Lambda).
// DNS and CloudFront propagation can take minutes after a first deploy, so retry for a bounded time.
const attemptHealth = async () => {
    try {
        const response = await request(`${publicBaseUrl}/healthz`);
        const text = await response.text();
        if (response.status !== 200) {
            return `HTTP ${response.status}`;
        }
        let body;
        try {
            body = JSON.parse(text);
        } catch {
            return 'HTTP 200 with an unexpected body';
        }
        const expected = { service: 'wildduck-spam-trainer', version, status: 'ok' };
        const matches = body !== null && typeof body === 'object' && !Array.isArray(body)
            && Object.keys(expected).every(key => body[key] === expected[key]) && Object.keys(body).length === Object.keys(expected).length;
        return matches ? undefined : 'HTTP 200 with an unexpected body (not the checked-out release)';
    } catch {
        return 'network error';
    }
};
const deadline = Date.now() + HEALTH_WAIT_MS;
for (let attempt = 1; ; attempt += 1) {
    const failure = await attemptHealth();
    if (failure === undefined) {
        log(`public /healthz: HTTP 200 (attempt ${attempt})`);
        break;
    }
    log(`public /healthz attempt ${attempt}: ${failure}`);
    check(Date.now() + HEALTH_RETRY_MS < deadline, `Public /healthz did not return the checked-out release within ${HEALTH_WAIT_MS / 60_000} minutes`);
    await sleep(HEALTH_RETRY_MS);
}

// 5. From the CI runner (not allowlisted) the edge must reject webhook POSTs before they reach Lambda.
const hook = await request(`${publicBaseUrl}${WEBHOOK_PATH}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: PROBE_BODY });
const hookBody = await hook.text();
check(hook.status === 403, `The edge must reject webhook POSTs from a non-allowlisted address (HTTP ${hook.status})`);
check(hookBody !== FORBIDDEN_BODY, 'The 403 must come from the edge function, not the Lambda');
log('public webhook POST from the runner: HTTP 403 from the edge');

// 6. Informational: readiness depends on the operator-installed training key.
const ready = await request(`${publicBaseUrl}/readyz`);
log(`readiness: HTTP ${ready.status}`);
await ready.body?.cancel();
