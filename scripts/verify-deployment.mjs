// Post-deploy verification. Works in both bootstrap phases and never triggers learning:
// probe requests carry no valid origin header (direct) or come from a non-allowlisted
// GitHub runner address (edge), and their body is an unsupported event in any case.
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';

const FUNCTION_NAME = 'wildduck-spam-trainer-prod-webhook';
const PUBLIC_BASE_URL = 'https://wildduck-spam-training.rungie.com';
const PROBE_BODY = JSON.stringify({ ev: 'deployment.probe' });
const { version } = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const aws = (...args) => JSON.parse(execFileSync('aws', [...args, '--output', 'json'], { encoding: 'utf8', timeout: 30_000 }));
const request = (url, options = {}) => fetch(url, { ...options, redirect: 'manual', signal: AbortSignal.timeout(15_000) });

// 1. Deployed Lambda configuration and version (always).
const deployed = aws('lambda', 'get-function-configuration', '--function-name', FUNCTION_NAME);
assert.equal(deployed.Runtime, 'nodejs26.x');
assert.deepEqual(deployed.Architectures, ['arm64']);
assert.ok(deployed.MemorySize >= 1024, 'Memory must stay at or above the 1024 MB floor');
assert.equal(deployed.Timeout, 25);
assert.equal(deployed.Description, `wildduck-spam-trainer ${version}`, 'Live Lambda must run the checked-out release');
assert.deepEqual(Object.keys(deployed.Environment?.Variables ?? {}).sort(), ['ORIGIN_VERIFY_SECRET_ID', 'TRAINING_PROXY_KEY_PARAMETER'], 'Only resource names are configured');
assert.equal(deployed.Environment.Variables.TRAINING_PROXY_KEY_PARAMETER, process.env.TRAINING_PROXY_KEY_PARAMETER);
assert.equal(deployed.Environment.Variables.ORIGIN_VERIFY_SECRET_ID, process.env.ORIGIN_VERIFY_SECRET_ID);
const concurrency = aws('lambda', 'get-function-concurrency', '--function-name', FUNCTION_NAME);
assert.equal(concurrency.ReservedConcurrentExecutions, 5);
const urlConfig = aws('lambda', 'get-function-url-config', '--function-name', FUNCTION_NAME);
assert.equal(urlConfig.AuthType, 'NONE');
const functionUrl = urlConfig.FunctionUrl;

// 2. Direct Function URL requests are rejected without (or with a wrong) origin header.
const fabricated = randomBytes(48).toString('base64').replace(/[^A-Za-z0-9]/g, '').padEnd(64, 'a');
for (const [path, method, headers] of [
    ['/healthz', 'GET', {}],
    ['/healthz', 'GET', { 'X-Origin-Verify': fabricated }],
    ['/hooks/wildduck', 'POST', { 'Content-Type': 'application/json' }],
]) {
    const response = await request(new URL(path, functionUrl), { method, headers, ...(method === 'POST' ? { body: PROBE_BODY } : {}) });
    assert.equal(response.status, 403, `Direct Function URL ${method} ${path} must be rejected`);
    // The service's own body proves the function ran and rejected it (not an AWS-side authorization failure).
    assert.equal(await response.text(), '{"error":"forbidden"}', `Direct Function URL ${method} ${path} must be rejected by the origin check`);
}

// 3. Public edge checks, only once bootstrap phase 2 has created the distribution.
if (process.env.PUBLIC_ENDPOINT_ENABLED === 'true') {
    const health = await request(`${PUBLIC_BASE_URL}/healthz`);
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { service: 'wildduck-spam-trainer', version, status: 'ok' }, 'Public endpoint must serve the checked-out release');
    const hook = await request(`${PUBLIC_BASE_URL}/hooks/wildduck`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: PROBE_BODY });
    const text = await hook.text();
    assert.equal(hook.status, 403, 'The edge must reject webhook POSTs from a non-allowlisted address');
    assert.notEqual(text, '{"error":"forbidden"}', 'The 403 must come from the edge function, not the Lambda');
    const ready = await request(`${PUBLIC_BASE_URL}/readyz`);
    // Informational: readiness depends on the operator-installed training key (bootstrap step 4).
    process.stdout.write(`readiness: HTTP ${ready.status}\n`);
    await ready.body?.cancel();
} else {
    process.stdout.write('PUBLIC_ENDPOINT_ENABLED is not true: skipped public edge checks.\n');
}
