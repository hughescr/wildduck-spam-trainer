import { describe, expect, test } from 'bun:test';

type Resource = { Type: string; Condition?: string; DeletionPolicy?: string; UpdateReplacePolicy?: string; Properties: Record<string, unknown> };
interface PolicyStatement { Effect?: string; Action: string | string[]; Resource: unknown; Condition?: unknown }
interface Serverless {
    service: string; frameworkVersion: string; configValidationMode: string;
    provider: { runtime: string; architecture: string; region: string; stage: string; memorySize: number; timeout: number; logRetentionInDays: number; versionFunctions: boolean; iam: { role: string }; environment: Record<string, unknown> };
    build: { esbuild: boolean }; package: { artifact: string };
    functions: Record<string, { handler: string; url: unknown; reservedConcurrency: number; description: string }>;
    resources?: unknown;
}
interface Bootstrap {
    Parameters: Record<string, { Type: string; Default?: string; AllowedPattern?: string; AllowedValues?: string[] }>;
    Conditions: Record<string, unknown>;
    Resources: Record<string, Resource>;
    Outputs: Record<string, { Condition?: string; Value: unknown; Export?: unknown }>;
}
interface DistributionConfig {
    Aliases: unknown[]; Comment: unknown; Enabled: boolean; IPV6Enabled: boolean; HttpVersion: string; PriceClass: string; ViewerCertificate: Record<string, unknown>;
    Origins: { Id: string; DomainName: unknown; CustomOriginConfig: Record<string, unknown>; OriginCustomHeaders: { HeaderName: string; HeaderValue: unknown }[]; OriginAccessControlId?: unknown }[];
    DefaultCacheBehavior: Record<string, unknown>; CacheBehaviors?: unknown;
    CustomErrorResponses: { ErrorCode: number; ErrorCachingMinTTL: number; ResponseCode?: number; ResponsePagePath?: string }[];
    WebACLId?: unknown;
}

const serverlessText = await Bun.file('serverless.yml').text();
const bootstrapText = await Bun.file('infra/bootstrap.yml').text();
const workflowText = await Bun.file('.github/workflows/ci.yml').text();
const deployScript = await Bun.file('scripts/deploy.sh').text();
const serverless = Bun.YAML.parse(serverlessText) as Serverless;
const bootstrap = Bun.YAML.parse(bootstrapText) as Bootstrap;
const resources = bootstrap.Resources;
const distribution = resources['PublicDistribution']?.Properties['DistributionConfig'] as DistributionConfig;
function resource(name: string): Resource {
    const found = resources[name];
    if (!found) {
        throw new Error(`missing resource ${name}`);
    }
    return found;
}
const statements = (role: string) => (resource(role).Properties['Policies'] as { PolicyDocument: { Statement: PolicyStatement[] } }[]).flatMap(policy => policy.PolicyDocument.Statement);
const actions = (statement: PolicyStatement) => (typeof statement.Action === 'string' ? [statement.Action] : statement.Action);

describe('application stack (serverless.yml)', () => {
    const fn = serverless.functions['webhook'];

    test('runtime footprint: Node 26 arm64 in us-west-2, 1024 MB floor, 25 s timeout, reserved concurrency 5', () => {
        expect(serverless.frameworkVersion).toBe('4');
        expect(serverless.configValidationMode).toBe('error');
        expect(serverless.provider.runtime).toBe('nodejs26.x');
        expect(serverless.provider.architecture).toBe('arm64');
        expect(serverless.provider.region).toBe('us-west-2');
        expect(serverless.provider.memorySize).toBeGreaterThanOrEqual(1024);
        expect(serverless.provider.timeout).toBe(25);
        expect(serverless.provider.logRetentionInDays).toBe(14);
        expect(serverless.provider.versionFunctions).toBe(true);
        expect(fn?.reservedConcurrency).toBe(5);
        expect(fn?.url).toBe(true);
        expect(fn?.handler).toBe('handler.handler');
        expect(fn?.description).toBe('wildduck-spam-trainer ${file(./package.json):version}');
    });

    test('deploys the prebuilt artifact only, with no extra resources and no cross-stack imports', () => {
        expect(serverless.build.esbuild).toBe(false);
        expect(serverless.package.artifact).toBe('dist/function.zip');
        expect(serverless.resources).toBeUndefined();
        expect(serverlessText).not.toContain('ImportValue');
    });

    test('only resource names reach the Lambda environment, via exact-name-guarded variables', () => {
        expect(serverless.provider.environment).toEqual({
            TRAINING_PROXY_KEY_PARAMETER: "${env:TRAINING_PROXY_KEY_PARAMETER, ''}",
            ORIGIN_VERIFY_SECRET_ID: "${env:ORIGIN_VERIFY_SECRET_ID, ''}",
        });
        expect(deployScript).toContain("[[ \"$TRAINING_PROXY_KEY_PARAMETER\" == '/wildduck-spam-trainer/prod/training-proxy-key' ]]");
        expect(deployScript).toContain("[[ \"$ORIGIN_VERIFY_SECRET_ID\" == 'wildduck-spam-trainer/prod/origin-verify-key' ]]");
        expect(workflowText).toContain('test "$TRAINING_PROXY_KEY_PARAMETER" = /wildduck-spam-trainer/prod/training-proxy-key');
        expect(workflowText).toContain('test "$ORIGIN_VERIFY_SECRET_ID" = wildduck-spam-trainer/prod/origin-verify-key');
        expect(serverless.provider.iam.role).toContain('${env:AWS_EXECUTION_ROLE_ARN');
    });
});

describe('bootstrap two-phase structure', () => {
    test('FunctionUrlOrigin defaults to empty and gates the edge resources', () => {
        const origin = bootstrap.Parameters['FunctionUrlOrigin'];
        expect(origin?.Default).toBe('');
        const pattern = new RegExp(origin?.AllowedPattern ?? '');
        expect(pattern.test('')).toBe(true);
        expect(pattern.test('https://abc123xyz.lambda-url.us-west-2.on.aws')).toBe(true);
        for (const bad of ['https://abc.lambda-url.us-west-2.on.aws/', 'http://abc.lambda-url.us-west-2.on.aws', 'https://evil.example.com', 'https://abc.lambda-url.us-west-2.on.aws.evil.com']) {
            expect(pattern.test(bad)).toBe(false);
        }
        expect(bootstrap.Conditions).toEqual({ HasFunctionUrlOrigin: { 'Fn::Not': [{ 'Fn::Equals': [{ Ref: 'FunctionUrlOrigin' }, ''] }] } });
        const conditional = Object.entries(resources).filter(([, resource]) => resource.Condition === 'HasFunctionUrlOrigin').map(([name]) => name).sort();
        expect(conditional).toEqual(['OriginRequestPolicy', 'PublicDistribution', 'PublicDnsA', 'PublicDnsAAAA', 'ViewerRequestFunction']);
        for (const name of ['SSLCertificate', 'OriginVerifySecret', 'ArtifactBucket', 'ExecutionRole', 'GitHubDeployRole']) {
            expect(resources[name]?.Condition).toBeUndefined();
        }
    });

    test('outputs of conditional resources are conditional, and nothing is exported for the app stack to import', () => {
        for (const name of ['DistributionId', 'DistributionDomainName', 'PublicWebhookUrl', 'ViewerRequestFunctionArn']) {
            expect(bootstrap.Outputs[name]?.Condition).toBe('HasFunctionUrlOrigin');
        }
        for (const [name, output] of Object.entries(bootstrap.Outputs)) {
            expect(output.Export).toBeUndefined();
            const text = JSON.stringify(output.Value);
            const conditionalRefs = ['PublicDistribution', 'ViewerRequestFunction', 'OriginRequestPolicy', 'PublicDnsA'];
            if (conditionalRefs.some(ref => text.includes(ref))) {
                expect(`${name}:${output.Condition}`).toBe(`${name}:HasFunctionUrlOrigin`);
            }
        }
    });

    test('certificate and DNS follow the shared pattern', () => {
        expect(bootstrap.Parameters['PublicDomainName']?.Default).toBe('wildduck-spam-training.rungie.com');
        expect(bootstrap.Parameters['PublicDomainName']?.AllowedValues).toEqual(['wildduck-spam-training.rungie.com']);
        expect(bootstrap.Parameters['HostedZoneId']?.Default).toBe('Z1VXUCOF8PCGCR');
        const certificate = resources['SSLCertificate'];
        expect(certificate?.Type).toBe('Custom::DNSCertificate');
        expect(certificate?.Properties['Region']).toBe('us-east-1');
        expect(certificate?.Properties['ServiceToken']).toEqual({ 'Fn::ImportValue': 'CertificateAccepterLambda-Arn' });
        expect(certificate?.DeletionPolicy).toBe('Retain');
        for (const [name, type] of [['PublicDnsA', 'A'], ['PublicDnsAAAA', 'AAAA']] as const) {
            const dns = resources[name];
            expect(dns?.Properties['Type']).toBe(type);
            expect(dns?.Properties['Name']).toEqual({ Ref: 'PublicDomainName' });
            expect(dns?.Properties['AliasTarget']).toEqual({ DNSName: { 'Fn::GetAtt': ['PublicDistribution', 'DomainName'] }, HostedZoneId: 'Z2FDTNDATAQYW2' });
        }
        expect(distribution.Aliases).toEqual([{ Ref: 'PublicDomainName' }]);
        expect(distribution.ViewerCertificate).toEqual({ AcmCertificateArn: { Ref: 'SSLCertificate' }, SslSupportMethod: 'sni-only', MinimumProtocolVersion: 'TLSv1.2_2021' });
    });
});

describe('CloudFront distribution', () => {
    test('one Function URL origin, https-only, 30 s read timeout, no OAC, WAF, API Gateway or Lambda@Edge', () => {
        expect(distribution.Origins).toHaveLength(1);
        const origin = distribution.Origins[0];
        expect(origin?.DomainName).toEqual({ 'Fn::Select': [2, { 'Fn::Split': ['/', { Ref: 'FunctionUrlOrigin' }] }] });
        expect(origin?.CustomOriginConfig).toEqual({ OriginProtocolPolicy: 'https-only', OriginReadTimeout: 30, OriginSSLProtocols: ['TLSv1.2'] });
        expect(origin?.OriginAccessControlId).toBeUndefined();
        expect(distribution.WebACLId).toBeUndefined();
        expect(Object.values(resources).some(resource => /OriginAccessControl|WAF|ApiGateway|Lambda::Function$/.test(resource.Type))).toBe(false);
        expect(distribution.Enabled).toBe(true);
        expect(distribution.IPV6Enabled).toBe(true);
        expect(distribution.HttpVersion).toBe('http2and3');
        expect(distribution.PriceClass).toBe('PriceClass_100');
    });

    test('the origin secret header is a Secrets Manager dynamic reference; the value never appears in the template', () => {
        expect(distribution.Origins[0]?.OriginCustomHeaders).toEqual([
            { HeaderName: 'X-Origin-Verify', HeaderValue: { 'Fn::Sub': '{{resolve:secretsmanager:${OriginVerifySecret}:SecretString}}' } },
        ]);
        const secret = resources['OriginVerifySecret'];
        expect(secret?.Type).toBe('AWS::SecretsManager::Secret');
        expect(secret?.Properties['Name']).toBe('wildduck-spam-trainer/prod/origin-verify-key');
        expect(secret?.Properties['SecretString']).toBeUndefined();
        expect(secret?.Properties['GenerateSecretString']).toEqual({ PasswordLength: 64, ExcludePunctuation: true, IncludeSpace: false, RequireEachIncludedType: true });
        // AWS warns that names ending in "-" plus six characters look like ARN suffixes.
        expect(String(secret?.Properties['Name'])).not.toMatch(/-[A-Za-z0-9]{6}$/);
    });

    test('a rotation serial is wired into the distribution so updates re-resolve the dynamic reference', () => {
        expect(bootstrap.Parameters['OriginSecretRotationSerial']?.Default).toBe('1');
        expect(JSON.stringify(distribution.Comment)).toContain('${OriginSecretRotationSerial}');
    });

    test('single default behavior: seven methods, CachingDisabled, custom origin policy, viewer-request function', () => {
        const behavior = distribution.DefaultCacheBehavior;
        expect(distribution.CacheBehaviors).toBeUndefined();
        expect(behavior['AllowedMethods']).toEqual(['GET', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'POST', 'DELETE']);
        expect(behavior['CachePolicyId']).toBe('4135ea2d-6df8-44a3-9df3-4b5a84be39ad');
        expect(behavior['OriginRequestPolicyId']).toEqual({ Ref: 'OriginRequestPolicy' });
        expect(behavior['ViewerProtocolPolicy']).toBe('https-only');
        expect(behavior['FunctionAssociations']).toEqual([{ EventType: 'viewer-request', FunctionARN: { 'Fn::GetAtt': ['ViewerRequestFunction', 'FunctionARN'] } }]);
        expect(behavior['LambdaFunctionAssociations']).toBeUndefined();
        expect(behavior['ResponseHeadersPolicyId']).toBeUndefined();
    });

    test('custom errors have zero TTL and no body or status rewriting', () => {
        expect(distribution.CustomErrorResponses.map(error => error.ErrorCode)).toEqual([400, 403, 404, 405, 414, 416, 500, 501, 502, 503, 504]);
        for (const error of distribution.CustomErrorResponses) {
            expect(error.ErrorCachingMinTTL).toBe(0);
            expect(error.ResponseCode).toBeUndefined();
            expect(error.ResponsePagePath).toBeUndefined();
        }
    });

    test('origin request policy forwards only Content-Type and User-Agent, never Host or x-origin-verify', () => {
        const config = resources['OriginRequestPolicy']?.Properties['OriginRequestPolicyConfig'] as { HeadersConfig: { HeaderBehavior: string; Headers: string[] }; CookiesConfig: unknown; QueryStringsConfig: unknown };
        expect(config.HeadersConfig).toEqual({ HeaderBehavior: 'whitelist', Headers: ['Content-Type', 'User-Agent'] });
        const lower = config.HeadersConfig.Headers.map(header => header.toLowerCase());
        expect(lower).not.toContain('host');
        expect(lower).not.toContain('x-origin-verify');
        expect(config.CookiesConfig).toEqual({ CookieBehavior: 'none' });
        expect(config.QueryStringsConfig).toEqual({ QueryStringBehavior: 'all' });
    });
});

describe('IAM', () => {
    test('execution role: logs on its own group, exactly one SSM parameter, exactly the origin secret; nothing else', () => {
        expect(statements('ExecutionRole')).toEqual([
            { Effect: 'Allow', Action: ['logs:CreateLogStream', 'logs:PutLogEvents'], Resource: { 'Fn::Sub': 'arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/wildduck-spam-trainer-prod-webhook:*' } },
            { Effect: 'Allow', Action: 'ssm:GetParameter', Resource: { 'Fn::Sub': 'arn:${AWS::Partition}:ssm:${AWS::Region}:${AWS::AccountId}:parameter/wildduck-spam-trainer/prod/training-proxy-key' } },
            { Effect: 'Allow', Action: 'secretsmanager:GetSecretValue', Resource: { Ref: 'OriginVerifySecret' } },
        ]);
        expect(resources['ExecutionRole']?.Properties['ManagedPolicyArns']).toBeUndefined();
    });

    test('CI deploy role is limited to its own stack, function, log group and artifact prefix', () => {
        const deploy = statements('GitHubDeployRole');
        const all = deploy.flatMap(actions);
        for (const forbidden of ['cloudfront:', 'route53:', 'ssm:', 'secretsmanager:', 'acm:', 'kms:', 'wafv2:', 'apigateway:', 'iam:Create', 'iam:Put', 'iam:Attach', 'iam:Update', 'iam:Delete', 'sts:']) {
            expect(all.some(action => action.startsWith(forbidden))).toBe(false);
        }
        const wildcard = deploy.filter(statement => statement.Resource === '*').flatMap(actions).sort();
        expect(wildcard).toEqual(['cloudformation:ValidateTemplate', 'logs:DescribeLogGroups']);
        const lambda = deploy.find(statement => actions(statement).includes('lambda:*'));
        expect(lambda?.Resource).toEqual([
            { 'Fn::Sub': 'arn:${AWS::Partition}:lambda:${AWS::Region}:${AWS::AccountId}:function:wildduck-spam-trainer-prod-webhook' },
            { 'Fn::Sub': 'arn:${AWS::Partition}:lambda:${AWS::Region}:${AWS::AccountId}:function:wildduck-spam-trainer-prod-webhook:*' },
        ]);
        const logs = deploy.find(statement => actions(statement).includes('logs:*'));
        expect(logs?.Resource).toEqual([
            { 'Fn::Sub': 'arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/wildduck-spam-trainer-prod-webhook' },
            { 'Fn::Sub': 'arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/wildduck-spam-trainer-prod-webhook:*' },
        ]);
        const stack = deploy.find(statement => actions(statement).includes('cloudformation:UpdateStack'));
        expect(stack?.Resource).toEqual({ 'Fn::Sub': 'arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/wildduck-spam-trainer-prod/*' });
        const objects = deploy.find(statement => actions(statement).includes('s3:PutObject'));
        expect(objects?.Resource).toEqual({ 'Fn::Sub': '${ArtifactBucket.Arn}/serverless/wildduck-spam-trainer/prod/*' });
        const iam = deploy.find(statement => actions(statement).some(action => action.startsWith('iam:')));
        expect(iam).toEqual({ Effect: 'Allow', Action: ['iam:GetRole', 'iam:PassRole'], Resource: { 'Fn::GetAtt': ['ExecutionRole', 'Arn'] }, Condition: { StringEqualsIfExists: { 'iam:PassedToService': 'lambda.amazonaws.com' } } });
    });

    test('OIDC trust binds the immutable owner/repository IDs and the main branch only', () => {
        const trust = (resource('GitHubDeployRole').Properties['AssumeRolePolicyDocument'] as { Statement: { Action: string; Principal: unknown; Condition: unknown }[] }).Statement;
        expect(trust).toHaveLength(1);
        expect(trust[0]?.Action).toBe('sts:AssumeRoleWithWebIdentity');
        expect(trust[0]?.Principal).toEqual({ Federated: { 'Fn::ImportValue': 'GitHubOIDCProvider-Arn' } });
        expect(trust[0]?.Condition).toEqual({
            StringEquals: {
                'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
                'token.actions.githubusercontent.com:sub': { 'Fn::Sub': 'repo:hughescr@46348/wildduck-spam-trainer@${GitHubRepositoryId}:ref:refs/heads/main' },
            },
        });
        const repoId = bootstrap.Parameters['GitHubRepositoryId'];
        expect(repoId?.Default).toBeUndefined();
        expect(new RegExp(repoId?.AllowedPattern ?? '').test('1434754693')).toBe(true);
        expect(new RegExp(repoId?.AllowedPattern ?? '').test('*')).toBe(false);
    });
});

describe('CI workflow', () => {
    test('uses the same pinned actions, deploys only main with DEPLOY_ENABLED via OIDC, and has no long-lived keys', () => {
        const uses = [...new Set([...workflowText.matchAll(/uses: (\S+)/g)].map(match => match[1]))].sort();
        expect(uses).toEqual(['actions/checkout@v7', 'actions/download-artifact@v8', 'actions/setup-node@v7', 'actions/upload-artifact@v7', 'aws-actions/configure-aws-credentials@v6', 'oven-sh/setup-bun@v2']);
        expect(workflowText).toContain("if: github.event_name != 'pull_request' && github.ref == 'refs/heads/main' && vars.DEPLOY_ENABLED == 'true'");
        expect(workflowText.match(/id-token: write/g)).toHaveLength(1);
        expect(workflowText).not.toMatch(/aws-access-key-id|aws-secret-access-key|AWS_SECRET_ACCESS_KEY/);
        const secrets = [...new Set([...workflowText.matchAll(/secrets\.([A-Z_]+)/g)].map(match => match[1]))];
        expect(secrets).toEqual(['SERVERLESS_ACCESS_KEY']);
        expect(workflowText).toContain('bun-version: 1.4.4');
        expect(workflowText).toContain("node-version: '26'");
        expect(workflowText).toContain('node scripts/verify-deployment.mjs');
        expect(workflowText).toContain("PUBLIC_ENDPOINT_ENABLED: ${{ vars.PUBLIC_ENDPOINT_ENABLED || 'false' }}");
    });
});

describe('no secret material anywhere in configuration', () => {
    const files = ['serverless.yml', 'infra/bootstrap.yml', '.github/workflows/ci.yml', '.env.example', 'scripts/deploy.sh', 'scripts/verify-deployment.mjs'];

    test('templates and workflows contain no secret values or long opaque tokens', async () => {
        for (const file of files) {
            const text = await Bun.file(file).text();
            expect(text).not.toMatch(/AKIA[0-9A-Z]{16}/);
            // A literal SecretString property would embed a value; GenerateSecretString is fine.
            expect(/^\s*SecretString:/m.test(text)).toBe(false);
            expect(text).not.toMatch(/X-Mail-Training-Key:\s*\S/i);
            expect(text).not.toMatch(/X-Origin-Verify:\s*[A-Za-z0-9]{16,}/i);
            // No hard-coded high-entropy tokens (secret-looking strings of 32+ alphanumerics).
            expect(text).not.toMatch(/(?<![A-Za-z0-9])(?=[A-Za-z0-9]*[0-9])(?=[A-Za-z0-9]*[a-z])(?=[A-Za-z0-9]*[A-Z])[A-Za-z0-9]{32,}(?![A-Za-z0-9])/);
        }
        // The training key is operator-provisioned, never a CloudFormation resource.
        expect(Object.values(resources).some(resource => resource.Type === 'AWS::SSM::Parameter')).toBe(false);
    });

    test('the project never mentions a webhook query secret', async () => {
        const glob = new Bun.Glob('**/*.{ts,mjs,sh,yml,yaml,json,md,example}');
        for await (const file of glob.scan({ cwd: '.', dot: true })) {
            if (file.startsWith('node_modules/') || file.startsWith('dist/') || file.startsWith('.serverless/') || file === 'bun.lock' || file === 'tests/infrastructure.test.ts') {
                continue;
            }
            const text = (await Bun.file(file).text()).toLowerCase();
            for (const phrase of ['webhook secret', 'webhook-secret', 'webhook_secret', '?secret=', 'webhooksecret']) {
                if (text.includes(phrase)) {
                    throw new Error(`${file} mentions ${phrase}`);
                }
            }
        }
    });
});
