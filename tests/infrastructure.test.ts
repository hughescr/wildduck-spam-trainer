import { describe, expect, test } from 'bun:test';

type Resource = { Type: string; Condition?: string; DeletionPolicy?: string; UpdateReplacePolicy?: string; Properties: Record<string, unknown> };
interface PolicyStatement { Sid?: string; Effect?: string; Action: string | string[]; Resource: unknown; Condition?: unknown }
interface Serverless {
    service: string; frameworkVersion: string; configValidationMode: string;
    provider: { runtime: string; architecture: string; region: string; stage: string; deploymentMethod: string; memorySize: number; timeout: number; logRetentionInDays: number; versionFunctions: boolean; iam: { role: string }; environment: Record<string, unknown>; stackTags: Record<string, string>; tags: Record<string, string> };
    build: { esbuild: boolean }; package: { artifact: string };
    functions: Record<string, { handler: string; url: unknown; reservedConcurrency: number; description: string }>;
    resources: { extensions: Record<string, { Properties: Record<string, unknown> }>; Resources: Record<string, Resource>; Outputs: Record<string, { Value: unknown }> };
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
const resources = { ...bootstrap.Resources, ...serverless.resources.Resources };
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

    test('deploys the prebuilt artifact and edge resources together using direct deployment', () => {
        expect(serverless.build.esbuild).toBe(false);
        expect(serverless.package.artifact).toBe('dist/function.zip');
        expect(serverless.provider.deploymentMethod).toBe('direct');
        expect(serverless.provider.stage).toBe('prod');
        expect(serverless.service).toBe('wildduck-spam-trainer');
        expect(Object.keys(serverless.resources.Resources).sort()).toEqual(['PublicDistribution', 'PublicDnsA', 'PublicDnsAAAA', 'ViewerRequestFunction']);
        const env = [...new Set([...serverlessText.matchAll(/\$\{env:([A-Z_]+)/g)].map(match => match[1]))].sort();
        expect(env).toEqual(['ALLOWED_SOURCE_IPS', 'AWS_DEPLOYMENT_BUCKET_NAME', 'AWS_EXECUTION_ROLE_ARN', 'ORIGIN_SECRET_ROTATION_SERIAL', 'ORIGIN_VERIFY_SECRET_ID', 'TRAINING_PROXY_KEY_PARAMETER']);
        expect(serverlessText).not.toContain('cfnRole');
        expect(serverlessText).not.toContain('deploymentRole');
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

describe('one-time bootstrap structure', () => {
    test('owns only the stable foundation and admin edge settings, without a Function URL input', () => {
        expect(bootstrapText).not.toContain('FunctionUrlOrigin');
        expect(serverlessText).not.toContain('FunctionUrlOrigin');
        expect(bootstrap.Conditions).toBeUndefined();
        expect(Object.keys(bootstrap.Parameters).sort()).toEqual(['AllowedSourceIps', 'GitHubRepositoryId', 'HostedZoneId', 'OriginSecretRotationSerial', 'PublicDomainName']);
        expect(Object.keys(bootstrap.Resources).sort()).toEqual(['AllowedSourceIpsParameter', 'ArtifactBucket', 'ExecutionRole', 'GitHubDeployRole', 'OriginSecretRotationSerialParameter', 'OriginVerifySecret', 'SSLCertificate']);
        for (const entry of Object.values(resources)) {
            expect(entry.Condition).toBeUndefined();
        }
        for (const [name, parameter, path] of [
            ['AllowedSourceIpsParameter', 'AllowedSourceIps', 'allowed-source-ips'],
            ['OriginSecretRotationSerialParameter', 'OriginSecretRotationSerial', 'origin-secret-rotation-serial'],
        ] as const) {
            expect(resource(name)).toMatchObject({ Type: 'AWS::SSM::Parameter', Properties: {
                Name: `/wildduck-spam-trainer/prod/${path}`, Type: 'String', Value: { Ref: parameter }, AllowedPattern: bootstrap.Parameters[parameter]?.AllowedPattern,
            } });
        }
    });

    test('exports stable inputs only; mutable settings are read from SSM on every service deploy', () => {
        for (const [name, ref] of [['CertificateArn', 'SSLCertificate'], ['HostedZoneId', 'HostedZoneId'], ['PublicDomainName', 'PublicDomainName']] as const) {
            expect(bootstrap.Outputs[name]).toEqual({ Value: { Ref: ref }, Export: { Name: `wildduck-spam-trainer-prod-${name}` } });
            expect(serverlessText).toContain(`Fn::ImportValue: wildduck-spam-trainer-prod-${name}`);
        }
        expect(Object.keys(bootstrap.Outputs).sort()).toEqual(['ArtifactBucketName', 'CertificateArn', 'ExecutionRoleArn', 'GitHubDeployRoleArn', 'HostedZoneId', 'OriginVerifySecretArn', 'PublicDomainName']);
        expect(serverlessText).toContain('${env:ALLOWED_SOURCE_IPS, ssm(raw):/wildduck-spam-trainer/prod/allowed-source-ips}');
        expect(serverlessText).toContain('${env:ORIGIN_SECRET_ROTATION_SERIAL, ssm(raw):/wildduck-spam-trainer/prod/origin-secret-rotation-serial}');
        expect(serverless.resources.Outputs).toEqual({
            PublicWebhookUrl: { Value: { 'Fn::Join': ['', ['https://', { 'Fn::ImportValue': 'wildduck-spam-trainer-prod-PublicDomainName' }, '/hooks/wildduck']] } },
            DistributionId: { Value: { Ref: 'PublicDistribution' } },
            DistributionDomainName: { Value: { 'Fn::GetAtt': ['PublicDistribution', 'DomainName'] } },
        });
    });

    test('every supported resource has the Email billing tag and service ownership tag', () => {
        const tags = { Project: 'Email', Service: 'wildduck-spam-trainer' };
        expect(serverless.provider.tags).toEqual(tags);
        expect(serverless.provider.stackTags).toEqual(tags);
        expect(serverless.resources.extensions).toEqual({
            WebhookLogGroup: { Properties: { Tags: [{ Key: 'Project', Value: 'Email' }, { Key: 'Service', Value: 'wildduck-spam-trainer' }] } },
        });
        for (const [name, entry] of Object.entries(resources)) {
            // Custom certificate contract has no verified Tags support; policies/records are untaggable.
            if (['SSLCertificate', 'PublicDnsA', 'PublicDnsAAAA'].includes(name)) {
                expect(entry.Properties['Tags']).toBeUndefined();
            } else if (entry.Type === 'AWS::SSM::Parameter') {
                expect(entry.Properties['Tags']).toEqual(tags);
            } else {
                expect(entry.Properties['Tags']).toEqual([{ Key: 'Project', Value: 'Email' }, { Key: 'Service', Value: 'wildduck-spam-trainer' }]);
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
            expect(dns?.Properties['Name']).toEqual({ 'Fn::ImportValue': 'wildduck-spam-trainer-prod-PublicDomainName' });
            expect(dns?.Properties['HostedZoneId']).toEqual({ 'Fn::ImportValue': 'wildduck-spam-trainer-prod-HostedZoneId' });
            expect(dns?.Properties['AliasTarget']).toEqual({ DNSName: { 'Fn::GetAtt': ['PublicDistribution', 'DomainName'] }, HostedZoneId: 'Z2FDTNDATAQYW2' });
        }
        expect(distribution.Aliases).toEqual([{ 'Fn::ImportValue': 'wildduck-spam-trainer-prod-PublicDomainName' }]);
        expect(distribution.ViewerCertificate).toEqual({ AcmCertificateArn: { 'Fn::ImportValue': 'wildduck-spam-trainer-prod-CertificateArn' }, SslSupportMethod: 'sni-only', MinimumProtocolVersion: 'TLSv1.2_2021' });
    });
});

describe('CloudFront distribution', () => {
    test('one Function URL origin, https-only, 30 s read timeout, no OAC, WAF, API Gateway or Lambda@Edge', () => {
        expect(resource('PublicDistribution').DeletionPolicy).toBe('RetainExceptOnCreate');
        expect(resource('PublicDnsA').DeletionPolicy).toBeUndefined();
        expect(resource('PublicDnsAAAA').DeletionPolicy).toBeUndefined();
        expect(resource('PublicDistribution').UpdateReplacePolicy).toBe('Retain');
        expect(distribution.Origins).toHaveLength(1);
        const origin = distribution.Origins[0];
        expect(origin?.DomainName).toEqual({ 'Fn::Select': [2, { 'Fn::Split': ['/', { 'Fn::GetAtt': ['WebhookLambdaFunctionUrl', 'FunctionUrl'] }] }] });
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
            { HeaderName: 'X-Origin-Verify', HeaderValue: '{{resolve:secretsmanager:${env:ORIGIN_VERIFY_SECRET_ID}:SecretString}}' },
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
        expect(distribution.Comment).toBe('wildduck-spam-trainer webhook edge (origin secret serial ${env:ORIGIN_SECRET_ROTATION_SERIAL, ssm(raw):/wildduck-spam-trainer/prod/origin-secret-rotation-serial})');
    });

    test('single default behavior: seven methods, CachingDisabled, managed origin policy, viewer-request function', () => {
        const behavior = distribution.DefaultCacheBehavior;
        expect(distribution.CacheBehaviors).toBeUndefined();
        expect(behavior['AllowedMethods']).toEqual(['GET', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'POST', 'DELETE']);
        expect(behavior['CachePolicyId']).toBe('4135ea2d-6df8-44a3-9df3-4b5a84be39ad');
        expect(behavior['OriginRequestPolicyId']).toBe('b689b0a8-53d0-40ab-baf2-68738e2966ac');
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

    test('uses AllViewerExceptHostHeader with all query strings and cookies, without a custom policy or policy-management permissions', () => {
        expect(distribution.DefaultCacheBehavior['OriginRequestPolicyId']).toBe('b689b0a8-53d0-40ab-baf2-68738e2966ac');
        expect(resources['OriginRequestPolicy']).toBeUndefined();
        expect(Object.values(resources).some(entry => entry.Type === 'AWS::CloudFront::OriginRequestPolicy')).toBe(false);
        expect(statements('GitHubDeployRole').flatMap(actions).some(action => action.includes('OriginRequestPolicy'))).toBe(false);
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
        for (const forbidden of ['acm:', 'kms:', 'wafv2:', 'apigateway:', 'iam:Create', 'iam:Put', 'iam:Attach', 'iam:Update', 'iam:Delete', 'ssm:Put', 'ssm:Delete', 'secretsmanager:Put', 'secretsmanager:Update', 'sts:']) {
            expect(all.some(action => action.startsWith(forbidden))).toBe(false);
        }
        const wildcard = deploy.filter(statement => statement.Effect === 'Allow' && statement.Resource === '*').flatMap(actions).sort();
        expect(wildcard).toEqual(['cloudformation:ValidateTemplate', 'cloudfront:CreateDistribution', 'cloudfront:CreateFunction', 'cloudfront:ListDistributions', 'cloudfront:ListFunctions', 'logs:DescribeIndexPolicies', 'logs:DescribeLogGroups', 'logs:DescribeResourcePolicies', 'route53:ListHostedZones']);
        const allowedActions = deploy.filter(statement => statement.Effect === 'Allow').flatMap(actions);
        expect(allowedActions).not.toContain('cloudformation:CreateChangeSet');
        expect(allowedActions).not.toContain('cloudformation:ExecuteChangeSet');
        expect(allowedActions).not.toContain('cloudformation:DeleteStack');
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
        expect(iam).toEqual({ Sid: 'ExecutionRoleOnly', Effect: 'Allow', Action: ['iam:GetRole', 'iam:PassRole'], Resource: { 'Fn::GetAtt': ['ExecutionRole', 'Arn'] }, Condition: { StringEqualsIfExists: { 'iam:PassedToService': 'lambda.amazonaws.com' } } });
    });

    test('CI can only read the two admin edge settings and the exact origin secret', () => {
        const deploy = statements('GitHubDeployRole');
        expect(deploy.filter(statement => actions(statement).some(action => action.startsWith('ssm:')))).toEqual([{
            Sid: 'ReadEdgeSettings', Effect: 'Allow', Action: ['ssm:GetParameter', 'ssm:GetParameters'], Resource: [
                { 'Fn::Sub': 'arn:${AWS::Partition}:ssm:${AWS::Region}:${AWS::AccountId}:parameter/wildduck-spam-trainer/prod/allowed-source-ips' },
                { 'Fn::Sub': 'arn:${AWS::Partition}:ssm:${AWS::Region}:${AWS::AccountId}:parameter/wildduck-spam-trainer/prod/origin-secret-rotation-serial' },
            ],
        }]);
        expect(deploy.filter(statement => actions(statement).some(action => action.startsWith('secretsmanager:')))).toEqual([{
            Sid: 'ResolveOriginSecret', Effect: 'Allow', Action: 'secretsmanager:GetSecretValue', Resource: { Ref: 'OriginVerifySecret' },
        }]);
    });

    test('stack tags are restricted to Project/Service with a nonempty-key guard', () => {
        const tags = statements('GitHubDeployRole').filter(statement => actions(statement).some(action => ['cloudformation:TagResource', 'cloudformation:UntagResource'].includes(action)));
        expect(tags).toEqual([{
            Sid: 'ServiceStackTags', Effect: 'Allow', Action: ['cloudformation:TagResource', 'cloudformation:UntagResource'],
            Resource: { 'Fn::Sub': 'arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/wildduck-spam-trainer-prod/*' },
            Condition: { 'ForAllValues:StringEquals': { 'aws:TagKeys': ['Project', 'Service'] }, Null: { 'aws:TagKeys': 'false' } },
        }]);
    });

    test('alternate resource adoption and mutation paths are explicitly denied regardless of future Allows', () => {
        expect(statements('GitHubDeployRole').filter(statement => statement.Effect === 'Deny')).toEqual([{
            Sid: 'DenyAlternateResourceManagement', Effect: 'Deny',
            Action: ['cloudformation:CreateChangeSet', 'cloudformation:ExecuteChangeSet', 'cloudformation:CreateResource', 'cloudformation:UpdateResource', 'cloudformation:DeleteResource', 'cloudformation:CreateStackRefactor', 'cloudformation:ExecuteStackRefactor', 'cloudformation:ImportStacksToStackSet'],
            Resource: '*',
        }]);
    });

    test('CloudFront IAM uses supported tag conditions and an exact viewer function ARN', () => {
        const deploy = statements('GitHubDeployRole');
        const edge = deploy.filter(statement => actions(statement).some(action => action.startsWith('cloudfront:')));
        expect(edge.map(statement => statement.Sid)).toEqual(['ReadProviderListsViaCloudFormation', 'ReadDistributionDependenciesViaCloudFormation', 'CreateTaggedEdge', 'TagNewEdgeViaCloudFormation', 'ManageServiceDistribution', 'ManageViewerFunction']);
        const bySid = (sid: string) => edge.find(statement => statement.Sid === sid);
        expect(bySid('CreateTaggedEdge')).toEqual({
            Sid: 'CreateTaggedEdge', Effect: 'Allow', Action: ['cloudfront:CreateDistribution', 'cloudfront:CreateFunction'], Resource: '*',
            Condition: { StringEquals: { 'aws:RequestTag/Project': 'Email', 'aws:RequestTag/Service': 'wildduck-spam-trainer' } },
        });
        expect(bySid('TagNewEdgeViaCloudFormation')).toEqual({
            Sid: 'TagNewEdgeViaCloudFormation', Effect: 'Allow', Action: 'cloudfront:TagResource',
            Resource: [
                { 'Fn::Sub': 'arn:${AWS::Partition}:cloudfront::${AWS::AccountId}:distribution/*' },
                { 'Fn::Sub': 'arn:${AWS::Partition}:cloudfront::${AWS::AccountId}:function/wildduck-spam-trainer-prod-viewer-request' },
            ],
            Condition: { StringEquals: { 'aws:CalledViaLast': 'cloudformation.amazonaws.com', 'aws:RequestTag/Project': 'Email', 'aws:RequestTag/Service': 'wildduck-spam-trainer' } },
        });
        expect(bySid('ManageServiceDistribution')).toEqual({
            Sid: 'ManageServiceDistribution', Effect: 'Allow',
            Action: ['cloudfront:GetDistribution', 'cloudfront:GetDistributionConfig', 'cloudfront:UpdateDistribution', 'cloudfront:DeleteDistribution', 'cloudfront:ListTagsForResource', 'cloudfront:TagResource', 'cloudfront:UntagResource'],
            Resource: { 'Fn::Sub': 'arn:${AWS::Partition}:cloudfront::${AWS::AccountId}:distribution/*' },
            Condition: { StringEquals: { 'aws:ResourceTag/Service': 'wildduck-spam-trainer' } },
        });
        expect(bySid('ManageViewerFunction')).toEqual({
            Sid: 'ManageViewerFunction', Effect: 'Allow',
            Action: ['cloudfront:DescribeFunction', 'cloudfront:GetFunction', 'cloudfront:TestFunction', 'cloudfront:UpdateFunction', 'cloudfront:PublishFunction', 'cloudfront:DeleteFunction', 'cloudfront:ListTagsForResource', 'cloudfront:TagResource', 'cloudfront:UntagResource'],
            Resource: { 'Fn::Sub': 'arn:${AWS::Partition}:cloudfront::${AWS::AccountId}:function/wildduck-spam-trainer-prod-viewer-request' },
        });
        expect(bySid('ReadProviderListsViaCloudFormation')).toEqual({
            Sid: 'ReadProviderListsViaCloudFormation', Effect: 'Allow',
            Action: ['cloudfront:ListDistributions', 'cloudfront:ListFunctions', 'logs:DescribeIndexPolicies', 'logs:DescribeResourcePolicies'], Resource: '*',
            Condition: { StringEquals: { 'aws:CalledViaLast': 'cloudformation.amazonaws.com' } },
        });
        expect(bySid('ReadDistributionDependenciesViaCloudFormation')).toEqual({
            Sid: 'ReadDistributionDependenciesViaCloudFormation', Effect: 'Allow', Action: ['cloudfront:GetConnectionGroup', 'cloudfront:GetVpcOrigin'],
            Resource: [
                { 'Fn::Sub': 'arn:${AWS::Partition}:cloudfront::${AWS::AccountId}:connection-group/*' },
                { 'Fn::Sub': 'arn:${AWS::Partition}:cloudfront::${AWS::AccountId}:vpcorigin/*' },
            ],
            Condition: { StringEquals: { 'aws:CalledViaLast': 'cloudformation.amazonaws.com' } },
        });
        // CreateDistributionWithTags is an API, not an IAM action; no wildcard CloudFront actions.
        expect(edge.flatMap(actions)).not.toContain('cloudfront:CreateDistributionWithTags');
        expect(edge.flatMap(actions).some(action => action.includes('*'))).toBe(false);
    });

    test('Route53 writes only A/AAAA for the exact public name and zone; reads cannot mutate DNS', () => {
        const dns = statements('GitHubDeployRole').filter(statement => actions(statement).some(action => action.startsWith('route53:')));
        expect(dns).toEqual([
            {
                Sid: 'PublicDnsOnly', Effect: 'Allow', Action: 'route53:ChangeResourceRecordSets',
                Resource: { 'Fn::Sub': 'arn:${AWS::Partition}:route53:::hostedzone/${HostedZoneId}' },
                Condition: {
                    'ForAllValues:StringEquals': {
                        'route53:ChangeResourceRecordSetsNormalizedRecordNames': [{ Ref: 'PublicDomainName' }],
                        'route53:ChangeResourceRecordSetsRecordTypes': ['A', 'AAAA'],
                        'route53:ChangeResourceRecordSetsActions': ['CREATE', 'UPSERT', 'DELETE'],
                    },
                    Null: {
                        'route53:ChangeResourceRecordSetsNormalizedRecordNames': 'false',
                        'route53:ChangeResourceRecordSetsRecordTypes': 'false',
                        'route53:ChangeResourceRecordSetsActions': 'false',
                    },
                },
            },
            { Sid: 'ListHostedZones', Effect: 'Allow', Action: 'route53:ListHostedZones', Resource: '*' },
            { Sid: 'ReadPublicZone', Effect: 'Allow', Action: ['route53:GetHostedZone', 'route53:ListResourceRecordSets'], Resource: { 'Fn::Sub': 'arn:${AWS::Partition}:route53:::hostedzone/${HostedZoneId}' } },
            { Sid: 'PollDnsChanges', Effect: 'Allow', Action: 'route53:GetChange', Resource: { 'Fn::Sub': 'arn:${AWS::Partition}:route53:::change/*' } },
        ]);
    });

    test('covers the public provider schema read/list actions for all six edge/service resource types', () => {
        const required = {
            'AWS::CloudFront::Distribution': ['cloudfront:GetConnectionGroup', 'cloudfront:GetDistribution', 'cloudfront:GetDistributionConfig', 'cloudfront:GetVpcOrigin', 'cloudfront:ListTagsForResource', 'cloudfront:ListDistributions'],
            'AWS::CloudFront::Function': ['cloudfront:DescribeFunction', 'cloudfront:GetFunction', 'cloudfront:ListFunctions', 'cloudfront:ListTagsForResource'],
            'AWS::Route53::RecordSet': ['route53:ListHostedZones', 'route53:ListResourceRecordSets', 'route53:GetHostedZone', 'route53:GetChange'],
            'AWS::Lambda::Url': ['lambda:GetFunctionUrlConfig', 'lambda:ListFunctionUrlConfigs'],
            'AWS::Lambda::Permission': ['lambda:GetPolicy'],
            'AWS::Logs::LogGroup': ['logs:DescribeLogGroups', 'logs:ListTagsForResource', 'logs:GetDataProtectionPolicy', 'logs:DescribeIndexPolicies', 'logs:DescribeResourcePolicies'],
        };
        const allowed = statements('GitHubDeployRole').filter(statement => statement.Effect === 'Allow').flatMap(actions);
        for (const action of Object.values(required).flat()) {
            expect(allowed.some(grant => grant === action || grant === `${action.split(':')[0]}:*`)).toBe(true);
        }
        for (const action of ['logs:DescribeIndexPolicies', 'logs:DescribeResourcePolicies', 'cloudfront:ListFunctions', 'cloudfront:ListDistributions']) {
            const grant = statements('GitHubDeployRole').find(statement => actions(statement).includes(action));
            expect(grant?.Resource).toBe('*');
            expect(grant?.Condition).toEqual({ StringEquals: { 'aws:CalledViaLast': 'cloudformation.amazonaws.com' } });
        }
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
        expect(workflowText).not.toContain('PUBLIC_ENDPOINT_ENABLED');
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
        expect(Object.values(resources).filter(resource => resource.Type === 'AWS::SSM::Parameter').map(resource => resource.Properties['Name']).sort()).toEqual([
            '/wildduck-spam-trainer/prod/allowed-source-ips', '/wildduck-spam-trainer/prod/origin-secret-rotation-serial',
        ]);
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
