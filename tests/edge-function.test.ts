import { describe, expect, test } from 'bun:test';

/**
 * Executes the actual CloudFront Function source from infra/bootstrap.yml, with the
 * AllowedSourceIps parameter substituted exactly as Fn::Sub would, so the tested code
 * cannot drift from the deployed code.
 */
interface Template {
    Parameters: { AllowedSourceIps: { Default: string; AllowedPattern: string; MaxLength: number } };
    Resources: { ViewerRequestFunction: { Properties: { FunctionCode: { 'Fn::Sub': string }; FunctionConfig: { Runtime: string }; AutoPublish: boolean } } };
}
const template = Bun.YAML.parse(await Bun.file('infra/bootstrap.yml').text()) as Template;
const source = template.Resources.ViewerRequestFunction.Properties.FunctionCode['Fn::Sub'];
const parameter = template.Parameters.AllowedSourceIps;
const allowedPattern = new RegExp(parameter.AllowedPattern);

/** CloudFormation accepts a value only if it fully matches AllowedPattern and fits MaxLength. */
const parameterAccepted = (value: string) => value.length <= parameter.MaxLength && allowedPattern.test(value) && (allowedPattern.exec(value)?.[0] ?? '') === value;

function substitute(allowed: string): string {
    if (!parameterAccepted(allowed)) {
        throw new Error('CloudFormation would reject this parameter value');
    }
    // Fn::Sub semantics: ${Name} is replaced; ${!Literal} would become ${Literal}.
    const code = source.replace(/\$\{([^}!]+)\}/g, (_match, name: string) => {
        if (name !== 'AllowedSourceIps') {
            throw new Error(`unexpected substitution ${name}`);
        }
        return allowed;
    });
    return code;
}

type Headers = Record<string, { value: string }>;
interface ViewerEvent { version: string; context: { eventType: string }; viewer?: { ip?: unknown }; request: { method: string; uri: string; querystring: Record<string, unknown>; headers: Headers; cookies: Record<string, unknown> } }
type Handler = (event: ViewerEvent) => { statusCode?: number; uri?: string; headers?: Headers };

function load(allowed = parameter.Default): Handler {
    // The deployed source is executed verbatim.
    return new Function(`${substitute(allowed)}\nreturn handler;`)() as Handler;
}

const viewerEvent = (ip: unknown, uri = '/hooks/wildduck', headers: Headers = {}): ViewerEvent => ({
    version: '1.0',
    context: { eventType: 'viewer-request' },
    viewer: { ip },
    request: { method: 'POST', uri, querystring: {}, headers: { host: { value: 'wildduck-spam-training.rungie.com' }, ...headers }, cookies: {} },
});

const forwarded = (result: ReturnType<Handler>) => result.statusCode === undefined && typeof result.uri === 'string';

describe('CloudFront viewer-request function (from the template)', () => {
    const handler = load();

    test('runs on cloudfront-js-2.0, auto-publishes, fits the 10 KB limit and uses only plain JS', () => {
        expect(template.Resources.ViewerRequestFunction.Properties.FunctionConfig.Runtime).toBe('cloudfront-js-2.0');
        expect(template.Resources.ViewerRequestFunction.Properties.AutoPublish).toBe(true);
        const code = substitute('1.1.1.1,2.2.2.2,3.3.3.3');
        // The largest list CloudFormation accepts still keeps the function under 10 KB.
        const largest = Array.from({ length: 50 }, () => 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff').join(',');
        expect(Buffer.byteLength(substitute(largest), 'utf8')).toBeLessThan(10 * 1024);
        expect(code).not.toContain('`');
        expect(code).not.toMatch(/\brequire\s*\(|\bimport\b|\bprocess\b|\bBuffer\b/);
        expect(source.match(/\$\{/g)).toHaveLength(1);
    });

    test('default allowlist admits exactly the two WildDuck addresses', () => {
        expect(forwarded(handler(viewerEvent('54.71.178.94')))).toBe(true);
        expect(forwarded(handler(viewerEvent('2600:1f14:e8d:b300:9114:71e8:b97:39c')))).toBe(true);
    });

    test('IPv6 textual variants match (case, leading zeros, :: expansion, IPv4-mapped)', () => {
        for (const ip of ['2600:1F14:0E8D:B300:9114:71E8:0B97:039C', '2600:1f14:0e8d:b300:9114:71e8:0b97:039c', '::ffff:54.71.178.94', '0:0:0:0:0:ffff:3647:b25e']) {
            expect(forwarded(handler(viewerEvent(ip)))).toBe(true);
        }
        const compressed = load('2001:db8::1,10.0.0.1');
        for (const ip of ['2001:db8::1', '2001:DB8:0:0:0:0:0:1', '2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8:0::0:1', '::ffff:10.0.0.1', '010.000.000.001']) {
            expect(forwarded(compressed(viewerEvent(ip)))).toBe(true);
        }
        const allowZeroGroups = load('2600:1F14:0E8D:0:0:0:0B97:039C');
        expect(forwarded(allowZeroGroups(viewerEvent('2600:1f14:e8d::b97:39c')))).toBe(true);
    });

    test('every other address is rejected at the edge with 403', () => {
        for (const ip of ['54.71.178.95', '54.71.178.9', '154.71.178.94', '2600:1f14:e8d:b300:9114:71e8:b97:39d', '2600:1f14:e8d:b300::', '::', '::1', '0.0.0.0', '127.0.0.1', '', 'not-an-ip', '54.71.178.94.1', '54.71.178.256', '1:2:3:4:5:6:7:8:9', '1::2::3', 'g::1', '54.71.178.94/32', '2600:1f14:e8d:b300:9114:71e8:b97:39c%eth0', '2600:1f14:e8d:b300:9114:71e8:b97:39c%25eth0', '::ffff:54.71.178.94%1', '54.71.178.94%1', undefined, null, 42]) {
            const result = handler(viewerEvent(ip));
            expect(result.statusCode).toBe(403);
            expect(result.headers?.['cache-control']).toEqual({ value: 'no-store' });
        }
        const noViewer = viewerEvent('54.71.178.94');
        delete noViewer.viewer;
        expect(handler(noViewer).statusCode).toBe(403);
    });

    test('a spoofed X-Forwarded-For (or other address headers) is ignored', () => {
        const spoofed = viewerEvent('203.0.113.7', '/hooks/wildduck', {
            'x-forwarded-for': { value: '54.71.178.94' },
            'cloudfront-viewer-address': { value: '54.71.178.94:443' },
            'x-real-ip': { value: '54.71.178.94' },
            'true-client-ip': { value: '54.71.178.94' },
        });
        expect(handler(spoofed).statusCode).toBe(403);
    });

    test('health and readiness are open to any address (exact paths only)', () => {
        for (const ip of ['203.0.113.7', '2001:db8::dead', '']) {
            expect(forwarded(handler(viewerEvent(ip, '/healthz')))).toBe(true);
            expect(forwarded(handler(viewerEvent(ip, '/readyz')))).toBe(true);
        }
    });

    test('path tricks cannot dodge the IP check', () => {
        for (const uri of ['/healthz/', '/HEALTHZ', '//healthz', '/healthz/../hooks/wildduck', '/healthz%2F..%2Fhooks%2Fwildduck', '/%68ealthz', '/healthz.', '/healthz;x', '/readyz/', '/hooks/wildduck', '/hooks/wildduck/', '//hooks/wildduck', '/HOOKS/WILDDUCK', '/hooks%2Fwildduck', '/', '', '/anything']) {
            expect(handler(viewerEvent('203.0.113.7', uri)).statusCode).toBe(403);
        }
    });

    test('viewer-supplied x-origin-verify is removed on every forwarded request', () => {
        for (const [ip, uri] of [['54.71.178.94', '/hooks/wildduck'], ['203.0.113.7', '/healthz'], ['203.0.113.7', '/readyz']] as const) {
            const result = handler(viewerEvent(ip, uri, { 'x-origin-verify': { value: 'ViewerSuppliedGuess0123456789abcdefABCDEF' } }));
            expect(forwarded(result)).toBe(true);
            expect(result.headers?.['x-origin-verify']).toBeUndefined();
            expect(result.headers?.['host']).toEqual({ value: 'wildduck-spam-training.rungie.com' });
        }
    });

    test('invalid allowlist entries are ignored rather than matching anything', () => {
        const odd = load('1.2.3,::1::2,abc,1.2.3.4');
        expect(forwarded(odd(viewerEvent('1.2.3.4')))).toBe(true);
        expect(odd(viewerEvent('1.2.3.0')).statusCode).toBe(403);
        expect(odd(viewerEvent('::1')).statusCode).toBe(403);
    });
});

describe('AllowedSourceIps parameter cannot inject code', () => {
    test('the default and ordinary lists are accepted', () => {
        expect(parameterAccepted(parameter.Default)).toBe(true);
        expect(parameter.Default).toBe('54.71.178.94,2600:1f14:e8d:b300:9114:71e8:b97:39c');
        expect(parameterAccepted('192.0.2.1')).toBe(true);
        expect(parameterAccepted('192.0.2.1,2001:db8::1,::ffff:192.0.2.2')).toBe(true);
    });

    test('injection attempts and malformed lists are rejected by AllowedPattern', () => {
        for (const value of [
            "1.2.3.4';throw 1;//",
            '1.2.3.4\'',
            '1.2.3.4"',
            '1.2.3.4\\',
            '1.2.3.4\n',
            '1.2.3.4 x',
            '1.2.3.4, 5.6.7.8',
            '1.2.3.4,',
            ',1.2.3.4',
            '1.2.3.4,,5.6.7.8',
            '${AWS::AccountId}',
            '1.2.3.4/32',
            '1.2.3.4;alert(1)',
            "'+(globalThis.x=1)+'",
            '1.2.3.4</script>',
            '',
            'a'.repeat(46),
        ]) {
            expect(parameterAccepted(value)).toBe(false);
            expect(() => substitute(value)).toThrow();
        }
    });

    test('no accepted value can terminate the string literal', () => {
        // The pattern's character class excludes every character that could end or escape the literal.
        expect(allowedPattern.source).toBe('^[0-9A-Fa-f.:]{2,45}(,[0-9A-Fa-f.:]{2,45}){0,49}$');
        for (const forbidden of ["'", '"', '\\', '\n', '\r', '`', '$', '{', '}', ';', ' ', '/', '(', ')', '+']) {
            expect(parameterAccepted(`1.2.3.4${forbidden}`)).toBe(false);
        }
    });
});
