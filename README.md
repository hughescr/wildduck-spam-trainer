# wildduck-spam-trainer

An AWS Lambda that receives WildDuck `marked.spam` / `marked.ham` webhooks at `https://wildduck-spam-training.rungie.com/hooks/wildduck` and trains the existing Rspamd Bayes classifier through the existing Nginx training proxies. The webhook URL is clean: it carries no query string and no shared secret.

## Architecture and trust chain

```
WildDuck (54.71.178.94 / 2600:1f14:e8d:b300:9114:71e8:b97:39c)
  │  POST https://wildduck-spam-training.rungie.com/hooks/wildduck
  ▼
CloudFront (custom domain, TLSv1.2_2021, http2and3, IPv6)
  │  1. viewer-request CloudFront Function: source-IP allowlist on event.viewer.ip
  │  2. origin custom header X-Origin-Verify: <Secrets Manager value>
  ▼
Lambda Function URL (AuthType NONE, reserved concurrency 5)
  │  3. constant-time check of X-Origin-Verify (AWSCURRENT or AWSPREVIOUS)
  ▼
Training proxies (X-Mail-Training-Key)
  ├─ https://wildduck-api.rungie.com/_mail-training/v1/…  (mailbox, message state, raw .eml)
  └─ https://spam.rungie.com/_mail-training/v1/learn-spam | learn-ham  (Rspamd controller)
```

1. **Edge source-IP check.** A CloudFront Function (`cloudfront-js-2.0`, viewer-request) allows a request only if `event.viewer.ip` is in the allowlist. That field is CloudFront's own TCP connection address, so viewers cannot spoof it; `X-Forwarded-For` and similar headers are never read. Both sides are normalized before comparison. The function normalizes the standard IPv4 and IPv6 text forms: IPv4 octets drop leading zeros; IPv6 is lower-cased, with `::` compression expanded, zero-padded groups accepted, embedded dotted IPv4 tails converted, and IPv4-mapped addresses compared as IPv4. Anything else, including zone IDs (`%eth0`), CIDR suffixes and out-of-range values, normalizes to nothing and never matches. Every viewer that does not match gets a 403 from the edge and never reaches Lambda.
   - **Path rule.** Only the exact URIs `/healthz` and `/readyz` skip the IP check. Every other URI needs an allowlisted viewer, however it is spelled: trailing slash, upper case, `//`, percent-encoding, dot segments. CloudFront forwards the same URI to the origin. Lambda routes on the exact raw path, so a request that skipped the IP check can only reach health or readiness. No path variant can reach the webhook route without passing the check.
2. **Origin header.** CloudFront adds `X-Origin-Verify` to every origin request. Its value is the bootstrap-generated Secrets Manager secret, inserted through a CloudFormation dynamic reference, so the value never appears in a template, output or log. Two independent layers stop a viewer from supplying it:
   - CloudFront origin custom headers override any viewer header with the same name.
   - The viewer function deletes any viewer-supplied `x-origin-verify`.
   The AWS managed origin request policy **AllViewerExceptHostHeader** (`b689b0a8-53d0-40ab-baf2-68738e2966ac`) forwards all query strings, cookies and viewer headers except `Host`; CloudFront supplies the origin's hostname instead. It also adds CloudFront protocol, device and location headers. The origin custom header still overrides a same-named viewer value.
3. **Lambda.** The only inbound authentication is the origin header. It is required on every route, health included. A direct request to the public Function URL without it gets a uniform 403. The Lambda reads only `X-Origin-Verify` from inbound headers; it does not trust `Host`, `X-Forwarded-For`, authorization, cookies or other newly forwarded viewer headers. It never uses the source address (`requestContext.http.sourceIp`) for any decision and has no other shared secret.

There is no API Gateway, WAF or Lambda@Edge. **CloudFront Origin Access Control is deliberately not used.** With OAC, AWS requires viewers that POST to a Lambda Function URL to send an `x-amz-content-sha256` header carrying the payload hash. WildDuck's webhook sender (axios) does not send it, so OAC would break every webhook delivery. The Function URL therefore stays public (`AuthType NONE`), and the origin header authenticates CloudFront instead.

`reservedConcurrency: 5` bounds what abusive direct traffic to the public Function URL can cost. Such traffic is rejected after a hash comparison, so it stays cheap. Requests without a well-formed header never trigger a Secrets Manager call. WildDuck posts one delivery at a time, so five instances are ample. The 1024 MB memory size is an intentional floor and must not be lowered.

Anyone who can read the origin secret can call the Function URL directly and bypass the edge IP check. Readers include principals with `secretsmanager:GetSecretValue` on it, and those with `cloudfront:GetDistributionConfig`, because the resolved header value is part of the distribution configuration. Treat both permissions as sensitive and grant them only where needed. CloudFormation resolves the dynamic reference with the deploy role's credentials, so the deploy role can read the secret and manage the distribution; guard the role accordingly (see [Deployment and bootstrap](#deployment-and-bootstrap)).

## HTTP behavior

Processing order: origin verification, then route and method, then a 1 MiB body cap (`isBase64Encoded` bodies are decoded first), then JSON parse, then validation.

| Request | Response |
|---|---|
| Missing or wrong `X-Origin-Verify` (any route) | 403 `{"error":"forbidden"}` |
| Origin secret cannot be loaded | 503 (fail closed) |
| `GET /healthz` | 200 `{"service":"wildduck-spam-trainer","version":"<package version>","status":"ok"}` |
| `GET /readyz` | 200 `{"ready":true}` when the training key loads, else 503 `{"ready":false}` |
| `POST /hooks/wildduck` (exact path) | see below |
| Other path | 404; wrong method on a known path: 405 with `Allow` |
| Body over 1 MiB | 413 |
| Invalid JSON, `user`/`mailbox` not a 24-hex ObjectId, `message` not a positive safe integer | 400 (WildDuck retries are pointless but harmless) |
| `ev` other than `marked.spam` / `marked.ham` | 200 `{"action":"ignored"}` |

All responses are small JSON with `cache-control: no-store`. **The service never returns 410**, because WildDuck deletes a webhook that answers 410 Gone. Every response passes through a central guard that rewrites a 410, and a test asserts this for upstream 410s at every step.

WildDuck treats only 2xx as delivered. It makes 5 delivery attempts in total (1 initial attempt and 4 retries) with exponential backoff starting at 2 s, about 30 s of cumulative backoff, one delivery at a time and without a client timeout.

One request deadline bounds the whole invocation. It is created when the invocation starts, before origin verification: 20 s, or `context.getRemainingTimeInMillis()` minus a 3 s response reserve when that is lower. Origin-secret and training-key loads, every upstream call and the message download and upload all abort at that deadline, so the total time to a response is bounded by it. A hung upstream or secret load yields a clean 503, not a Lambda timeout.

## Training logic

The proxies are reached with `redirect: 'error'` and exactly one credential, `X-Mail-Training-Key`. No WildDuck access token or Rspamd password is ever sent. Identifiers are validated before they are interpolated into paths. Base URLs are fixed in code; `TRAINING_API_BASE_URL` and `TRAINING_LEARN_BASE_URL` override them only for tests and loopback work.

**`marked.spam`**
1. Fetch the mailbox.
2. Continue only if `specialUse` is exactly `\Junk`; otherwise answer `ignored`.
3. Read and validate the raw message's header section, then stream the normalized message into `learn-spam` (see [Header normalization](#header-normalization)).

**`marked.ham`** WildDuck also emits this event when a message is merely starred, so the event alone is not a ham signal.
1. Fetch the mailbox. Ignore the event if it is `\Junk` or `\Trash`.
2. Fetch the message state. Require the returned `user`, `mailbox` and `id` to equal the event's values.
3. Ignore the event if `flagged` is true or `flags` contains `\Flagged` (case-insensitive).
4. Read and validate the raw message's header section, then stream the normalized message into `learn-ham`.

**Learn hand-off semantics.** The service is a pipeline between WildDuck and Rspamd: its job is to hand the message off correctly, not to judge whether Rspamd used it. The learn response is classified by HTTP status only. Its body is never read; it is cancelled so the connection is released. Any 2xx means the message was handed off and is answered HTTP 200, but only once the upload has completed. The body says what Rspamd did: 208 (already learned) is `{"action":"skipped","reason":"already_learned"}`, 204 (not learnable: too few or too many tokens, learn conditions) is `{"action":"skipped","reason":"not_learnable"}`, and every other 2xx (200, 201, …) is `{"action":"trained"}`. All are HTTP 200 because WildDuck must never retry them: a retry cannot change the result. A hand-off counts only once the upload has completed: the stream reached the message's real end and the request consumed every byte. A 2xx that arrives while the upload is still running is held until the upload completes or fails, bounded by the request deadline. If it fails, the answer is that failure's decision (502 for an `.eml` read failure, 503 for the deadline, `too_large` for the 25 MiB cap), or 502 `upload_incomplete` if the learn side stopped reading. An early non-2xx stops the upload and is classified by status. An interrupted upload always ends the request by error and abort, never by a normal end, so the proxy cannot mistake a partial message for a complete one. Response bodies are cancelled without waiting, so a cancel that never settles cannot hold the answer. The 208 and 204 answers are logged at info level as the outcomes `already_learned` and `not_learnable`. An error status where a later attempt can help (408, 425, 429, 5xx, and 401/403, which mean a misconfigured key) is answered 502 so WildDuck retries; every other 4xx (400, 404, 413, 415, 422, …) is permanent, so it is answered 200 `skipped` with a warning, because retrying cannot help.

| Condition | Response to WildDuck | Log level |
|---|---|---|
| Learn 2xx other than 204 and 208 (200, 201, …) | 200 `{"action":"trained"}`; logged outcome `trained` | info |
| Learn 208 (already learned) | 200 `skipped`/`already_learned`; logged outcome `already_learned` | info |
| Learn 204 (not learnable) | 200 `skipped`/`not_learnable`; logged outcome `not_learnable` | info |
| 404 from mailbox, message or `.eml` (moved or deleted since the event) | 200 `skipped`/`stale` | info |
| Not Junk / in Junk or Trash / flagged | 200 `ignored` with a reason | info |
| Identity mismatch | 200 `skipped`/`identity_mismatch` | warn |
| Malformed message (see [Header normalization](#header-normalization)); the learn endpoint is never called | 200 `skipped`/`malformed_message` | warn |
| Message over 25 MiB (`size`, `Content-Length` or counted while streaming), or learn 413 | 200 `skipped`/`too_large` | warn |
| Header section over 1 MiB; the learn endpoint is never called | 200 `skipped`/`header_too_large` | warn |
| Other permanent 4xx: lookups (`upstream_rejected`) or learn, e.g. 400, 404, 415, 422 (`learn_rejected`) | 200 `skipped` with that reason | warn |
| Network error, 5xx, 408, 425, 429 (`upstream_unreachable` / `upstream_unavailable`); a lookup 200 without `success: true` or with malformed state; `.eml` read failure (`eml_read_failed`); a learn 2xx whose upload the learn side stopped reading (`upload_incomplete`) | 502 `retry` (WildDuck retries) | error |
| Proxy 401/403 on any request (key misconfigured; the cached key is reloaded) | 502 `retry`/`proxy_auth_failed` | error |
| Timeout or request deadline, training key unavailable | 503 `retry` | error |

**Rspamd learn responses.** These come from the controller source in Rspamd 3.14 and 4.x (`src/controller.c` and `src/libstat/stat_process.c`). The stat-layer error code becomes the HTTP status. Success is 200. A same-class repeat is 208 with the Redis learn cache (the default since 1.8.3) and 404 with the SQLite cache, which this service treats as an ordinary permanent 404. A message previously learned as the opposite class is unlearned and relearned automatically, and returns 200. Unlearnable messages return 204. A bad Rspamd password is 401.

**No dedup database.** Rspamd's Bayes learn cache recognizes same-class repeats and relearns opposite-class messages. Duplicate deliveries, such as WildDuck retries after a lost response, are therefore expected and safe.

### Proxy API contract

Every request carries `X-Mail-Training-Key: <trainingProxyKey>`.

| Request | Success response |
|---|---|
| `GET https://wildduck-api.rungie.com/_mail-training/v1/users/{user}/mailboxes/{mailbox}` | `{"success":true,"id","path","specialUse"}` |
| `GET …/users/{user}/mailboxes/{mailbox}/messages/{uid}` | `{"success":true,"id":<uid>,"mailbox","user","size","flagged","flags",…}` |
| `GET …/users/{user}/mailboxes/{mailbox}/messages/{uid}/message.eml` | RFC 5322 bytes |
| `POST https://spam.rungie.com/_mail-training/v1/learn-spam` or `/learn-ham` | Rspamd controller answer |

The learn requests send `Content-Type: message/rfc822` and a chunked streaming body. Nginx limits the body to 25 MiB.

### Header normalization

**Principle: reconstruct the message as it was when Rspamd originally scanned it.** Header fields that our own pipeline adds after the scan, and the families of scan-result fields that Haraka's Rspamd hook and Rspamd itself add (including future ones), are removed. Every other header field is preserved byte for byte, and so is the body. When unsure, preserve. A message that looks malformed is not trained at all, so Bayes never learns from doubtful data.

The raw message passes through a byte-level transform (`src/header-strip.ts`) into the learn request body (`duplex: 'half'`). The transform never decodes, re-encodes, reorders or re-folds anything. The header section is read, buffered (capped at 1 MiB) and validated before the learn request starts; the body then streams through without buffering. The rules:

1. **Post-scan fields, removed wherever they appear.** Names are matched case-insensitively and also with whitespace before the colon (`X-Rspamd-Score : 1`). A removed field takes all its folded continuation lines with it. Removed are:
   - any field whose name starts with `X-Rspamd-`, `X-Spamd-` or `X-Spam-` (`POST_SCAN_HEADER_PREFIXES`). The hyphen is part of the prefix, so `X-Spam` and `X-Spammy` are kept.
   - the exact fields (`POST_SCAN_HEADER_NAMES`) `WD-Mail-Classification`, `WD-Mail-Classification-Source` and `WD-Mail-Classification-Info` (the only fields WildDuck's `lib/filter-handler.js` adds), and `BIMI-Location` and `BIMI-Indicator`.
2. **Leading delivery fields, removed by position.** WildDuck prepends exactly two lines to every stored message after the scan, `Delivered-To: …` then `Return-Path: <…>`, after first stripping any leading ones. They are removed only while they are the leading header fields: if the first field is `Delivered-To` or `Return-Path`, it is removed with its continuation lines, and if the next field is the other one of the two, it is removed too (either order, at most one of each). A `Delivered-To` or `Return-Path` anywhere later in the header block is preserved. A message that does not start with them loses nothing.
3. **Malformed messages are skipped.** The learn endpoint is not called, the download is cancelled, and WildDuck gets 200 `{"action":"skipped","reason":"malformed_message"}` with a warn-level `message_malformed` log line that carries only a category code (`reason`). A message is malformed when its header section contains a bare CR (`bare_cr`, a CR not immediately followed by LF) or a NUL byte (`nul`); a line that is neither a field start (a field name of bytes 33–126 except `:`, optional spaces or tabs, then `:`) nor a continuation line after a field (`invalid_line`); a continuation line before any field (`leading_continuation`); or an mbox `From ` envelope line as the first line (`mbox_envelope`); when its header section has no field at all, because it starts with the blank separator line or is only blank lines (`no_headers`; every real message has header fields, since Haraka adds some before the Rspamd scan, and the rule is judged on the original message, before any removal); or when the message is empty (`empty`). Lines are validated in order as they arrive, so a malformed message is refused without reading the rest. A header line that ends beyond 1 MiB is `header_too_large` instead.

Valid and unchanged: CRLF, bare LF and mixed line endings; a message with headers but no blank line or body; 8-bit bytes in header values; very long lines. After the header section the body passes through byte-identical, whatever it contains; a body line that looks like a removable header survives. The output of a valid message is the original bytes minus exactly the removed fields.

**Headers deliberately preserved.** Everything not named above is uploaded byte for byte, and so is the whole body. That includes `Authentication-Results`, `Original-Authentication-Results`, `Received`, `Received-SPF`, `DKIM-Signature`, the `ARC-*` fields, `X-Original-Rcpt`, `X-Zone-Original-Rcpt`, `WD-Mail-Classification-Other` and other look-alikes. The BIMI headers are removed because Haraka's rspamd hook runs before the WildDuck plugin generates them, whereas `X-Original-Rcpt` is kept because it is added at RCPT time, before the scan.

Tests compare the streaming transform against an independent whole-buffer reference implementation: split at every byte offset, one byte at a time, and thousands of seeded random messages (valid, malformed and oversized) with random chunkings.

## Logging

Logs are single-line JSON on stdout, never `console.*`. A typed allowlist validates every field before it is written. The allowed fields are:

- request id, delivery `id`, `ev`, `user`, `mailbox` and uid
- route, method and status
- outcome and reason (for a malformed message, only its category code)
- upstream name, upstream status and duration
- byte count and the number of removed header fields

There is no field that could carry the training key, the origin secret, header values, URLs or query strings, subjects, addresses, Message-IDs, message content or upstream bodies. Thrown errors are never serialized. Tests capture logs across success and failure paths and assert that none of these values appear.

## Local validation

Requires Bun 1.4.4 and Node 26.

```sh
bun install --frozen-lockfile --ignore-scripts
bun run validate   # typecheck, oxlint --deny-warnings, bun test, build dist/function.zip, Node 26 smoke
bun run package    # serverless package (needs the deployed bootstrap stack, see Deployment and bootstrap)
bun run test:release
```

Tests inject `fetch`, SSM and Secrets Manager doubles and make no network calls. The smoke test runs the built artifact under Node 26. It checks the production wiring's fail-closed behavior without AWS calls, then runs spam-training passes and one malformed-message skip through Node's real `fetch` and streams against a loopback-only stand-in. The training passes cover a learn endpoint that answers after reading the body, one that sends its 200 before reading the body (the whole message must still arrive, properly ended), and one that sends a complete 200 before reading the body (`trained` only if the whole message arrived, otherwise a retry).

## Deployment and bootstrap

Main and develop pushes and their pull requests validate and build once into `dist/function.zip`. The main-only deploy job deploys that exact artifact. It uses short-lived GitHub OIDC credentials; no long-lived AWS key exists anywhere.

Deployment is a single phase with two stacks.

The administrator-owned bootstrap stack (`infra/bootstrap.yml`, deployed once) owns:
- the certificate and the origin-verify secret
- the artifact bucket, the Lambda execution role and the GitHub deploy role
- two admin-owned SSM String parameters, `/wildduck-spam-trainer/prod/allowed-source-ips` and `/wildduck-spam-trainer/prod/origin-secret-rotation-serial`, set from the bootstrap parameters `AllowedSourceIps` and `OriginSecretRotationSerial`

It exports `wildduck-spam-trainer-prod-CertificateArn`, `wildduck-spam-trainer-prod-HostedZoneId` and `wildduck-spam-trainer-prod-PublicDomainName`, which the Serverless stack imports.

The Serverless stack `wildduck-spam-trainer-prod` is deployed by CI from `main`. In one deploy it creates:
- the Lambda and its Function URL
- the CloudFront viewer-request function and the CloudFront distribution, using AWS's managed AllViewerExceptHostHeader origin request policy
- the DNS A and AAAA records for `wildduck-spam-training.rungie.com`

`scripts/deploy.sh` reads the allowlist and rotation serial from SSM with the AWS CLI before invoking Serverless. It requires full matches of the bootstrap patterns, `^[0-9A-Fa-f.:]{2,45}(,[0-9A-Fa-f.:]{2,45}){0,49}$` and `^[0-9]{1,9}$`, respectively, and refuses missing, unreadable or invalid values with fixed messages only. It passes the validated snapshots through `ALLOWED_SOURCE_IPS` and `ORIGIN_SECRET_ROTATION_SERIAL`, overriding any inherited values. Serverless uses those snapshots rather than re-reading potentially changed parameters. The raw SSM fallbacks in the template support packaging; deploy through the wrapper, not raw Serverless commands. These edge settings are not Lambda environment variables.

The service imports the certificate ARN, hosted zone ID and domain name from the bootstrap exports. It resolves the origin secret by name (`ORIGIN_VERIFY_SECRET_ID`) through a CloudFormation dynamic reference. The execution role comes from bootstrap (`AWS_EXECUTION_ROLE_ARN`). Its outputs are `PublicWebhookUrl`, `DistributionId`, `DistributionDomainName` and the framework's Function URL output.

`provider.deploymentMethod` is `direct` (CreateStack/UpdateStack, no change sets) and must not be changed. An explicit Deny blocks change-set creation/execution, Cloud Control create/update/delete resource APIs, stack-refactor creation/execution and `ImportStacksToStackSet`, even if another policy later grants them. Ordinary resource import uses change sets; there is no separate ordinary-stack import action. This preserves the `aws:CalledViaLast=cloudformation.amazonaws.com` boundary on create-time CloudFront tagging by excluding alternate paths that could adopt another project's resources.

The deploy role can be assumed only by GitHub OIDC from this repository's `main` branch, with sessions of up to one hour. Its policy allows, briefly:
- CloudFormation create, update, describe, cancel and continue-rollback on the `wildduck-spam-trainer-prod` stack only, plus template validation. `TagResource` and `UntagResource` apply only to that stack, with `aws:TagKeys` restricted to `Project` and `Service` and a `Null` guard requiring tag keys. It has no `DeleteStack`; the alternate resource-management paths above are explicitly denied.
- S3 object access under `serverless/wildduck-spam-trainer/prod/` in the artifact bucket, and read access to the bucket's settings.
- `lambda:*` on the `wildduck-spam-trainer-prod-webhook` function and its versions, `logs:*` on its log group, and `iam:GetRole` / `iam:PassRole` on the execution role only, for Lambda.
- Read access to the two edge SSM parameters and to the origin secret, because CloudFormation resolves the dynamic reference with the role's credentials.
- CloudFront: creating distributions and functions only with the tags `Project=Email` and `Service=wildduck-spam-trainer`; tagging new ones only through CloudFormation; getting, updating, deleting and re-tagging only distributions tagged `Service=wildduck-spam-trainer`; managing and testing only the `wildduck-spam-trainer-prod-viewer-request` function. There are no origin-request-policy management permissions.
- Resource-provider reads: CloudFront `ListDistributions` / `ListFunctions` and Logs `DescribeIndexPolicies` / `DescribeResourcePolicies` require `Resource: '*'` and are limited to calls through CloudFormation. Distribution-handler `GetConnectionGroup` / `GetVpcOrigin` reads are limited to those resource types in this account and calls through CloudFormation. These permissions add no mutation rights for those optional distribution features. The existing function/log-group scopes cover the Lambda URL, Lambda permission and remaining Logs handler reads.
- Route 53: record changes in the `rungie.com` hosted zone limited to A and AAAA records for the public domain name, read access to that zone and change status, and `ListHostedZones` on `*` as required by the RecordSet handler.

Treat the deploy role as sensitive: it can change the edge configuration and read the origin secret. Anyone who can write to `main` controls the deployed edge function code, including its allowlist enforcement. A principal with `ssm:PutParameter` on the allowlist parameter can change the list used by the next deploy; this ability is not exclusive to administrators updating bootstrap. The deploy role itself can only read that parameter.

All taggable AWS resources carry `Project=Email` (billing) and `Service=wildduck-spam-trainer`. The bootstrap deploy command also passes `--tags Project=Email`, and the Serverless stack applies both tags through `stackTags` and `tags`. The certificate custom resource has no verified tag support, and DNS records support no tags. The deploy role's CloudFront update and delete permissions match on the `Service` tag, so do not change it.

Permission and lifecycle references: [CloudFormation SAR](https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudformation.html), [Cloud Control SAR](https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudcontrol.html), [CloudFront SAR](https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudfront.html), [Logs SAR](https://docs.aws.amazon.com/service-authorization/latest/reference/list_logs.html), [Route 53 SAR](https://docs.aws.amazon.com/service-authorization/latest/reference/list_route53.html), [public us-west-2 resource-provider schemas](https://schema.cloudformation.us-west-2.amazonaws.com/CloudformationSchema.zip), [managed origin request policies](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-managed-origin-request-policies.html), [origin custom-header precedence](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/add-origin-custom-headers.html), [isolated function testing](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/test-function.html), and [RetainExceptOnCreate](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-attribute-deletionpolicy.html).

**Required AWS exports**, from existing stacks in us-west-2: `GitHubOIDCProvider-Arn` and `CertificateAccepterLambda-Arn`.

**GitHub configuration**

| Kind | Name | Value |
|---|---|---|
| secret | `SERVERLESS_ACCESS_KEY` | Serverless Framework access key (`gh secret set SERVERLESS_ACCESS_KEY` prompts for it) |
| variable | `AWS_DEPLOY_ROLE_ARN` | bootstrap output `GitHubDeployRoleArn` |
| variable | `AWS_DEPLOYMENT_BUCKET_NAME` | bootstrap output `ArtifactBucketName` |
| variable | `AWS_EXECUTION_ROLE_ARN` | bootstrap output `ExecutionRoleArn` |
| variable | `TRAINING_PROXY_KEY_PARAMETER` | exactly `/wildduck-spam-trainer/prod/training-proxy-key` |
| variable | `ORIGIN_VERIFY_SECRET_ID` | exactly `wildduck-spam-trainer/prod/origin-verify-key` |
| variable | `DEPLOY_ENABLED` | `true`, set last |

Both CI and `scripts/deploy.sh` refuse any other parameter or secret name.

Perform these steps in order.

**1. Create the repository and read its ID.** Create the GitHub repository, then read its immutable numeric ID and confirm that the OIDC subject format uses IDs:

```sh
REPO_ID="$(gh api repos/hughescr/wildduck-spam-trainer --jq .id)"
gh api repos/hughescr/wildduck-spam-trainer/actions/oidc/customization/sub
```

**2. Deploy bootstrap once.** An administrator deploys the bootstrap stack. Nothing in CI modifies it afterwards; the administrator updates it only for the parameters described in [Source-IP allowlist](#source-ip-allowlist) and [Origin secret rotation](#origin-secret-rotation).

```sh
aws cloudformation deploy --region us-west-2 --tags Project=Email \
  --stack-name wildduck-spam-trainer-bootstrap --template-file infra/bootstrap.yml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides "GitHubRepositoryId=$REPO_ID"
aws cloudformation describe-stacks --region us-west-2 --stack-name wildduck-spam-trainer-bootstrap --query 'Stacks[0].Outputs'
```

This creates:
- the certificate (validated in us-east-1 via the shared provider)
- the origin secret (its value is generated by AWS and never shown)
- the artifact bucket, the execution role and the deploy role
- the two SSM parameters, with `AllowedSourceIps` defaulting to the WildDuck addresses and `OriginSecretRotationSerial` to `1`

Its outputs are `CertificateArn`, `HostedZoneId`, `PublicDomainName` (these three are the exports above), `OriginVerifySecretArn`, `ArtifactBucketName`, `ExecutionRoleArn` and `GitHubDeployRoleArn`. Before the first deploy, verify that no other CloudFront distribution already claims the `wildduck-spam-training.rungie.com` alias.

**3. Install the training key.** See [Training key](#training-key) below. Until the key exists, `/readyz` and webhook requests answer 503.

**4. Set the GitHub secret and variables** from the table above, with `DEPLOY_ENABLED=true` last.

**5. Release to `main`.** Follow [Branches and releases](#branches-and-releases); the first release is `minor`, giving 0.1.0. The push to `main` makes CI deploy the verified artifact. One deploy creates the Lambda, Function URL, CloudFront function, distribution and DNS records. The distribution can take several minutes to deploy, and DNS can take longer to resolve.

**6. Verify.** Post-deploy verification (`scripts/verify-deployment.mjs`) runs in CI after the deploy. It checks:
- the live configuration: runtime, arm64, memory floor, 25 s timeout, reserved concurrency 5, `AuthType NONE`, release description, name-only environment
- the stack outputs `PublicWebhookUrl`, `DistributionId` and `DistributionDomainName` exist, and the Function URL output matches the deployed Function URL
- CloudFront `TestFunction` against the viewer function's **LIVE** stage accepts `POST /hooks/wildduck` for every address in the current SSM allowlist and returns 403 for a non-listed address. These isolated function tests never send a request to Lambda and cannot trigger learning.
- `GET /healthz` on the public domain returns 200 with exactly the expected service, checked-out version and status, which proves CloudFront → origin header → Lambda. JSON `null`, arrays, primitives and malformed bodies are failed checks, not network errors. It is retried for up to about 10 minutes while DNS and CloudFront propagate.
- a `POST /hooks/wildduck` from the GitHub runner, which is not allowlisted, is rejected with the edge's 403
- direct Function URL requests with no header and with a fabricated header are rejected by the service itself, with a 403 and its own body

It also logs the `/readyz` status for information. None of these probes can trigger learning. Logs contain statuses and fixed check messages only, never addresses, response bodies, function execution logs or AWS error details. Manually, from an administrator machine (not allowlisted):

```sh
FUNCTION_URL="$(aws cloudformation describe-stacks --region us-west-2 --stack-name wildduck-spam-trainer-prod \
  --query "Stacks[0].Outputs[?ends_with(OutputKey, 'LambdaFunctionUrl')].OutputValue" --output text)"
curl -sS https://wildduck-spam-training.rungie.com/healthz                    # 200 {"service":…,"status":"ok"}
curl -sS https://wildduck-spam-training.rungie.com/readyz                     # 200 {"ready":true} once the key is installed
curl -sS -o /dev/null -w '%{http_code}\n' -X POST -H 'Content-Type: application/json' \
  --data '{"ev":"probe"}' https://wildduck-spam-training.rungie.com/hooks/wildduck   # 403 from the edge
curl -sS -o /dev/null -w '%{http_code}\n' "${FUNCTION_URL%/}/healthz"        # 403 from Lambda (no origin header)
```

**7. Explicitly authorized integration test.** This step trains the real Bayes database. Run it only with the owner's explicit authorization. From the mail server, an allowlisted address, first send an unsupported event. It should be acknowledged with 200 `{"action":"ignored"}`, which proves the whole chain without learning:

```sh
curl -sS -X POST -H 'Content-Type: application/json' --data '{"ev":"integration.probe"}' \
  https://wildduck-spam-training.rungie.com/hooks/wildduck
```

Next, choose a dedicated test message that is already in a test account's Junk folder. Post a `marked.spam` for its user, mailbox and UID. Expect `{"action":"trained"}`; on a repeat the answer is `{"action":"skipped","reason":"already_learned"}` (logged outcome `already_learned`). Then check the structured logs (see [Monitoring](#monitoring)).

**8. Register the WildDuck webhook.** Do this only after steps 1–7. It needs an administrator access token with `createAny` permission on `webhooks`. Keep the token in a root-only header file containing the line `X-Access-Token: <token>`, so the token is never on a command line. Omitting `user` registers the webhook for all users.

```sh
sudo curl -sS -X POST "$WILDDUCK_API/webhooks" -H @/root/wildduck-admin-token.header \
  -H 'Content-Type: application/json' \
  --data '{"type":["marked.spam","marked.ham"],"url":"https://wildduck-spam-training.rungie.com/hooks/wildduck"}'
# → {"success":true,"id":"<webhook id>"}
sudo curl -sS "$WILDDUCK_API/webhooks?type=marked.spam" -H @/root/wildduck-admin-token.header   # confirm exactly one
```

The URL is the clean URL with no query string. WildDuck must run with `webhooks.enabled`. To stop training at any time, remove the webhook with `DELETE $WILDDUCK_API/webhooks/<webhook id>`. See the WildDuck [webhooks](https://docs.wildduck.email/docs/wildduck-api/webhooks/) and [create webhook](https://docs.wildduck.email/docs/wildduck-api/create-webhook/) documentation.

`bun run package` resolves the two SSM parameters, so the bootstrap stack must exist first and the shell needs AWS credentials that can read them. It also needs `ORIGIN_VERIFY_SECRET_ID` set (`serverless.yml` has no default for it) and a Serverless Framework login or access key. `bun run deploy` refuses missing settings, unexpected names, a missing build artifact, failed SSM reads and SSM values that do not fully match the bootstrap patterns. Never deploy placeholders with raw Serverless commands.

## Training key

`trainingProxyKey` is an operator-created SSM SecureString at `/wildduck-spam-trainer/prod/training-proxy-key`. It is never stored in CloudFormation, source, artifacts, GitHub variables or logs. The value already exists in root-only storage on the mail server. Copy it without putting it on a command line or echoing it. Either use a root-only file:

```sh
sudo aws ssm put-parameter --region us-west-2 --name /wildduck-spam-trainer/prod/training-proxy-key \
  --type SecureString --value file:///root/path/to/training-proxy-key --overwrite
```

Or stream it from the mail server to an administrator machine:

```sh
ssh mail.example 'sudo cat /root/path/to/training-proxy-key' | aws ssm put-parameter --region us-west-2 \
  --name /wildduck-spam-trainer/prod/training-proxy-key --type SecureString --value file:///dev/stdin --overwrite
```

The key must be printable ASCII with no spaces, at least 16 characters. One trailing newline from the file is tolerated. The Lambda caches the key for five minutes. A proxy 401/403 forces a reload, rate-limited to one attempt per 10 s. If a refresh fails, the last good key stays usable for at most ten more minutes.

**Rotation.** Install the new key on the proxies so that it accepts both the old and the new key. Overwrite the parameter. Within five minutes every warm Lambda uses the new key, and no deploy is needed. Then remove the old key from the proxies. If the proxies accept only one key at a time, expect up to five minutes of 502s, which WildDuck retries for only about 30 s; schedule the change for a quiet period.

## Origin secret rotation

1. Put a new random value. It must be alphanumeric so that it is a valid header value. It is written to a root-only temporary file without echoing:

   ```sh
   umask 077; f="$(mktemp)"
   aws secretsmanager get-random-password --region us-west-2 --password-length 64 --exclude-punctuation \
     --query RandomPassword --output text | tr -d '\n' > "$f"
   aws secretsmanager put-secret-value --region us-west-2 \
     --secret-id wildduck-spam-trainer/prod/origin-verify-key --secret-string "file://$f"
   rm -f "$f"
   ```

   The new value becomes `AWSCURRENT` and the old one `AWSPREVIOUS`. The Lambda accepts both. A mismatch triggers at most one refresh per minute, and caches also expire after five minutes.
2. Update the bootstrap stack (administrator) with a higher `OriginSecretRotationSerial`. This sets the SSM parameter `/wildduck-spam-trainer/prod/origin-secret-rotation-serial`:

   ```sh
   aws cloudformation deploy --region us-west-2 --tags Project=Email \
     --stack-name wildduck-spam-trainer-bootstrap --template-file infra/bootstrap.yml \
     --capabilities CAPABILITY_NAMED_IAM \
     --parameter-overrides OriginSecretRotationSerial=2
   ```
3. Re-run the deploy workflow on `main` (`gh workflow run ci.yml --ref main`). CloudFormation re-resolves a dynamic reference only when the resource itself updates. The Serverless stack reads the serial from SSM at deploy time and carries it into the distribution comment, so a changed serial forces CloudFront to pick up the new `AWSCURRENT` value.
4. The old value stops being accepted after the following rotation, when it drops out of `AWSPREVIOUS`.

## Source-IP allowlist

The allowlist is initialized by the bootstrap parameter `AllowedSourceIps`. It is a comma-separated list of exact IPv4/IPv6 addresses, with no spaces and no CIDR, defaulting to `54.71.178.94,2600:1f14:e8d:b300:9114:71e8:b97:39c`. Its `AllowedPattern` permits only hex digits, dots, colons and commas. The bootstrap stack stores it in the SSM parameter `/wildduck-spam-trainer/prod/allowed-source-ips` with the same pattern. Before deployment, `scripts/deploy.sh` independently validates the fetched value and pins that validated snapshot for insertion into the function source, so changing the parameter's stored validation metadata cannot enable code injection through this deploy path. The pattern constrains source-code characters, not IP validity; the viewer function ignores invalid addresses, and post-deploy verification fails if an entry is not a valid address or is not accepted.

An administrator can update the bootstrap parameter as below, but any principal with `ssm:PutParameter` on this parameter can change the list picked up at the next deploy. Anyone who can write to `main` controls the edge function code itself and can change or remove its enforcement. Protect both access paths; CI's deploy role can read but not write the SSM parameter.

1. Update the bootstrap stack parameter (administrator):

   ```sh
   aws cloudformation deploy --region us-west-2 --tags Project=Email \
     --stack-name wildduck-spam-trainer-bootstrap --template-file infra/bootstrap.yml \
     --capabilities CAPABILITY_NAMED_IAM \
     --parameter-overrides "AllowedSourceIps=54.71.178.94,2600:1f14:e8d:b300:9114:71e8:b97:39c,<new address>"
   ```
2. Re-run the deploy workflow on `main` (`gh workflow run ci.yml --ref main`) so the Serverless stack picks up the new SSM value.

The function auto-publishes to the live stage. Add a new address before WildDuck starts using it, and remove an old one only afterwards.

## Monitoring

- **Lambda** (`wildduck-spam-trainer-prod-webhook`):
  - `Errors`: unhandled failures; expected to be zero.
  - `Throttles`: the reserved concurrency of 5 was exceeded, most likely by direct abusive traffic.
  - `Duration`: p99 should stay well under 20 s.
- **CloudFront:** 4xx error rate. Edge 403s are expected for scanners and are not WildDuck failures. 5xx rate.
- **Logs Insights** on `/aws/lambda/wildduck-spam-trainer-prod-webhook` (retention 14 days):

  ```
  filter event = "request_completed" and route = "/hooks/wildduck"
  | stats count() by ev, outcome, reason, status
  ```

  ```
  filter level = "error"
  | stats count() by event, reason, upstream, upstreamStatus
  ```

  ```
  filter event = "request_completed" and outcome = "forbidden"
  | stats count() by bin(1h)
  ```

  `filter event = "upstream_response" | stats avg(durationMs), max(durationMs) by upstream, upstreamStatus` shows upstream latency per proxy.

**Silent loss window.** WildDuck's retries span only about 30 s. Any outage longer than that silently loses training events: proxies down, key missing, edge misconfigured. Alert on any `level = "error"` and on `status >= 500` rather than relying on WildDuck's retries.

## Rollback

Every deploy publishes a numbered Lambda version, and the versioned artifact bucket keeps previous artifacts.

- **Normal rollback.** Revert the offending commit on `main`. CI rebuilds, verifies and deploys the previous behavior. Alternatively, download an earlier verified `lambda` artifact (`gh run download <run-id> -n lambda -D dist`) and run `bun run deploy` with the same environment as CI, from an administrator shell holding the deploy role.
- **Emergency.** Stop training immediately by deleting the WildDuck webhook, or set the function's reserved concurrency to 0. Then restore a previous published version's code with `aws lambda get-function --function-name wildduck-spam-trainer-prod-webhook:<N> --query Code.Location` followed by `update-function-code`. Follow up with a revert commit so the stack and the code agree again.
- **Allowlist or rotation changes.** Revert the bootstrap parameter (`AllowedSourceIps` or `OriginSecretRotationSerial`) and re-run the deploy workflow on `main`.
- **Never use `serverless remove` as rollback.** Removal needs an administrator because the deploy role has no `DeleteStack`. Stack deletion removes the Lambda, Function URL, DNS A/AAAA records and log group, but retains the CloudFront distribution. The public endpoint is down: the DNS records are gone and the retained distribution's origin is deleted. The distribution still claims its custom-domain alias, so a fresh deployment cannot simply recreate the stack with that alias. Retaining the distribution can also prevent its associated viewer function from being deleted; administrative cleanup may be needed to finish stack deletion.

The distribution has `DeletionPolicy: RetainExceptOnCreate` and `UpdateReplacePolicy: Retain`. If the stack operation that initially creates it rolls back (including a failed first deploy), CloudFormation deletes that newly created distribution rather than orphaning it and leaving its alias claimed. Newly created DNS records are also removed on that rollback. Once creation succeeds, later stack deletion or removal of the distribution from the template retains it; replacement retains the old distribution. Normal update rollback restores prior configuration rather than intentionally deleting a successfully created distribution. Retention is not a backup of a working endpoint or its DNS.

Before recreating a removed stack, an administrator must release the retained distribution's alias or disable and delete the distribution, detach/delete the viewer function as needed, and complete cleanup in dependency order. The certificate, origin secret and artifact bucket are retained if the bootstrap stack is deleted and also require deliberate administrative cleanup. Do not remove either stack as a rollback shortcut.

## Branches and releases

Work happens on `develop`; `main` is the deployed branch. Tags are bare package versions. Configure git flow once per clone with `bun run gitflow:init`.

From a clean `develop`, release with `bun pm version --no-git-tag-version <patch|minor|major>`. The version in `package.json` starts at 0.0.0, so the first release is `minor`, giving 0.1.0. The `postversion` script (`scripts/postversion.sh`) then:
1. updates the lockfile and validates
2. commits the version bump
3. runs `git flow release start` and `git flow release finish`, which merges to `main` and tags the version
4. merges `main` back into `develop`

Then push everything; the push to `main` triggers the CI deploy:

```sh
git push origin develop main --tags
```

Nothing pushes automatically. Inspect the status before recovering any failed release. `bun run test:release` exercises the release path in a disposable local repository.
