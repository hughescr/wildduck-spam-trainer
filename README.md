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
2. **Origin header.** CloudFront adds `X-Origin-Verify` to every origin request. Its value is a bootstrap-generated Secrets Manager secret, inserted through a CloudFormation dynamic reference, so the value never appears in a template, output or log. Three independent layers stop a viewer from supplying it:
   - CloudFront origin custom headers override any viewer header with the same name.
   - The custom origin request policy forwards only `Content-Type` and `User-Agent`, never `x-origin-verify` or `Host`.
   - The viewer function deletes any viewer-supplied `x-origin-verify`.
3. **Lambda.** The only inbound authentication is the origin header. It is required on every route, health included. A direct request to the public Function URL without it gets a uniform 403. The Lambda never uses the source address (`requestContext.http.sourceIp`, `X-Forwarded-For`) for any decision and has no other shared secret.

There is no API Gateway, WAF or Lambda@Edge. **CloudFront Origin Access Control is deliberately not used.** With OAC, AWS requires viewers that POST to a Lambda Function URL to send an `x-amz-content-sha256` header carrying the payload hash. WildDuck's webhook sender (axios) does not send it, so OAC would break every webhook delivery. The Function URL therefore stays public (`AuthType NONE`), and the origin header authenticates CloudFront instead.

`reservedConcurrency: 5` bounds what abusive direct traffic to the public Function URL can cost. Such traffic is rejected after a hash comparison, so it stays cheap. Requests without a well-formed header never trigger a Secrets Manager call. WildDuck posts one delivery at a time, so five instances are ample. The 1024 MB memory size is an intentional floor and must not be lowered.

Anyone who can read the origin secret can call the Function URL directly and bypass the edge IP check. Readers include principals with `secretsmanager:GetSecretValue` on it, and those with `cloudfront:GetDistributionConfig`, because the resolved header value is part of the distribution configuration. Treat both permissions as sensitive. The CI deploy role has neither.

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

**Learn hand-off semantics.** The service is a pipeline between WildDuck and Rspamd: its job is to hand the message off correctly, not to judge whether Rspamd used it. The learn response is classified by HTTP status only. Its body is never read; it is cancelled so the connection is released. Any 2xx (200, 204, 208, …) means the message was handed off and is answered 200 `{"action":"trained"}`, but only once the upload has completed: the stream reached the message's real end and the request consumed every byte. A 2xx that arrives while the upload is still running is held until the upload completes or fails, bounded by the request deadline. If it fails, the answer is that failure's decision (502 for an `.eml` read failure, 503 for the deadline, `too_large` for the 25 MiB cap), or 502 `upload_incomplete` if the learn side stopped reading. An early non-2xx stops the upload and is classified by status. An interrupted upload always ends the request by error and abort, never by a normal end, so the proxy cannot mistake a partial message for a complete one. Response bodies are cancelled without waiting, so a cancel that never settles cannot hold the answer. Rspamd's 208 (already learned) and 204 (not learnable: too few or too many tokens, learn conditions) appear only as the logged outcomes `already_learned` and `not_learnable`. An error status where a later attempt can help (408, 425, 429, 5xx, and 401/403, which mean a misconfigured key) is answered 502 so WildDuck retries; every other 4xx (400, 404, 413, 415, 422, …) is permanent, so it is answered 200 `skipped` with a warning, because retrying cannot help.

| Condition | Response to WildDuck | Log level |
|---|---|---|
| Learn 2xx (any) | 200 `{"action":"trained"}`; logged outcome `trained`, or `already_learned` (208) / `not_learnable` (204) | info |
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

**Principle: reconstruct the message as it was when Rspamd originally scanned it.** Only header fields that our own pipeline adds after the scan are removed. Every header field that was, or may have been, present at scan time is preserved byte for byte, and so is the body. When unsure, preserve. A message that looks malformed is not trained at all, so Bayes never learns from doubtful data.

The raw message passes through a byte-level transform (`src/header-strip.ts`) into the learn request body (`duplex: 'half'`). The transform never decodes, re-encodes, reorders or re-folds anything. The header section is read, buffered (capped at 1 MiB) and validated before the learn request starts; the body then streams through without buffering. The rules:

1. **Post-scan fields, removed wherever they appear.** These exact names (`POST_SCAN_HEADER_NAMES`), matched case-insensitively and also with whitespace before the colon (`X-Rspamd-Score : 1`), are removed together with their folded continuation lines:
   - `X-Rspamd-Bar`, `X-Rspamd-Report`, `X-Rspamd-Score`: added by Haraka after the scan.
   - `WD-Mail-Classification`, `WD-Mail-Classification-Source`, `WD-Mail-Classification-Info`: the only three fields WildDuck adds (`lib/filter-handler.js`).
2. **Leading delivery fields, removed by position.** WildDuck prepends exactly two lines to every stored message after the scan, `Delivered-To: …` then `Return-Path: <…>`, after first stripping any leading ones. They are removed only while they are the leading header fields: if the first field is `Delivered-To` or `Return-Path`, it is removed with its continuation lines, and if the next field is the other one of the two, it is removed too (either order, at most one of each). A `Delivered-To` or `Return-Path` anywhere later in the header block is preserved. A message that does not start with them loses nothing.
3. **Malformed messages are skipped.** The learn endpoint is not called, the download is cancelled, and WildDuck gets 200 `{"action":"skipped","reason":"malformed_message"}` with a warn-level `message_malformed` log line that carries only a category code (`reason`). A message is malformed when its header section contains a bare CR (`bare_cr`, a CR not immediately followed by LF) or a NUL byte (`nul`); a line that is neither a field start (a field name of bytes 33–126 except `:`, optional spaces or tabs, then `:`) nor a continuation line after a field (`invalid_line`); a continuation line before any field (`leading_continuation`); or an mbox `From ` envelope line (`mbox_envelope`); when its header section has no field at all, because it starts with the blank separator line or is only blank lines (`no_headers`; every real message has header fields, since Haraka adds some before the Rspamd scan, and the rule is judged on the original message, before any removal); or when the message is empty (`empty`). Lines are validated in order as they arrive, so a malformed message is refused without reading the rest. A header line that ends beyond 1 MiB is `header_too_large` instead.

Valid and unchanged: CRLF, bare LF and mixed line endings; a message with headers but no blank line or body; 8-bit bytes in header values; very long lines. After the header section the body passes through byte-identical, whatever it contains; a body line that looks like a removable header survives. The output of a valid message is the original bytes minus exactly the removed fields.

**Headers deliberately preserved.** `X-Original-Rcpt`, `BIMI-Location` and `BIMI-Indicator` are added by the Haraka WildDuck plugin; whether that happens before or after the Rspamd scan depends on Haraka plugin order, so they are preserved. Third-party `X-Spam-*` fields and `X-Rspamd-*` fields other than the three listed (for example `X-Spam-Status`, `X-Spam-Flag`, `X-Spamd-Result`, `X-Rspamd-Queue-Id`, `X-Rspamd-Server`), `WD-Mail-Classification-Other` and other look-alikes are preserved, because they may have been present at scan time. So are `Received`, `Received-SPF`, `Authentication-Results`, `DKIM-*` and `ARC-*`.

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
bun run package    # serverless package with placeholders (needs a Serverless Framework login/access key)
bun run test:release
```

Tests inject `fetch`, SSM and Secrets Manager doubles and make no network calls. The smoke test runs the built artifact under Node 26. It checks the production wiring's fail-closed behavior without AWS calls, then runs spam-training passes and one malformed-message skip through Node's real `fetch` and streams against a loopback-only stand-in. The training passes cover a learn endpoint that answers after reading the body, one that sends its 200 before reading the body (the whole message must still arrive, properly ended), and one that sends a complete 200 before reading the body (`trained` only if the whole message arrived, otherwise a retry).

## Deployment and bootstrap

Main and develop pushes and their pull requests validate and build once into `dist/function.zip`. The main-only deploy job deploys that exact artifact. It uses short-lived GitHub OIDC credentials; no long-lived AWS key exists anywhere.

The administrator-owned bootstrap stack (`infra/bootstrap.yml`) owns:
- the certificate, origin secret and CloudFront edge
- DNS, the artifact bucket and both IAM roles

CI cannot modify any of these. The CI role is scoped to the `wildduck-spam-trainer-prod` stack, the `wildduck-spam-trainer-prod-webhook` function and its log group, and the artifact prefix. It has no IAM write, CloudFront, Route 53, SSM or Secrets Manager access. The application stack imports nothing from bootstrap.

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
| variable | `PUBLIC_ENDPOINT_ENABLED` | `false` until phase 3 completes, then `true` |
| variable | `DEPLOY_ENABLED` | `true`, set last |

Both CI and `scripts/deploy.sh` refuse any other parameter or secret name.

Perform the phases in this order.

**1. Bootstrap, phase 1 (no edge yet).** Create the GitHub repository, then read its immutable ID and confirm that the OIDC subject format uses IDs:

```sh
REPO_ID="$(gh api repos/hughescr/wildduck-spam-trainer --jq .id)"
gh api repos/hughescr/wildduck-spam-trainer/actions/oidc/customization/sub
aws cloudformation deploy --region us-west-2 \
  --stack-name wildduck-spam-trainer-bootstrap --template-file infra/bootstrap.yml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides "GitHubRepositoryId=$REPO_ID"
aws cloudformation describe-stacks --region us-west-2 --stack-name wildduck-spam-trainer-bootstrap --query 'Stacks[0].Outputs'
```

With `FunctionUrlOrigin` empty, this creates:
- the certificate (validated in us-east-1 via the shared provider)
- the origin secret (its value is generated by AWS and never shown)
- the artifact bucket, the execution role and the deploy role

It creates no distribution, CloudFront Function, origin request policy or DNS records.

**2. First deploy.** Set the GitHub secret and variables from the table, with `PUBLIC_ENDPOINT_ENABLED=false` and `DEPLOY_ENABLED=true` last. Push or merge to `main`. CI deploys the verified artifact, which creates the Function URL. Post-deploy verification then checks:
- the live configuration: runtime, arm64, memory floor, 25 s timeout, reserved concurrency 5, `AuthType NONE`, release description, name-only environment
- that direct Function URL requests with no header and with a fabricated header are rejected by the service itself, with a 403 and its own body

**3. Bootstrap, phase 2 (edge).** Pass the Function URL origin without its trailing slash:

```sh
FUNCTION_URL_ORIGIN="$(aws lambda get-function-url-config --region us-west-2 \
  --function-name wildduck-spam-trainer-prod-webhook --query FunctionUrl --output text | sed 's:/*$::')"
aws cloudformation deploy --region us-west-2 \
  --stack-name wildduck-spam-trainer-bootstrap --template-file infra/bootstrap.yml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides "FunctionUrlOrigin=$FUNCTION_URL_ORIGIN"
```

`aws cloudformation deploy` keeps previous values for the parameters you do not override. Before the update, verify that no other CloudFront distribution already claims the `wildduck-spam-training.rungie.com` alias. Wait for the distribution to deploy and DNS to resolve, then set `PUBLIC_ENDPOINT_ENABLED=true`. If the Function URL is ever recreated, update `FunctionUrlOrigin` again; its hostname changes.

**4. Install the training key.** See [Training key](#training-key) below. Until the key exists, `/readyz` and webhook requests answer 503.

**5. Verify the gated edge.** Re-run the workflow on `main` (`gh workflow run ci.yml --ref main`). With `PUBLIC_ENDPOINT_ENABLED=true` it additionally checks:
- `GET /healthz` returns 200 with the checked-out version, which proves CloudFront → origin header → Lambda
- a `POST /hooks/wildduck` from the GitHub runner is rejected with the edge's 403
- direct Function URL requests are still rejected

None of these probes can trigger learning. Manually, from an administrator machine (not allowlisted):

```sh
curl -sS https://wildduck-spam-training.rungie.com/healthz                    # 200 {"service":…,"status":"ok"}
curl -sS https://wildduck-spam-training.rungie.com/readyz                     # 200 {"ready":true} once the key is installed
curl -sS -o /dev/null -w '%{http_code}\n' -X POST -H 'Content-Type: application/json' \
  --data '{"ev":"probe"}' https://wildduck-spam-training.rungie.com/hooks/wildduck   # 403 from the edge
curl -sS -o /dev/null -w '%{http_code}\n' "$FUNCTION_URL_ORIGIN/healthz"     # 403 from Lambda (no origin header)
```

Optionally exercise the deployed edge function with `aws cloudfront test-function --name wildduck-spam-trainer-prod-viewer-request --if-match <ETag> --stage LIVE --event-object fileb://event.json`, using an allowlisted and a non-allowlisted `viewer.ip`.

**6. Explicitly authorized integration test.** This step trains the real Bayes database. Run it only with the owner's explicit authorization. From the mail server, an allowlisted address, first send an unsupported event. It should be acknowledged with 200 `{"action":"ignored"}`, which proves the whole chain without learning:

```sh
curl -sS -X POST -H 'Content-Type: application/json' --data '{"ev":"integration.probe"}' \
  https://wildduck-spam-training.rungie.com/hooks/wildduck
```

Next, choose a dedicated test message that is already in a test account's Junk folder. Post a `marked.spam` for its user, mailbox and UID. Expect `{"action":"trained"}`; on a repeat the logged outcome is `already_learned`. Then check the structured logs (see [Monitoring](#monitoring)).

**7. Register the WildDuck webhook.** Do this only after steps 1–6. It needs an administrator access token with `createAny` permission on `webhooks`. Keep the token in a root-only header file containing the line `X-Access-Token: <token>`, so the token is never on a command line. Omitting `user` registers the webhook for all users.

```sh
sudo curl -sS -X POST "$WILDDUCK_API/webhooks" -H @/root/wildduck-admin-token.header \
  -H 'Content-Type: application/json' \
  --data '{"type":["marked.spam","marked.ham"],"url":"https://wildduck-spam-training.rungie.com/hooks/wildduck"}'
# → {"success":true,"id":"<webhook id>"}
sudo curl -sS "$WILDDUCK_API/webhooks?type=marked.spam" -H @/root/wildduck-admin-token.header   # confirm exactly one
```

The URL is the clean URL with no query string. WildDuck must run with `webhooks.enabled`. To stop training at any time, remove the webhook with `DELETE $WILDDUCK_API/webhooks/<webhook id>`. See the WildDuck [webhooks](https://docs.wildduck.email/docs/wildduck-api/webhooks/) and [create webhook](https://docs.wildduck.email/docs/wildduck-api/create-webhook/) documentation.

`bun run package` packages locally with placeholder names and no AWS access. `bun run deploy` refuses missing settings, unexpected names and a missing build artifact. Never deploy placeholders with raw Serverless commands.

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
2. Update the bootstrap stack with a higher `OriginSecretRotationSerial`, for example `--parameter-overrides OriginSecretRotationSerial=2`. CloudFormation re-resolves a dynamic reference only when the resource itself updates. The serial is part of the distribution comment, so changing it forces CloudFront to pick up the new `AWSCURRENT` value.
3. The old value stops being accepted after the following rotation, when it drops out of `AWSPREVIOUS`.

## Source-IP allowlist

The allowlist is the bootstrap parameter `AllowedSourceIps`. It is a comma-separated list of exact IPv4/IPv6 addresses, with no spaces and no CIDR, defaulting to `54.71.178.94,2600:1f14:e8d:b300:9114:71e8:b97:39c`. Its `AllowedPattern` permits only hex digits, dots, colons and commas, so a parameter value cannot inject code into the function source. Only an administrator updating the bootstrap stack can change it; CI cannot.

```sh
aws cloudformation deploy --region us-west-2 \
  --stack-name wildduck-spam-trainer-bootstrap --template-file infra/bootstrap.yml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides "AllowedSourceIps=54.71.178.94,2600:1f14:e8d:b300:9114:71e8:b97:39c,<new address>"
```

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
- **Never use `serverless remove` as rollback.** It deletes the Function URL. A recreated URL has a new hostname, which breaks the CloudFront origin until bootstrap is updated, and the log group is deleted too.

The certificate, origin secret, distribution and artifact bucket are retained if the bootstrap stack is deleted; their removal is a separate, ordered administrative cleanup.

## Branches and releases

`develop` is the default development branch and `main` is the deployed branch. Tags are bare package versions. Initialize with `bun run gitflow:init`.

From a clean `develop`, `bun pm version patch --no-git-tag-version` (or the npm equivalent) runs the postversion workflow:
1. update the lockfile and validate
2. commit
3. finish a Gitflow release
4. merge `main` back into `develop`

Nothing pushes automatically. Inspect the status before recovering any failed release. `bun run test:release` exercises the release path in a disposable local repository.
