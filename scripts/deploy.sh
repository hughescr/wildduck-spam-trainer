#!/usr/bin/env bash
set -euo pipefail
: "${AWS_DEPLOYMENT_BUCKET_NAME:?Set this from the bootstrap ArtifactBucketName output}"
: "${AWS_EXECUTION_ROLE_ARN:?Set this from the bootstrap ExecutionRoleArn output}"
: "${SERVERLESS_ACCESS_KEY:?Set a Serverless Framework access key}"
: "${TRAINING_PROXY_KEY_PARAMETER:?Set the exact SSM training proxy key parameter name}"
: "${ORIGIN_VERIFY_SECRET_ID:?Set the exact origin verification secret name}"
[[ "$TRAINING_PROXY_KEY_PARAMETER" == '/wildduck-spam-trainer/prod/training-proxy-key' ]] || { echo 'Unexpected training proxy key parameter name' >&2; exit 1; }
[[ "$ORIGIN_VERIFY_SECRET_ID" == 'wildduck-spam-trainer/prod/origin-verify-key' ]] || { echo 'Unexpected origin verification secret name' >&2; exit 1; }
[[ -f dist/function.zip ]] || { echo 'Missing dist/function.zip; deploy only the verified build artifact' >&2; exit 1; }
# Parse JSON rather than text so trailing newlines in a parameter cannot be silently trimmed.
read_edge_setting() {
    aws ssm get-parameter --region us-west-2 --name "$1" --query Parameter.Value --output json 2>/dev/null |
        node -e '
            try {
                const value = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
                const match = typeof value === "string" && new RegExp(process.argv[1]).exec(value);
                if (!match || match[0] !== value) process.exit(1);
                process.stdout.write(value);
            } catch { process.exit(1); }
        ' "$2"
}
ALLOWED_SOURCE_IPS="$(read_edge_setting /wildduck-spam-trainer/prod/allowed-source-ips '^[0-9A-Fa-f.:]{2,45}(,[0-9A-Fa-f.:]{2,45}){0,49}$')" || { echo 'Invalid or unreadable source-IP allowlist' >&2; exit 1; }
ORIGIN_SECRET_ROTATION_SERIAL="$(read_edge_setting /wildduck-spam-trainer/prod/origin-secret-rotation-serial '^[0-9]{1,9}$')" || { echo 'Invalid or unreadable origin rotation serial' >&2; exit 1; }
# Use exactly the validated snapshot, not a second SSM read that could race a PutParameter.
export ALLOWED_SOURCE_IPS ORIGIN_SECRET_ROTATION_SERIAL
node_modules/.bin/serverless deploy --stage prod
