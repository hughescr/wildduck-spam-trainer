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
node_modules/.bin/serverless deploy --stage prod
