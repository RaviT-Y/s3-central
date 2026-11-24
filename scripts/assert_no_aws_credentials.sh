#!/usr/bin/env bash
# Fail if this job can reach any AWS credentials.
#
# Every publisher job except "upload" runs this first, so artifact handling can
# never happen on a runner (or with a configuration) that holds AWS access.
# Only the names of what was found are printed, never values.
set -uo pipefail

found=()

for var in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_WEB_IDENTITY_TOKEN_FILE \
           AWS_ROLE_ARN AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_CREDENTIALS_RELATIVE_URI; do
  if [[ -n "${!var:-}" ]]; then
    found+=("environment variable $var")
  fi
done

if command -v aws >/dev/null 2>&1; then
  # Resolves the full credential chain (env, files, SSO, containers, instance role).
  if AWS_METADATA_SERVICE_TIMEOUT=2 AWS_METADATA_SERVICE_NUM_ATTEMPTS=1 \
     timeout 30 aws configure export-credentials >/dev/null 2>&1; then
    found+=("aws CLI credential chain")
  fi
fi

if command -v curl >/dev/null 2>&1; then
  # EC2 instance metadata (instance profile). IMDSv2 first, then IMDSv1.
  token="$(curl -sf -m 2 -X PUT "http://169.254.169.254/latest/api/token" \
             -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)"
  headers=()
  if [[ -n "$token" ]]; then
    headers=(-H "X-aws-ec2-metadata-token: $token")
  fi
  role="$(curl -sf -m 2 ${headers[@]+"${headers[@]}"} \
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null || true)"
  if [[ -n "$role" && "$role" =~ ^[A-Za-z0-9+=,.@_-]+$ ]]; then
    found+=("EC2 instance role")
  fi
fi

if (( ${#found[@]} > 0 )); then
  echo "::error::AWS credentials are reachable in a job that handles untrusted artifacts: ${found[*]}."
  echo "::error::Only the upload job may run on an AWS-credentialed runner."
  exit 1
fi
echo "No AWS credentials reachable."
