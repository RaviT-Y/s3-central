# ARMOR S3 publisher

This repository publishes ARMOR API/ABI check results to S3 once a day. ARMOR PR checks run on GitHub-hosted runners without AWS access, and their results stay in GitHub artifact storage. This repository's workflow then picks those artifacts up, validates them as untrusted input, and uploads only the files that pass.

```
PR (consumer repo, no AWS) ─► artifacts apichecker-reports / abichecker-reports
                                   │
              armor-s3-publisher.yml (daily, default branch of this repo)
   collect ─► validate ─► upload (AWS runner) ─► finalize
```

| Job | Runner | Credentials | What it does |
|---|---|---|---|
| `collect` | GitHub-hosted | Read-only GitHub token | For each repo in `repos.txt`, lists the ARMOR artifacts from the lookback window. It keeps only completed runs that call `armor-checker.yml` and are not yet in the ledger. It reads run and PR details from the GitHub API, then downloads the zips without opening them. |
| `validate` | GitHub-hosted | None | Checks every zip in a sandboxed process. A failed artifact is **ignored** and the next one is processed. |
| `upload` | AWS self-hosted | Runner's instance role (same as the old flow) | Re-checks the validated files and runs `aws s3 cp` to keys built only from trusted run data. |
| `finalize` | GitHub-hosted | None | Writes the job summary and saves the ledger. It **fails the run** if any artifact was ignored or could not be uploaded. Otherwise the run succeeds. |

`collect`, `validate` and `finalize` start with `scripts/assert_no_aws_credentials.sh`. That script fails the job if any AWS credentials are reachable, so untrusted artifacts are never handled on an AWS-credentialed runner.

## What "valid" means

Each artifact must pass all of these checks, or it is ignored:

- **Archive:** a real zip, at most 100 MiB to download, at most 5,000 entries. No encrypted entries, no symlinks or special files, no files with execute permission. No duplicate names, including names that differ only in case.
- **Paths:** relative and plain. No `..`, no absolute paths, no backslashes, no hidden files, no control characters. Every file must sit where the ARMOR checker writes it:
  - API (`apichecker-reports`): `metadata.json`, `incompatible_blocking.txt`, `incompatible_nonblocking.txt`, `others.txt`, and `<header>/armor_reports/...` or `<header>/debug_output/...` for headers listed in `metadata.json`.
  - ABI (`abichecker-reports`): `abi_metadata.json`, plus one `.txt` report per binary listed in it.
- **File types:** only `.json`, `.html`, `.txt` and `.log` (ARMOR's plain-text diagnostics log). The content is checked too, not just the extension:
  - it must be valid UTF-8 text with no NUL bytes;
  - it must not carry an executable, script (`#!`) or archive signature;
  - `.json` files must parse as strict JSON (no duplicate keys, no NaN, limited nesting depth).
- **Sizes:** each file at most 25 MiB and at most 300 MiB per artifact. These limits are enforced while extracting, so the sizes the zip declares are never trusted. Compression ratio above 200:1 counts as a zip bomb.
- **Schema:** `metadata.json` and `abi_metadata.json` must have exactly the expected keys and types, with status values from the ARMOR enums.
- **Provenance:** the metadata must match the run information from the GitHub API:
  - `project_url` matches the repository;
  - the run ID in the `artifacts` URL matches the run;
  - `github_event` matches the run's event;
  - `pr_number` is one of the run's pull requests;
  - `branch` is the PR's base branch (PR runs) or the pushed branch (push runs);
  - commit SHAs are consistent with the run;
  - `timestamp` falls inside the run.

  Newer armor-checkers releases add `repository`, `run_id`, `run_attempt` and `run_head_sha`, which are checked when present.

Report contents are only ever treated as data. Nothing from an artifact is executed, and nothing from an artifact is used to build an S3 key apart from the allowlisted relative file path.

## S3 layout

The layout is the same as the old in-PR upload:

```
s3://<bucket>/<YYYY>/<MM>/<DD>/<HH>/github.com/<owner>/<repo>/<ref>/<run_id>/files/...
```

- The date and hour come from the workflow run's `created_at` (UTC).
- `<ref>` is `<pr_number>/merge` for PR runs, or the branch name for push runs.
- `files/` holds the API report tree and `abi_metadata.json`.
- ABI per-binary reports go to `files/abi_reports/`.
- A trusted `publish-manifest.json` sits next to `files/`. It records the source run, the GitHub artifact IDs and digests, and the SHA-256 of every uploaded object.

Keys are deterministic, so uploading a run again only overwrites the same objects.

## Not processing runs twice

`finalize` saves an `armor-publisher-ledger` artifact (`ledger.json`). The next run reads it from the most recent earlier run of this workflow on the default branch.

- **Published and ignored artifacts** are recorded. That run is not looked at again unless it is re-run, in which case the newer attempt is processed.
- **Errors** (downloads or uploads) are not recorded, so the next run retries them.
- **In-progress runs** are left for a later run.

The default lookback is 48 hours. With one run a day, one missed or late day is covered.

## Setup

1. **Repository:** keep it **private**. Protect the default branch and require reviews.
   - In a public repo, GitHub disables scheduled workflows after 60 days without activity.
   - In a public repo, fork PRs could also target the AWS runner.
2. **`repos.txt`:** one `owner/repo` per line, `#` for comments. Artifact names are the same in every repo, so nothing else is needed.
3. **AWS runner for `upload`:**
   - Register a self-hosted runner whose instance role can `s3:PutObject` to the bucket, with label `armor-s3-upload`. To use a different runner, set the `ARMOR_S3_UPLOAD_RUNS_ON` variable.
   - Restrict its runner group to this repository and, if your plan supports it, to this workflow.
   - The runner needs `python3` (3.8 or newer), the AWS CLI, and a runner version that supports Node 24 actions.
4. **Variables** (*Settings → Secrets and variables → Actions → Variables*). All are optional:

   | Variable | Default | Purpose |
   |---|---|---|
   | `ARMOR_S3_UPLOAD_RUNS_ON` | `["self-hosted", "armor-s3-upload"]` | Runner for the upload job (JSON) |
   | `ARMOR_S3_BUCKET` | `qli-prd-armor-gh-artifacts` | Target bucket |
   | `ARMOR_S3_BUCKET_OWNER` | – | 12-digit account ID that must own the bucket (`--expected-bucket-owner`) |
   | `ARMOR_CHECKER_WORKFLOWS` | `qualcomm/armor-checkers/.github/workflows/armor-checker.yml` | Reusable workflow(s) a run must call to count as an ARMOR run |
   | `ARMOR_PUBLISHER_APP_CLIENT_ID` | – | GitHub App client ID (see below) |
   | `ARMOR_PUBLISHER_APP_OWNER` | this repo's owner | Org where the App is installed |

5. **GitHub App (only if needed):**
   - By default the workflow's own `GITHUB_TOKEN` reads the public consumer repos.
   - If the run summary shows `github-api-error` or `artifact-download-failed` for every repo, create a GitHub App with **Actions: read** and **Pull requests: read**. Install it on the consumer repos.
   - Then set `ARMOR_PUBLISHER_APP_CLIENT_ID` and the secret `ARMOR_PUBLISHER_APP_PRIVATE_KEY`.

## Running it

- **Daily:** the schedule runs at 03:17 UTC.
- **Manual (*Run workflow*):** `lookback-hours` sets how far back to look. Raise it to backfill, up to 2160 hours (artifact retention).
- **Dry run:** `dry-run` validates everything and prints the S3 keys, but uploads nothing and leaves the ledger unchanged. It runs entirely on GitHub-hosted runners.
- **Reading results:** the job summary lists every artifact with its result (`published`, `ignored` or `error`) and a reason code.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests build valid and malicious artifacts in code. They cover path traversal, symlinks, executables, disguised scripts and binaries, nested archives, zip bombs, encrypted entries, schema and provenance mismatches, S3 key safety, the ledger, a tampered bundle, and the token-free artifact redirect.

## Residual risk

ARMOR results from a PR are produced by that PR's own job (the ABI build script comes from the PR). Validation guarantees three things: the data has the right shape, it is attributed to the right run, and it can only land in that run's own S3 path. It cannot prove the results are true. `publish-manifest.json` marks fork PRs (`is_fork`) so downstream users can filter them.
# s3-central
