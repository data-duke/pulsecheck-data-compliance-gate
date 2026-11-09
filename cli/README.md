# pulsecheck-gate

The PulseCheck Data Compliance Gate for **GitLab merge request pipelines**. It scans the merge request's diff on your
runner (GDPR and EU AI Act rules served by PulseCheck), reports a **masked** verdict back, and writes a GitLab **Code
Quality** report. No source code leaves the runner. GitHub pull requests are scanned by the GitHub Action
([`data-duke/pulsecheck-data-compliance-gate`](https://github.com/data-duke/pulsecheck-data-compliance-gate)), not by this command.

## Set it up

1. In PulseCheck: **Organization Settings → CI Gate**, create a CI token.
2. In your GitLab project: **Settings → CI/CD → Variables → Add variable**, name it `PULSECHECK_TOKEN`, paste the token, and
   **mask** it. Leave **Protect variable** off: a protected variable is only available to pipelines on protected branches or
   tags, so a merge request from an ordinary branch would not receive it and the gate would silently do nothing.
3. Add this job to `.gitlab-ci.yml`:

```yaml
pulsecheck-gate:
  image: node:22
  variables:
    GIT_DEPTH: "50"
    npm_config_registry: https://registry.npmjs.org/
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - CLI_DIR="$(mktemp -d)"
    - npm install --prefix "$CLI_DIR" --no-audit --no-fund @pulsecheck/gate-cli@0.1
    - "$CLI_DIR/node_modules/.bin/pulsecheck-gate"
  artifacts:
    reports:
      codequality: gl-code-quality-report.json
```

4. To block merges: **Settings → Merge requests → Merge checks → Pipelines must succeed** (Maintainer or Owner). Do this only
   once the job has run on a few merge requests: a required job that has never run blocks every merge.

## What it does

- Reads the merge request from GitLab's predefined variables (`CI_MERGE_REQUEST_IID`, `CI_MERGE_REQUEST_DIFF_BASE_SHA`,
  `CI_COMMIT_SHA`, and the merge request's project path, which for a merge request from a fork is the target project).
- Reads the diff with `git diff <base> <head>`. If the base commit is not in the clone it fetches that one commit; if it
  cannot, the run reports "needs review" with the reason and does **not** fail the job.
- Scans each framework locally and posts only masked verdicts to PulseCheck, as provider `gitlab`.
- Writes `gl-code-quality-report.json`: one issue per finding, on the file and line it was seen, with severity
  `critical` (block), `major` (review) or `minor` (advise). Findings show in the merge request's report widget.
- Exits `1` only when a framework listed in `--fail-on` fails (default: Data Compliance). It exits `0` for advisory
  findings, when PulseCheck is unreachable, when the diff cannot be read, and outside a merge request pipeline.

## Optional: a comment on the merge request

Add a second masked CI/CD variable, `PULSECHECK_GITLAB_TOKEN`: a project access token with the `api` scope and a role that
may comment on merge requests. The CLI then keeps **one** comment on the merge request (marked with a hidden tag, and only
ever updated if the same token's user wrote it) with the verdict per framework and the masked findings, updated on every
pipeline. Without the variable nothing is posted. A comment that cannot be posted is a warning: it never changes the verdict
or the exit code. The token is sent only to your GitLab instance (`CI_API_V4_URL`), never to PulseCheck or to `git`.

## Options

```
pulsecheck-gate [--fail-on "Data Compliance, EU AI Act"] [--url <host>] [--diff-cap-bytes <n>]
                [--code-quality <path> | --no-code-quality] [--provider gitlab]
```

The token is read only from `PULSECHECK_TOKEN`. There is no `--token` option on purpose: a command-line argument is visible
to every process on the runner and ends up in job traces. `PULSECHECK_URL` overrides the API host.

## Limits

GitLab behaviour here follows GitLab's documentation as read on 2026-10-15 and has been exercised with fixtures, not yet with
a live GitLab project. The merge request description is cut at 2,700 characters by GitLab; the CLI warns when it was.
Azure DevOps and Bitbucket are not supported.
