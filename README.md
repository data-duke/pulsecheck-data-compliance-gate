# PulseCheck Data Compliance Gate

A GitHub Action that reviews every pull request for **personal-data risk** —
unredacted PII in seeds and fixtures, credentials pointing at a personal-data
store, PII in logs and URLs, removed safeguards, newly added tracking SDKs —
and reports a pass / fail check before the code merges.

**Your code never leaves your CI.** The scan runs entirely on your own runner.
Raw pull request text, the raw diff, and any personal data found in it are
never transmitted to PulseCheck and never stored by us. Only a verdict and
*masked* evidence come back.

---

## Quick start

1. In PulseCheck, go to **Organization Settings → CI Gate** and create a CI
   token.
2. In the repository you want to protect, add the token as a secret:
   **Settings → Secrets and variables → Actions → New repository secret**,
   named `PULSECHECK_TOKEN`.
3. Add `.github/workflows/data-compliance.yml`:

```yaml
name: Data Compliance Gate
on:
  pull_request:
permissions:
  contents: read
  pull-requests: read
  checks: write # required to publish the check run
jobs:
  data-compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: data-duke/pulsecheck-data-compliance-gate@v2
        with:
          pulsecheck-token: ${{ secrets.PULSECHECK_TOKEN }}
```

That is the whole installation. There is nothing to substitute — the action
resolves from this repository, and your own repository is supplied
automatically by the workflow context.

### Make it block merges

Mark the **“Data Compliance Gate”** check as required:
**Settings → Branches → branch protection → Require status checks**.

Do this only once you have seen the gate report on a few pull requests — a
required check that has never reported will block every merge on the branch.

---

## Behaviour

| Situation | Result |
| --- | --- |
| Blocking finding (`fail`) | check run `failure` + the step fails → merge blocked |
| Needs review | check run `neutral` (advisory) — surfaced, not blocked |
| Clean (`pass`) | check run `success` |
| **No token** | **inert** — no scan, no check run, no verdict |
| **PulseCheck unreachable** | `needs_review` + `neutral` check + a warning — never a silent pass, and never a hard block because of an outage on our side |
| Diff larger than `diff-cap-bytes` | truncated, floored to `needs_review`, with a warning |

## Inputs

| Input | Required | Default | Notes |
| --- | --- | --- | --- |
| `pulsecheck-token` | yes | — | Your `ci_live_*` token. With no token the action is inert. |
| `pulsecheck-url` | no | PulseCheck production | Override for self-hosted deployments. |
| `github-token` | yes | `${{ github.token }}` | Reads the diff and publishes the check run. |
| `pr-number` | no | — | Scan this pull request instead of the event's. Works for **merged** PRs — see Backfill below. |
| `publish-check-run` | no | `true` | Set `false` to record the verdict without publishing a check run. |
| `diff-cap-bytes` | no | `5000000` | Truncation threshold. |
| `fail-on` | no | `Data Compliance` | Frameworks whose `fail` verdict fails the step, comma-separated, case-insensitive (`none` never fails it). See Multiple frameworks below. Ignored in baseline mode. |
| `scan-mode` | no | `pr` | `pr` scans a pull request (everything above). `baseline` builds the AI usage inventory instead — see Baseline scan below. Any other value fails the step. |
| `baseline-sample-paths` | no | `false` | Baseline mode only: `true` also sends up to 3 example file paths per detection. |

### Multiple frameworks

The action asks PulseCheck for the rulesets enabled for your organisation and scans each one **independently**: its own rules, its own verdict, its own check run. Every organisation gets the original **Data Compliance** (GDPR) ruleset, published as the check run `Data Compliance Gate`, exactly as before. An organisation that switches on **AI change control (EU AI Act)** in PulseCheck (Organization settings → CI Gate; beta) also gets an EU AI Act ruleset, published as the advisory check `PulseCheck · AI change control`.

- Each additional framework publishes its own check run (for example `PulseCheck · AI change control`).
- A framework that `fail-on` does **not** list is advisory: its check run is shown but never concludes `failure`, so it cannot block a merge by itself. List it (`fail-on: Data Compliance, EU AI Act`) to make its `fail` verdict fail the step.
- A server that predates multiple frameworks is handled transparently: its single ruleset is read as Data Compliance.
- The action sends the repository name (`owner/repo`) and announces the `context` capability, so PulseCheck can say whether the repository is linked to a registered AI system. The context it returns holds two yes/no answers and a version number, never a name or an id; it only lowers how a finding is graded (review → advise), never which lines match.
- If PulseCheck cannot serve a ruleset in a run, or records only part of a verdict, the action says so in a warning.
- Findings are signals to review, not a legal conclusion.

### Backfill: scanning pull requests that already merged

Everything downstream already worked for merged pull requests — the diff endpoint
serves them, the scanner does not care, and verdicts are recorded against a PR number.
Only the input was missing, so you could not ask "what would this ruleset have said
about our last six months?" without merging something first.

```yaml
on:
  workflow_dispatch:
    inputs:
      pr:
        description: 'Pull request number to scan'
        required: true

jobs:
  backfill:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
      # NOTE: no `checks: write` — a backfill publishes no check run.
    steps:
      - uses: data-duke/pulsecheck-data-compliance-gate@v2
        with:
          pulsecheck-token: ${{ secrets.PULSECHECK_TOKEN }}
          pr-number: ${{ inputs.pr }}
          publish-check-run: 'false'
```

**Why `publish-check-run: 'false'` belongs on a backfill.** A check run is a claim about
a commit's *current* state. Stamping one onto a six-month-old merge rewrites history in
the GitHub UI and can re-open a required-check decision that was settled long ago. The
verdict is still recorded in PulseCheck either way — you lose nothing but the annotation.

**Scanning an open PR by number does not suppress the check run.** That is an ordinary
re-run and its check run is still wanted, so only the explicit flag turns publication off.

**One pull request per run, deliberately.** These inputs name a single PR; they are not a
bulk history sweep. One org in the field holds ~2,800 merged pull requests, so a bulk
backfill needs paging and rate-limit handling that does not belong inside a per-PR gate —
drive it from a matrix or a loop outside the action instead.

### Baseline scan (AI usage inventory)

A pull request scan only sees what changes. To find out where a repository **already** uses AI — the OpenAI client imported three years ago, the model endpoint in a config file — run the action in `scan-mode: baseline` on a schedule. It walks every tracked file of the checked-out repository, runs the EU AI Act baseline rules (AI SDK in a dependency manifest, AI SDK import, hosted model endpoint, emotion or biometric analysis API) and posts the result to PulseCheck, where **AI systems → Detected AI usage** lists repositories that use AI but are not yet covered by a registered AI system.

It needs an organization with **AI change control (EU AI Act)** switched on in PulseCheck, and its **own** CI token: in Organization settings → CI Gate choose *AI usage baseline scan (counts only)* when you generate the token (scopes `ruleset:read` and `inventory:write`, never `verdict:write`) and save it as the repository secret `PULSECHECK_BASELINE_TOKEN`. Your pull request gate token (`PULSECHECK_TOKEN`) does not carry `inventory:write`, so it cannot be reused here.

**`scan-mode` needs version 2.2.0 or later of this action.** Older releases do not know the input (GitHub logs an "Unexpected input" warning) and run their ordinary pull request scan instead, so no inventory is recorded. `@v2` picks up 2.2.0 once it is published.

```yaml
name: AI usage inventory
on:
  schedule:
    - cron: '17 3 * * 1' # weekly, Monday 03:17 UTC
  workflow_dispatch:
permissions:
  contents: read
jobs:
  inventory:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false # the action never needs the GitHub token on disk
      - uses: data-duke/pulsecheck-data-compliance-gate@v2
        with:
          pulsecheck-token: ${{ secrets.PULSECHECK_BASELINE_TOKEN }}
          scan-mode: baseline
```

**What is sent: counts only.** One row per rule and AI provider family (`openai`, `anthropic`, `google-ai`, `langchain`, … `other-ai`, `emotion-biometric` — a fixed list, never text from your code), with the number of matching lines, plus the repository name, the commit SHA, how many files were scanned and whether the scan was cut short. No code line, no matched text and no file content leaves the runner.

**Sample paths are off by default.** With `baseline-sample-paths: 'true'` the action also sends up to 3 example file paths per row, so reviewers can find the code. Paths only, never content. **The paths are sent whatever your organization has decided**: the action cannot see that setting. PulseCheck stores them only if your organization has switched sample paths on (CI Gate settings) and otherwise discards them on arrival; switching the setting off later also deletes the paths already stored. If file paths must not leave the runner at all, leave `baseline-sample-paths` unset.

How it behaves:

- No pull request needed, no check run, no verdict; `fail-on` is ignored.
- Files are those `git ls-files` lists, so the `actions/checkout` step is required. Lockfiles, `dist/`, `build/`, `vendor/`, `node_modules/` and minified files are skipped, as are binary files and files over 512 KB.
- The walk stops after 5,000 files or 60 seconds. The result is still posted, marked as cut short (the counts are a lower bound), with a warning in the log.
- A scan that finds nothing tells PulseCheck the repository no longer uses AI, and its earlier detections are cleared. So a scan that could not look everywhere it should is posted as cut short instead, with a warning, and PulseCheck keeps the earlier detections: a baseline rule that could not run, or a rule whose files could not be read at all (all over 512 KB, not regular files, or a sparse or partial checkout).
- **It never fails your workflow.** PulseCheck unreachable, a token without `inventory:write`, an invalid or revoked token, an organization whose subscription or trial has ended, or an organization without AI change control: each is a log line saying which, and the step succeeds.

## Outputs

| Output | Notes |
| --- | --- |
| `verdict` | `pass`, `fail`, or `needs_review` |
| `findings-count` | Number of masked findings |
| `verdicts` | JSON object with each scanned framework's verdict, e.g. `{"Data Compliance":"pass"}` |

`verdict` and `findings-count` describe the Data Compliance (GDPR) gate, as they always have. A baseline scan sets no outputs.

---

## How it works, and what we can honestly claim

The action is a **sensor, not a rulebook**. It bakes in no rules of its own: at
run time it fetches your organization's active ruleset from PulseCheck, scans
the diff locally, masks every finding, publishes a GitHub check run, and posts
back only the verdict plus masked evidence.
For AI change control the server also returns a registry context and its SHA-256 hash; both are posted back unchanged so every stored verdict can be rebuilt from the ruleset hash, the context hash, the repository and the commit.

Because the scan runs in **your** CI, a PulseCheck audit record attests *“the
customer's CI reported this verdict”* — not that we independently verified it.
That is inherent to any client-side scanner (Snyk and GitGuardian have the same
property) and it is the price of the guarantee that your code never reaches our
systems. We would rather state it plainly than imply an assurance we cannot
give.

## Audit it yourself

The full source is in this repository, not just the built bundle, precisely so
that the claim above is checkable rather than merely asserted. `dist/` is the
committed runtime entrypoint; it is built from `src/` with:

```bash
npm install
npm test
npm run build   # ncc → dist/
```

Everything that executes on your runner is in this repository. Three
integration suites are deliberately *not* mirrored here. They test this scanner
and the report it posts against PulseCheck's server-side code: the ruleset
mapping, the EU AI Act rules as stored in the product database, and the parser
that receives a scan result. That code is not part of the action and cannot run
standalone, so the suites live with it in our product repository.

This package is **not published to npm** — `package.json` carries
`"private": true` so that it cannot be, deliberately. A GitHub Action is
consumed through `uses:`, not `npm install`; the flag stops an accidental
publish and does not mean anything here is withheld.

## Versioning

Pin the major ref — `@v2` — and you receive fixes and new detections without
action on your part. The `v2` ref moves as we release; breaking changes ship as
`v3`. `@v1` keeps working unchanged for existing users.

`v2` is currently a **branch**, not a tag, so it will not appear in this
repository's tag list — GitHub Actions resolves `@v2` against either, and
pinning it works the same way.

If you would rather pin something **immutable**, pin a commit SHA — the
strongest supply-chain pin GitHub offers, and one that can never move:

```bash
# the SHA currently behind @v2, which you can then review and pin
git ls-remote https://github.com/data-duke/pulsecheck-data-compliance-gate v2
```

```yaml
- uses: data-duke/pulsecheck-data-compliance-gate@<the SHA you reviewed>
```

Deliberately no example SHA here: a hardcoded one in documentation goes stale
and would quietly pin you to an old scanner. Note also that no `vX.Y.Z` release
tags are published yet — do not pin one, it would fail to resolve. (Which is
precisely the failure this action's own history is a lesson in: an install
instruction pointing at something that does not resolve is worse than no
instruction, because it looks like it should work.)

Avoid pinning `@main`: it is our development branch and carries no stability
promise.

## Support

Questions, false positives, or a detection you think we are missing: contact
your Data Duke representative or raise an issue in this repository.

## License

[MIT](./LICENSE) © Data Duke
