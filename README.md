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
      - uses: data-duke/pulsecheck-data-compliance-gate@v1
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
| `diff-cap-bytes` | no | `5000000` | Truncation threshold. |

## Outputs

| Output | Notes |
| --- | --- |
| `verdict` | `pass`, `fail`, or `needs_review` |
| `findings-count` | Number of masked findings |

---

## How it works, and what we can honestly claim

The action is a **sensor, not a rulebook**. It bakes in no rules of its own: at
run time it fetches your organization's active ruleset from PulseCheck, scans
the diff locally, masks every finding, publishes a GitHub check run, and posts
back only the verdict plus masked evidence.

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

Everything that executes on your runner is in this repository. One integration
suite is deliberately *not* mirrored here: it asserts this scanner against
PulseCheck's server-side ruleset mapping, which is not part of the action and
cannot run standalone, so it lives with that mapping in our product
repository.

This package is **not published to npm** — `package.json` carries
`"private": true` so that it cannot be, deliberately. A GitHub Action is
consumed through `uses:`, not `npm install`; the flag stops an accidental
publish and does not mean anything here is withheld.

## Versioning

Pin the major ref — `@v1` — and you receive fixes and new detections without
action on your part. The `v1` ref moves as we release; breaking changes ship as
`v2`.

`v1` is currently a **branch**, not a tag, so it will not appear in this
repository's tag list — GitHub Actions resolves `@v1` against either, and
pinning it works the same way. If you would rather pin something immutable, use
a full release tag (`@v1.0.0`) and update it deliberately.

Avoid pinning `@main`: it is our development branch and carries no stability
promise.

## Support

Questions, false positives, or a detection you think we are missing: contact
your Data Duke representative or raise an issue in this repository.

## License

[MIT](./LICENSE) © Data Duke
