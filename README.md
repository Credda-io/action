# Credda

**Label an issue. Get back the fix.**

You label a bug report or a security vulnerability. Credda reproduces the
failure, diagnoses the cause, writes the patch, proves it with a test that fails
before and passes after, and hands back a diff. Opening a pull request is
`open-pull-request` below: opt-in, off by default. It proposes. It never merges.

That first sentence used to read "Credda finds the bugs and security
vulnerabilities in a company's production and QA environments". Nothing in this
Action goes looking: the workflow below is triggered by a label, and the
`issue-body` it passes is the human description everything downstream depends
on. ADR 0024 in the engine repository amends the sentence at its source.

This repository is the GitHub Action that runs it in your own CI. The product
is at [credda.io](https://credda.io), and the
[API reference](https://credda.io/reference) for the routes this Action calls
is at credda.io/reference.

**What this launcher runs today, and the promise this paragraph used to make.**
It said: "when the fix stage lands the workflow will ask for `contents: write`
and `pull-requests: write`, and this file will say so before it does." The fix
stage has landed. ADR 0019 in the engine repository put the fixer and the
verifier back on the investigation path on 2026-08-27, and on 2026-08-28 the
engine's forge delivery path was wired to open a pull request for a run that
reaches `READY_FOR_REVIEW` still carrying a patch, on either of two verdicts: a
`VERIFIED` one, or -- since 2026-08-28 -- a `PARTIALLY_VERIFIED` one whose
recorded signals prove the reported failure changed shape rather than survived.
So, saying it before it does:

**Opening a pull request needs `contents: write` and `pull-requests: write`.**
Those are the two scopes, they are what the engine's own GitHub App now asks an
operator for (`docs/setup.md` in the engine repository), and they are the ones
this file promised to name.

**This Action now opens pull requests, and the default install still asks for
neither scope.** This paragraph used to say the launcher "pushes no branch and
opens no pull request", that the proposal came from the engine's GitHub App
rather than from CI, and that the permission block would gain the two lines on
the same commit as the code. The code landed on 2026-08-29 -- `deliver-pr.mjs`,
run from this Action, on your runner, with your own `GITHUB_TOKEN` -- and this
paragraph was not corrected with it. It is corrected here, which is a day late:
a README that denies a feature the same file documents two sections down leaves
a reader to guess which half is current.

What is unchanged, and is the reason the permission block below still grants no
write scope: `open-pull-request` defaults to `'false'`. A default install pushes
no branch and opens no proposal, and its token could not if it tried. The two
scopes are yours to grant, in your own workflow, on the run you decide should
propose -- see *Opening a pull request* below.

**What the write scopes never buy, here or anywhere.** Credda does not merge.
There is no merge call in the engine and no merge method on its forge contract,
and a test fails if one appears. `pull-requests: write` opens a proposal; a
human decides.

**Honest status.** The install path is proven: a public repository outside our
organisation resolved this action, minted its OIDC token, was served the engine
with no signup and no licence, verified the digest, ran `triage` and posted its
comment. What has *not* been proven anywhere but our own repositories is
`investigate` -- the sandbox, the reproduction, the report. Treat the first
investigation in your repository as an experiment, not a service.

**What it costs.** Nothing on a public repository: there is no signup, no
account, and no key to ask us for. GitHub decides whether your repository is
public and signs that statement; we read it. A private repository needs a
licence and is refused with a `402` at the fetch step until it has one. Your own
Actions minutes are the other cost, and `investigate` spends more of them than
`triage` does.

## Five modes

| `mode` | Fires on | Cost | What arrives |
| --- | --- | --- | --- |
| `security` | **a push or a schedule. Nobody has to file anything** | a Linux runner, Docker, an install of your package in a container, minutes | a job summary of the findings an exploit proved, each with the exploit, and the same findings in your repository's code scanning alerts. With `fix` and your own model key, a patch per proven class that the check-fix gates proved, and -- if you asked for it -- a pull request for each |
| `discover` | **a push. Nobody has to file anything** | one download and one Node process, seconds | a job summary listing the defects Credda found in your code |
| `sweep` | **a push. Nobody has to file anything** | a runner, Docker, and a reproduction per candidate, minutes | a job summary, and -- if you asked for it -- a pull request per verified fix |
| `investigate` (default) | a label | a runner, Docker, an install of your repository, minutes | a reproduction report |
| `triage` | an issue being opened | one download and one Node process, seconds | a short note saying what Credda could not use in the report -- **or nothing** |

`discover` is the one that does not wait to be asked, and it is what Credda is
for: it reads your repository and reports defects nobody reported. The other two
both start from an issue somebody filed.

It **runs none of your code**. It reads source and reports what it found; it
starts no container, installs nothing from your repository, makes no model call
and needs no API key. Some of what it finds is settled by reading -- a function
that calls what its siblings guard, a declaration the code beside it
contradicts -- and the summary says so. Everything else is a **candidate**: a
question with a program attached that has not been run. The summary never calls
one of those a finding.

It **posts nothing**. No issue, no comment, no pull request. Findings go to the
job summary, because a tool whose first act is to open twenty issues gets
uninstalled the same afternoon. `stated-findings` and `candidates` are outputs,
so gating a merge on either is your decision to wire up rather than ours to
make.

```yaml
# .github/workflows/credda-discover.yml
name: Credda
on: push

permissions:
  contents: read          # read the code. It posts nothing.
  id-token: write         # mint the OIDC token that fetches the engine

jobs:
  discover:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Credda-io/action@v1
        with:
          mode: discover
```

### Security mode

`mode: security` runs Credda's exploit probes against your repository's own
code and reports a finding only when an exploit proved it. The probes cover
prototype pollution, regular expressions that take super-linear time, archive
and path traversal, credentials sent across a redirect, and signature or
certificate-chain verification bypass. It also fuzzes the package's exported
functions for about a minute, and keeps a fuzz finding only when a reproducer
proves it again in a fresh container. The probes read JavaScript and
TypeScript packages, and Python packages with a manifest at the repository
root.

Your package is installed in a container, and every probe runs in a second
container with no network, a memory cap and a timeout. npm installs with
install scripts off. pip has no such switch, so a Python package's build code
runs in the install container. Your checkout is copied first, so nothing is
written into it.

Each finding on the job summary carries the exploit program that proved it, so
anyone can run it again. Results that were not proven (clean, no verdict, or a
probe of ours that crashed) are never called findings. Their counts are on the
job summary under *What this run reached*, and the rest stays in
`security.json` on the runner.

The proven findings are also uploaded as SARIF to GitHub code scanning and
appear under the repository's Security tab. Credda stores none of them. The
file uploaded is `security.sarif`, which holds proven findings only. Unproven
patterns, when the CLI's unproven tier is on, are written to a separate
`unproven.sarif` that this action does not upload. Set `upload-sarif: 'false'`
to keep the findings on the job summary only.

```yaml
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'
permissions:
  contents: read
  id-token: write
  security-events: write
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Credda-io/action@v1
        with:
          mode: security
```

The job stays green whatever is found. The `security-findings` output counts
only proven findings, so it is safe to gate a merge on. The job goes red only
when the probes could not run, because a count of zero from a run that never
happened would read exactly like a clean repository.

#### What this run reached

Under the findings, the job summary has a *What this run reached* section. It is
built only from what the engine wrote in `security.json`: the probes and how
each ended, the functions fuzzed and the calls made, how the package was loaded
from source and which modules failed and why (engine v0.1.19 or later), the
engine's notes, and any temp directory Credda could not delete. A line the
engine wrote nothing for is left out.

- *Clean* means the probe ran against code it could drive and no exploit
  succeeded.
- *Abstained* means the probe had nothing it could drive or measure, so it says
  nothing about that class.
- *Timed out*, *crashed* and *not run* also say nothing about that class. A
  crash is Credda's failure.

The section also lists what the engine marked *NOT TESTED*, with the engine's
reason: a language whose package was never loaded (`untested`, engine v0.1.19
or later), a checkout with nothing it could scan (`unsupported`), and a scan
of a workspace root that scanned only the root (engine v0.1.19).

When a run proved nothing and reached too little to mean anything, the summary
opens with *Credda could not exercise this repository's code*, says why, and
quotes the engine. The Slack message says the same. Reach is limited when no
finding was proven and any of these holds:

1. `installed` is `false`: the package did not install.
2. there is a fuzz record and it fuzzed 0 functions.
3. at least one probe calls the package's exports (`site.kind` is `package`)
   and none of them ended clean.
4. the engine loaded the package from source and imported no module.
5. no probe ran and no function was fuzzed.

A workspace report has its own rule. See *Monorepos*.

The same facts are in the `security-reach` output as one line of JSON:

```json
{"limited":false,"functions":36,"probes":{"proven":0,"clean":18,"abstained":5,"timedOut":0,"crashed":0,"notRun":0},"sourceFiles":{"loaded":12,"failed":0},"partial":false,"packages":null}
```

- `limited` is the rule above: nothing proven, and the code could not be
  exercised.
- `partial` is true when part of what was in scope was not exercised. On a
  workspace report: at least one package was not tested or was over the cap.
  On a report of one package: the engine listed something as *NOT TESTED*. An
  engine older than v0.1.19 writes no such list, so `partial` is `false` there.
- `packages` is `null` on a report of one package. On a workspace report it
  holds the package counts: `found`, `scanned`, `exercised`, `notTested` and
  `overCap`.

A field the engine did not write is `null`. The job does not fail on either
boolean. To fail it yourself when anything was not exercised:

```yaml
      - uses: Credda-io/action@v1
        id: credda
        with:
          mode: security
      - if: fromJSON(steps.credda.outputs.security-reach).limited || fromJSON(steps.credda.outputs.security-reach).partial
        run: |
          echo "::error::Credda did not exercise all of this repository's code. See the job summary."
          exit 1
```

Gate on `limited` alone to fail only when nothing was exercised.

#### Monorepos

The engine after v0.1.19 scans every package of a workspace: `workspaces` in
package.json, `pnpm-workspace.yaml` or `lerna.json`. It installs, probes and
fuzzes at most 10 packages. The rest are over the cap: only their regular
expressions are read. v0.1.19 scans only the root, and the summary says so.

On a workspace report the job summary opens with how many packages Credda
exercised, such as *Credda exercised 3 of 30 packages*, and names the ones it
did not, each with the engine's reason. It never reads as a clean pass while a
package was not exercised. *What this run reached* counts the packages found,
scanned, exercised, not tested and over the cap, then gives one line per
exercised package and lists the rest with their reasons. Long lists are cut
and say how many are not shown; `keep-report` keeps the full `security.json`.
Each proven finding names its package. The engine starts a package's finding
ids with the package path, and that prefix is what names it.

On a workspace report, reach is limited only when no finding was proven and no
package was exercised. `installed` is `false` there when any one package did
not install, so it is not used. When some packages were exercised and some
were not, `limited` is `false` and `partial` is `true`.

**Fixes in a monorepo.** The engine attempts no fix on a workspace report. It
records each proven class as not attempted, and the *Fixes* section says that
once. Fixes run on one package at a time. This action has no input that points
it at a subdirectory: it always scans the checkout root. To have fixes
attempted for one package today, run a separate job where that package is the
checkout root:

```yaml
  fix-one-package:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          path: repo
      # The package becomes the root this action scans.
      - run: cp -R repo/packages/a/. . && rm -rf repo
      - uses: Credda-io/action@v1
        id: credda
        with:
          mode: security
          fix: 'true'
          upload-sarif: 'false'
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
      - if: steps.credda.outputs.fix-patches != ''
        uses: actions/upload-artifact@v4
        with:
          name: credda-fixes
          path: ${{ steps.credda.outputs.fix-patches }}
```

Know what this gives up. The root is no longer a git checkout, so no pull
request can be opened: a proven patch is kept in `fix-patches`, with paths
relative to the package. Turn `upload-sarif` off, because those paths would not
match the repository. A package whose dependencies are other packages of the
workspace may not install on its own; its report then says *NOT TESTED*.

#### Keeping the report: `keep-report`

`security.json` and the rest of the engine's report are deleted with the job.
`keep-report: 'true'` copies `security.json`, `security.md`, `security.sarif` and
`unproven.sarif` (when written) to a directory named in the
`security-report-path` output. This action uploads nothing itself; add the step
to your workflow:

```yaml
      - uses: Credda-io/action@v1
        id: credda
        with:
          mode: security
          keep-report: 'true'
      - uses: actions/upload-artifact@v4
        with:
          name: credda-security-report
          path: ${{ steps.credda.outputs.security-report-path }}
```

These files hold the exploit programs that proved each finding. Anyone who can
download the run's artifacts can read and run them.

#### Extra probe classes: `extra-probes`

The engine keeps three newer probe classes behind flags, each off by default.
`extra-probes` turns on the ones you name, for the `credda security` run only:

| Name | Class | Languages | Engine |
| --- | --- | --- | --- |
| `injection` | injection to execution (CWE-94, CWE-77, CWE-78, CWE-1336) | JavaScript, Python | v0.1.18 or later |
| `ssrf` | server-side request forgery (CWE-918) | JavaScript, Python | v0.1.18 or later |
| `xss` | reflected cross-site scripting (CWE-79) | JavaScript | v0.1.19 or later |

```yaml
      - uses: Credda-io/action@v1
        with:
          mode: security
          extra-probes: injection, ssrf
```

These classes are newer than the others. Each still reports only what an
exploit proved. The job summary gets an *Extra probe classes* section with one
line per name: how many of its probes ran, or that no probe of the class applied
to this repository. When the engine is older than the class, the line says it is
not available in this engine, so a missing class never reads as a clean result.
An unknown name fails the job.

#### Proposing fixes: `fix`

`fix: 'true'` asks your own model for a patch for each class of finding an
exploit proved. It needs a model key: `anthropic-api-key`, or `model-api-key`
with `model-base-url` (see *Using your own model*). The patch is applied to a
temp copy, never to your checkout, and judged by the check-fix gates: the
exploit again, a fixed list of its variants, a fuzz of the patched functions, a
functional control, and your test suite. Only a patch the engine marks
`FIX_PROVEN` is kept. It needs engine v0.1.18 or later.

The job summary gets a *Fixes* section: per class, whether the fix was proven,
rejected (and at which gate) or not attempted (and why). With no model key,
nothing is attempted, the summary says so, and the job ends exactly as it would
without `fix`.

Each proven patch is written to the directory in the `fix-patches` output, with
the pull request body beside it. With `open-pull-request: 'true'` and the two
write scopes, Credda opens one pull request per proven fix against the branch it
scanned, through the same delivery code `investigate` and `sweep` use: one
branch per class (`credda/security-fix-<class>`), no force-push, an open
proposal met with "already proposed", and the same refusals. The body states the
finding, the CWE, that the exploit fired before the patch and not after, each
gate as the engine reported it, and the engine version. A person should review
it before merging. Credda never merges. A run on a `pull_request` event scans a
merge commit, so its fixes are attached and not proposed.

```yaml
on:
  push:
    branches: [main]
permissions:
  contents: write          # push the fix branch
  pull-requests: write     # open the proposal
  id-token: write
  security-events: write
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Credda-io/action@v1
        id: credda
        with:
          mode: security
          fix: 'true'
          open-pull-request: 'true'
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
      # Without open-pull-request, keep the proven patches as an artifact.
      - if: steps.credda.outputs.fix-patches != ''
        uses: actions/upload-artifact@v4
        with:
          name: credda-fixes
          path: ${{ steps.credda.outputs.fix-patches }}
```

### Sweep mode

`sweep` is `discover` carried all the way to a proposal. It discovers the defects
nobody filed, reproduces the first `max-candidates` of them in a sandbox exactly
as `investigate` does, and -- for the ones that reach a **verified** change -- opens
**one pull request each**, through the same delivery code the single-investigate
path uses. It is the surface that lets Credda run its own loop: find, reproduce,
fix, verify, propose, with nobody labelling anything.

It **proposes nothing on a default install.** Delivery happens only when
`open-pull-request: true` **and** your workflow grants `contents: write` +
`pull-requests: write`. With `open-pull-request` off, or without those scopes,
sweep still discovers and reproduces, and the job summary says of every verified
candidate that it **would** be proposed -- nothing is pushed, and the run holds a
token that cannot write to your repository. When the scopes are missing the first
push is refused by GitHub with a message naming the two lines to add; sweep
records it, stops attempting the rest, and the job stays green.

Three guardrails hold it:

- **A hard cap.** `max-candidates` (default 3, never unbounded) is the most
  candidates one sweep reproduces, and thus the most pull requests it can open in
  a single run. A mode whose first run opens twenty pull requests gets
  uninstalled the same afternoon.
- **One idempotent pull request per finding.** Each candidate's branch is named
  deterministically and distinctly from its provenance, so a re-run on an
  unchanged tree meets its own previous branches. An existing branch with an open
  proposal is left alone and reported; a branch with no open proposal is refused
  rather than overwritten. Credda never force-pushes.
- **Credda proposes and never merges.** There is no merge call anywhere on this
  path.

```yaml
# .github/workflows/credda-sweep.yml
name: Credda sweep
on: push        # or a schedule

permissions:
  contents: write         # push each fix branch
  pull-requests: write    # open each proposal
  id-token: write         # mint the OIDC token that fetches the engine

jobs:
  sweep:
    runs-on: ubuntu-latest    # a Linux runner with Docker; sweep reproduces in a sandbox
    steps:
      - uses: actions/checkout@v4
      - uses: Credda-io/action@v1
        with:
          mode: sweep
          open-pull-request: true
          max-candidates: '3'
          # anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}   # a model-backed provider fixes far more than the heuristic one
```

Drop `open-pull-request`, `contents: write` and `pull-requests: write` and the
same workflow becomes a dry run: it discovers, reproduces, and reports on the job
summary what it would have proposed, opening nothing.

`triage` runs no repository code, starts no container, installs nothing from
your repository, makes no model call and needs no API key. It reads the issue
and renders a decline reply, and it says nothing at all unless the report
contains something specific a reporter could add. Measured over 729 real inbound
issues from 40 repositories, roughly a quarter produce a specific request and
about half contain nothing a reporter could be asked for, so **silence is the
most common outcome** rather than the exception.

**Triage never claims a bug is absent.** It executes nothing, so it establishes
nothing, and the note it posts says so in its first sentence.

## Setup

`@v1` is the tag to pin. It moves with each engine release, and today it is
the same commit as `main`. Every section of this page applies to it. The older
`v1.0.0` release pins an earlier engine, so do not pin that one.

```yaml
# .github/workflows/credda.yml
name: Credda on labeled issues

on:
  issues:
    types: [labeled]

permissions:
  contents: read   # checkout of the repository under test
  issues: write    # the one report comment
  id-token: write  # mint an OIDC token to fetch the engine -- see below
  # Not `contents: write`, and not `pull-requests: write`. Those two are what
  # opening a pull request needs, and this install opens none: `open-pull-request`
  # is off by default, so it reports and stops. See "Opening a pull request"
  # below for what turning it on costs.

jobs:
  investigate:
    if: github.event.label.name == 'credda'
    runs-on: ubuntu-latest
    timeout-minutes: 30
    # One Credda run per issue at a time. Removing and re-applying the label
    # fires this workflow again, and two runs on one issue race to comment --
    # and, with `open-pull-request` on, race to push the same branch, since the
    # branch name is derived from the issue number. `cancel-in-progress: false`
    # queues the second rather than killing a reproduction halfway through.
    concurrency:
      group: credda-issue-${{ github.event.issue.number }}
      cancel-in-progress: false
    steps:
      - uses: actions/checkout@v4
      - uses: Credda-io/action@v1
        with:
          # Named explicitly. The default, `credda,codereef`, also accepts it,
          # but the action re-checks the applied label against this input.
          label: credda
          # Optional. Without it the deterministic heuristic provider runs:
          # it reproduces and reports, and cannot reason over prose.
          # anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

Then create the label the workflow triggers on, once, from a clone of the
repository (or from anywhere, with `--repo owner/name`):

```
gh label create credda --description 'Credda reproduces this bug in a sandbox and comments what it established.'
```

That is the whole install on a public repository. No GitHub App, no webhook
endpoint, no hosting, no database, no signup, and no credential beyond the job's
own token unless you choose to add a model key.

On a **private** repository, add one more line, and without it the job fails at
the fetch step with a `402`:

```yaml
      - uses: Credda-io/action@v1
        with:
          license: ${{ secrets.CREDDA_LICENSE }}
```

`runs-on: ubuntu-latest` is not decoration: `investigate` refuses to start on a
runner where its Docker sandbox is unavailable rather than running your code on
the host.

### If your workflow says `codereefai/action@v1`

It keeps working, and you do not have to change it today.

CodeReef was renamed to Credda, and this repository was **transferred** from
`codereefai` to `Credda-io`. The transfer is the thing that matters here: GitHub
leaves a redirect behind a transferred repository, so `uses: codereefai/action@v1`
still resolves to this action, at the same tags, with the same digests. You can
check that for yourself without trusting this paragraph:

```
gh api repos/codereefai/action --jq .full_name
# Credda-io/action
```

**A transfer is what buys that, and nothing else does.** Had the new name been
stood up as a *fresh* repository next to the old one, there would be no
redirect: `codereefai/action@v1` would have kept resolving to whatever the old
repository still contained, or stopped resolving at all, and every workflow
carrying the old reference would have broken on a day its owner did not choose.
For the same reason, publishing `Credda-io/action@v1` as the install reference
*before* the transfer would have been a dead reference in a README.

The order was: transfer first, then change the docs. `Credda-io/action@v1` is
what the examples above show and what to use in new workflows. Update the old
reference at your leisure -- when you next touch the file is soon enough. The
redirect is a courtesy GitHub maintains, not a contract we control, so it is
worth doing eventually rather than never.

### Why `id-token: write`

**This is a third permission, and it is new.** Credda used to need exactly
`contents: read` and `issues: write`, and the short permission list was
advertised as a feature. It is three lines now rather than two, and that is a
real regression in that story rather than a detail to skip past.

The Credda engine is not in this repository. This repository is a *launcher*:
it downloads the engine at run time from Credda's own service, checks it
against a digest committed here, and runs it. The service has to decide whether
the job asking is entitled -- free on a public repository, licensed on a private
one -- and the way it decides is a **GitHub Actions OIDC token**. With
`id-token: write`, the job can ask GitHub for a short-lived token stating which
repository is running, who owns it, and whether it is public or private. GitHub
signs those statements; Credda checks the signature.

What `id-token: write` grants:

- the ability for **this job** to **mint** a token that says which repository it
  is. That is the whole of it.

What it does not grant:

- no read or write access to your code, issues, packages or secrets;
- no access for Credda to your repository -- the token travels from your
  runner to our service and proves your identity to us, never ours to you;
- no use anywhere else: it is minted for Credda's audience and is rejected by
  any other service, and a token you already mint for AWS or Vault is rejected
  by ours.

The alternatives were worse. A download token issued with your licence is a
bearer secret sitting in a workflow file, and it leaks the first time somebody
pastes that file into a gist. A private container image pulled with a shared
credential is the same secret in a different wrapper, and per-customer registry
access does not scale past a handful of customers. OIDC distributes nothing, so
there is nothing to leak.

**If you would rather not grant it**, see *Running without depending on
Credda* below -- mirroring the artifact removes the OIDC step entirely.

### What happens when Credda is down

**Your job does not start.** That is the second cost of the same change and it
deserves to be blunt: before the engine moved out of this repository, nothing
Credda operated could stop your build. Now our service is in front of every
run.

When it happens the failure names itself. The step is called *Fetch and verify
the Credda engine* and the message says whose problem it is:

```
Credda could not reach its engine service at https://backend.credda.io/v1/engine
(<the network error>). This is an outage on our side or a network problem on the
runner, not a problem with your repository.
```

The download is attempted **three times** -- so twice more after the first
failure, two seconds apart and then four -- before the job fails. Only timeouts,
`408`, `429` and `5xx` are retried. A refusal is not: if the service answers
`402` because a private repository has no licence, re-asking cannot change the
answer, and the sentence the job prints is the one the service wrote rather than
one this action guessed.

**Nothing else about Credda changed:** the metering receipt still fails open
and still cannot redden a build (see *It cannot break your job*). Only the
engine download is load-bearing, because it is the code itself.

### Running without depending on Credda

Mirror the artifact once, and no request is made to Credda at all -- not for
the engine, not for a token -- and `id-token: write` is not needed:

```yaml
- uses: Credda-io/action@v1
  with:
    engine-archive: /opt/credda/engine-v0.1.1.tar.gz
```

The path is read on the runner, so getting the file there is your step, not
ours: a checkout, an `actions/cache` restore, an `aws s3 cp`, whatever you
already use. The version in the file name has to be the one the tag you pinned
expects -- `engine.lock.json` in this repository names it, and today it is
`v0.1.1`.

The mirrored copy is verified against the **same** digest in the same
`engine.lock.json`, so this removes the availability dependency and weakens
nothing. The artifact for a given tag is byte-stable, so mirroring is a copy
rather than a subscription. Ask us for the artifact matching the tag you pin.

### How the engine gets here, and why you can trust it

The thing this launcher must never get wrong is that it downloads code and then
executes it inside your checkout, in a job holding your `GITHUB_TOKEN`. So:

1. `engine.lock.json` in **this repository** pins the SHA-256 of the engine
   archive and of every file inside it. It arrives with the tag you pinned, over
   git, in the same commit as the code that reads it. The server's own answer is
   never consulted for the decision.
2. The archive is downloaded **into memory** and hashed. On a mismatch the job
   fails and **nothing is written to disk and nothing is executed**.
3. It is unpacked in memory by a reader that can only produce files the lockfile
   already names -- no symlinks, no absolute paths, no traversal, no extras.
4. Every file is hashed against its own pinned digest.
5. Only then is anything written.

There is no flag that skips any of this. The consequence, stated plainly: if our
service, our storage, or the network between them were compromised, an attacker
could **stop** your job and could not make it run anything.

The honest note in the other direction: the engine is not secret from you.
Anything that runs on your runner is readable by you, by construction. Keeping
it out of a public repository stops casual copying and makes the paid tier
enforceable; it is not a claim that the code is hidden from the people running
it.

### Adding the triage job

A second job in the same workflow, on the same trigger block. Both jobs want the
same permissions and the same token, and both carry the **same** `concurrency`
group -- the one already on the investigate job above, keyed on the issue
number. That is what stops a triage run and an investigation racing to comment
on one issue, and it only does it if both jobs name the same group: a group on
one job alone serialises that job against itself and nothing else.

```yaml
on:
  issues:
    types: [labeled, opened]   # `opened` is what arms triage

jobs:
  triage:
    if: github.event.action == 'opened'
    runs-on: ubuntu-latest
    timeout-minutes: 10
    concurrency:
      group: credda-issue-${{ github.event.issue.number }}
      cancel-in-progress: false
    steps:
      # Optional. Without it triage still runs; with it, a refusal can say
      # "this repository holds no `repro.js`" instead of staying quiet.
      - uses: actions/checkout@v4
      - uses: Credda-io/action@v1
        with:
          mode: triage
```

An issue that is opened *already carrying* the trigger label gets no triage
note: an investigation is about to run on it, and one thread does not need two
bots. The other order -- opened, then labelled later -- cannot be prevented,
because the note is already posted; the note names the label that runs the full
investigation, so the report that arrives later is the follow-up it pointed at.

> **Pin a tag.** A branch is whatever was last pushed to it, and pinning one
> means agreeing in advance to run code nobody has shown you, in your own
> repository, with your own token. Pin `@v1`, or a commit SHA.

### Why you create the label rather than the workflow creating it for you

Creating a label needs only the `issues: write` this workflow already has, so
the permission is not what stops it. The timing is. This workflow runs *because*
a label was applied, so a step that created the label would run strictly after
the one moment it was needed -- the first person to reach for `credda` still
has to type it into an empty label picker. Anything that fixes that has to fire
on an earlier event, such as a small `ensure-label` job on `workflow_dispatch`
and on pushes that touch the workflow file. The one-line `gh` command above buys
the same thing for a repository that would rather keep the workflow to one
trigger.

## Inputs

| Input | Default | What it does |
| --- | --- | --- |
| `mode` | `investigate` | `investigate` reproduces a labelled issue; `triage` reads a newly opened one; `discover` reads the repository and reports what nobody filed; `sweep` discovers, reproduces, and opens a pull request per verified fix; `security` runs exploit probes and reports only proven findings. |
| `upload-sarif` | `'true'` | **Security mode only.** Uploads proven findings to GitHub code scanning. Needs `security-events: write`. A refused upload does not fail the job. |
| `extra-probes` | `''` | **Security mode only, opt-in.** A comma-separated list of `injection`, `ssrf` and `xss`, the probe classes the engine keeps behind flags. An unknown name fails the job. See *Extra probe classes*. |
| `fix` | `'false'` | **Security mode only, opt-in.** Asks your own model for a patch per proven finding class and keeps only a patch the check-fix gates prove. Needs a model key. With `open-pull-request` on, opens a pull request for each fix the gates proved. See *Proposing fixes*. |
| `keep-report` | `'false'` | **Security mode only, opt-in.** Copies `security.json`, `security.md` and the SARIF files to the directory in `security-report-path`, for your own `actions/upload-artifact` step. They hold the exploit programs. See *Keeping the report*. |
| `max-files` | `'4000'` | In `discover` and `sweep` mode, the most source files to read. Ignored by the other modes. |
| `max-candidates` | `'3'` | **Sweep mode only.** The most discovered candidates one sweep reproduces and proposes -- a hard cap on the pull requests a single run can open. Never unbounded. |
| `label` | `credda,codereef` | Comma-separated list of labels that trigger an investigation (`*` accepts any). The default carries both names through the CodeReef -> Credda rename; `credda` is the one Credda names when it invites a maintainer to apply a label. In triage mode, the labels Credda stays quiet for. |
| `sandbox` | `docker` | Execution plane for repository code. `docker` is the only isolated plane, and needs a Linux runner. |
| `anthropic-api-key` | `''` | Optional. Without it the deterministic heuristic provider runs. Pass a secret. |
| `model-base-url` | `''` | Optional. Base URL of your own OpenAI-compatible endpoint, such as a vLLM server. See *Using your own model*. |
| `model-api-key` | `''` | Optional. Key for that endpoint. Required when either other `model-` input is set. Pass a secret. |
| `model-name` | `''` | Optional. Model id the endpoint serves. Empty uses `qwen/qwen2.5-coder-32b-instruct`. |
| `github-token` | `${{ github.token }}` | Posts the report comment, and -- only when `open-pull-request` is on -- makes the `gh` calls that open the proposal. The branch itself is pushed with the credential `actions/checkout` persisted, not with this value, so passing your own token here changes who opens the pull request and not who pushes the branch. |
| `comment` | `'true'` | `true` comments when something was established, `always` comments regardless, `false` never. |
| `open-pull-request` | `'false'` | **Opt-in, off by default.** `true` commits a *verified* fix to a branch and opens a pull request. Requires you to grant `contents: write` and `pull-requests: write` on your own `GITHUB_TOKEN`. A run that did not produce a verified fix opens nothing. See *Opening a pull request*. |
| `notify-url` | `''` | **Opt-in, off by default.** A URL to POST the run's facts to when it established something or stated a finding. A `hooks.slack.com` URL gets one sentence in Slack's `{text}` shape. Sent from your runner to your URL; nothing reaches Credda, and the report itself is never sent. A failure cannot fail your job. See *Notifying a channel*. |
| `slack-webhook-url` | `''` | **Opt-in, off by default.** A Slack incoming-webhook URL, mapped from a secret. Posts one Block Kit message. See *Slack, Linear and Jira*. |
| `notify-on` | `'findings'` | When the Slack message is sent: `findings` (only when the run proved or stated something) or `always`. |
| `linear-api-key`, `linear-team-id` | `''` | **Opt-in.** Security mode files one Linear issue per proven finding. Both are required. |
| `jira-base-url`, `jira-email`, `jira-api-token`, `jira-project-key` | `''` | **Opt-in.** Security mode files one Jira Cloud issue per proven finding. All four are required. The URL must be https on a public host. |
| `jira-issue-type` | `'Bug'` | The Jira issue type to create. |
| `max-issues` | `'10'` | The most issues one run may create in Linear, and the most in Jira (each has its own cap). |
| `license` | `''` | **Required on a private repository**, which will not start without one; never asked for and never read on a public one. It also enables decline replies on a private repository. Pass a secret, never a literal. |
| `metering-url` | `https://backend.credda.io/v1/runs` | Where one run receipt goes. Set to `''` for no request of any kind. |
| `engine-url` | `https://backend.credda.io/v1/engine` | Where the engine is fetched from. Whatever it returns is still checked against the digest in this repository's `engine.lock.json`, so pointing it somewhere hostile produces a failed job, not a compromised one. |
| `engine-archive` | `''` | Path on the runner to a mirrored copy of the engine archive. When set, **no request is made to Credda and no OIDC token is minted**; the copy goes through the identical digest check. |

Every input has a default and none is required on a public repository, so
`uses:` with no `with:` block at all is a working configuration.

### The defaults point at `backend.credda.io`

Both `metering-url` and `engine-url` default to **`backend.credda.io`**, where
Credda's metering and engine-delivery service runs. `metering-url` moved when
metering was ported into credda-backend (2026-09-06); `engine-url` moved on
2026-10-24, once the engine store was populated and the backend was serving
`/v1/engine` — the last of the two to move because it is the one input that can
genuinely fail a build, so it changed only after a real runner was *observed*
being served the engine. That proof is `smoke.yml`: it fetches the engine with a
GitHub-signed OIDC token and checks the bytes against `engine.lock.json`. The
client carries the same `metering-url` string as `DEFAULT_ENDPOINT`
(`core/packages/metering/src/client.ts`), which the engine repository's
`client.test.ts` asserts, so the launcher and the client never disagree about
where a receipt goes.

The OIDC audience the launcher requests (`ENGINE_AUDIENCE` in
`launcher/fetch-engine.mjs`) is also `https://backend.credda.io/v1/engine`. An
audience is a string the service compares, not an address anything connects to,
and the verifier accepts both the current and the legacy name
(`ACCEPTED_ENGINE_AUDIENCES` in the engine repository), so a workflow pinned to
an older tag keeps working: the legacy `metering.codereef.app` endpoint stays
answering until no supported pin still uses it.

Not `api.credda.io`: that host redirects to credda.io and routes no `/v1/*`
path. The runtime endpoints are on `backend.credda.io`.

If you have pinned either input explicitly, nothing here affects you.

## Outputs

| Output | Mode | Value |
| --- | --- | --- |
| `security-findings` | security | How many findings an exploit proved. Only proven findings are counted. |
| `sarif-path` | security | Absolute path of the SARIF file on the runner. |
| `security-fixes` | security | With `fix` on, how many fixes the check-fix gates proved (`FIX_PROVEN`). Empty when `fix` is off. |
| `fix-patches` | security | With `fix` on, a directory on the runner holding each proven patch and its pull request body, for `actions/upload-artifact`. Empty when no fix was proven. |
| `security-json-path` | security | Absolute path of `security.json` on the runner: the proven findings in full. |
| `security-reach` | security | One line of JSON: `limited`, `functions`, `probes` by verdict, `sourceFiles`, `partial` and `packages`. `limited` is true when the run proved nothing and could not exercise the code. `partial` is true when part of what was in scope was not exercised. `packages` holds a workspace's package counts, or `null`. A field the engine did not write is `null`. See *What this run reached* and *Monorepos*. |
| `security-report-path` | security | With `keep-report` on, a directory on the runner holding `security.json`, `security.md` and the SARIF files, for `actions/upload-artifact`. Empty otherwise. |
| `engine-version` | either | The engine version this run verified and executed, from `engine.lock.json`. The same number as the action's own release. |
| `should-post` | either | Whether a comment was posted. One predicate, computed in `run.mjs`, read by the posting step. `false` in `discover` and `sweep`, which run on a push and have no issue to comment on. |
| `candidates` | discover, sweep | How many candidates the run produced. In `sweep`, how many discovery wrote before the `max-candidates` cap. |
| `stated-findings` | discover, sweep | In `discover`, findings settled by reading. In `sweep`, the count of candidates that reached a verified change -- the run's real yield. |
| `investigation-id` | investigate | The investigation id, for `credda inspect` / `credda report`. |
| `outcome` | investigate | Terminal outcome, e.g. `REPRODUCED_AND_DIAGNOSED` or `NO_RUNNABLE_CHECK`. |
| `established` | investigate | Whether the run established anything about the repository. |
| `report-path` | investigate | Absolute path of the Markdown report on the runner. |
| `pull-request-opened` | investigate | Whether this run had a verified fix to deliver and went on to deliver it. `false` whenever `open-pull-request` is off, and `false` when it is on and the run produced no verified fix. Both are correct outcomes. It is written *before* the push, so on a job that did not succeed, read the step rather than this. |
| `triage-outcome` | triage | `COMMENT` when Credda had something specific to ask for, `SILENT` when it correctly had nothing to say. Both are successes. |
| `comment-path` | triage | Absolute path of the decline reply on the runner, or empty when silent. |
| `skipped` | either | `true` when this event was not one Credda acts on -- the wrong label, the wrong issue action, or an issue opened already labelled -- and `false` when it ran. A skip is a success, and it is the one outcome that otherwise looks identical to a run that never started. The reason is on the job summary. |

## What it needs, and what it refuses

- **A Linux runner with Docker** (`ubuntu-latest` is both), in `investigate`
  mode. Repository code executes only inside Credda's sandbox, which has its
  network removed before anything from the repository runs. The action refuses
  the docker plane on a runner that cannot provide it rather than degrading to
  host execution. `triage` mode runs no repository code at all, so it does not
  ask for that and the check is skipped for it.
- **Least privilege, with one addition that is called out rather than folded
  in.** `contents: read`, `issues: write`, and `id-token: write`, nothing else.
  Not `contents: write` and not `pull-requests: write`: on a default install
  this launcher creates no branch, pushes no commit and opens no pull request,
  so it asks for neither, and the token it holds cannot write to your
  repository whatever happens inside the engine. Those two scopes are needed
  only by the opt-in `open-pull-request` feature, which is off unless you turn
  it on and which is documented in *Opening a pull request* below. The third line is the
  price of the engine no longer being published in this repository; it lets the
  job mint a token saying which repository it is and grants no access to
  anything of yours. See *Why `id-token: write`* above,
  including how to drop it entirely by mirroring the artifact. If a fork of this
  workflow asks for more than these three, that is the fork's decision and not
  this action's requirement.
- **The issue text is treated as hostile.** It is read from the event JSON,
  written to a file, and passed by file name everywhere: `@file` into the CLI,
  `--body-file` into the comment. It is never interpolated into a shell, and
  the runner's workflow-command parsing is suspended around the one stream that
  quotes it.
- **No package manager, ever, and one download that is verified.** The action
  runs no package manager, reads no lockfile, resolves no dependency, and
  fetches nothing from any registry. The only thing it sets up is a Node 24
  runtime, which the hosted runners largely have already.

  It does make exactly one network fetch of code: the engine, from Credda's
  own service, checked against a SHA-256 digest committed in this repository
  before a byte reaches the disk. That is a real change from the version that
  shipped the engine in `bundle/` and fetched nothing at all -- see *How the
  engine gets here* and *What happens when Credda is down* above, both of
  which say what it costs.

### Using your own model

Credda can reason with any OpenAI-compatible endpoint instead of Anthropic,
such as a vLLM server or NVIDIA NIM. You pay for the GPU and Credda pays nothing.

```yaml
      - uses: Credda-io/action@v1
        with:
          model-base-url: http://gpu-host:8000/v1
          model-api-key: ${{ secrets.CREDDA_MODEL_API_KEY }}
          model-name: Qwen/Qwen2.5-Coder-32B-Instruct
```

The inputs map onto the engine's `CREDDA_OPENAI_BASE_URL`,
`CREDDA_OPENAI_API_KEY` and `CREDDA_OPENAI_MODEL`. Setting any of them also
sets `CREDDA_PROVIDER=openai-compatible`, so your endpoint is used even if
`anthropic-api-key` is passed as well, and a missing key fails the run instead
of letting it continue without a model. Leave `model-base-url` empty with a key
set to use NVIDIA NIM.

- **The runner must reach the endpoint.** Model calls are made by the engine
  on the runner, outside the sandbox. A model on a private network needs a
  self-hosted runner that can reach it. The default docker sandbox still
  needs Linux and Docker on that runner in `investigate` mode.
- **Repository code never reaches it.** With the docker sandbox, repository
  code runs in a container whose network is removed before any of it runs, and
  whose environment is built explicitly, so neither the endpoint nor its key is
  visible to it.
- **Cost is not metered.** Credda has no price for your endpoint, so the run
  reports the cost as unknown rather than as zero.

### Opening a pull request

**Off by default.** Everything above ends with a report: Credda reproduces the
reported failure, diagnoses it, and -- with a model-backed provider -- writes a
patch and proves it with a regression test that fails on the unpatched tree and
passes after. Until you turn this on, that patch reaches you as text inside an
issue comment and goes no further.

Turning it on has Credda commit the patch and the regression test to a new
branch and open a pull request whose body is the same report. It is one input:

```yaml
permissions:
  contents: write        # replaces `contents: read`: push the branch
  issues: write          # the report comment
  id-token: write        # mint an OIDC token to fetch the engine
  pull-requests: write   # open the proposal

# ...
      - uses: Credda-io/action@v1
        with:
          open-pull-request: 'true'
```

**Those two write scopes are on your own `GITHUB_TOKEN`, granted by you, in
your own workflow file.** There is no OAuth app in this path, no GitHub App, no
credential of Credda's, and no copy of your code on Credda's side. The push and
the pull request are made by your job, on your runner, with a token GitHub
minted for that job and destroyed when it ends. Nothing you grant here reaches
us.

Which is also the one thing to check if your checkout is hardened: the branch is
pushed with the credential `actions/checkout` persisted on `origin`, so
`persist-credentials: false` on that step leaves nothing to push with. Credda
has no credential of its own to fall back on -- that is the property, not a gap
-- so it names that setting and stops. The `github-token` input is read by `gh`
for the proposal itself and is not what git pushes with.

**It never merges.** There is no merge call anywhere on this path: no
auto-merge, no review approval, no branch-protection bypass. A pull request is
a claim made to a human, and the human decides. A test fails if a merge verb
appears.

**It refuses to propose an unproven fix, even when it is on.** The gate is the
engine's own record of what was *executed*: the run must have reached
`READY_FOR_REVIEW`, a patch row must have survived it, a verification must have
run, the regression test must have **failed before the change and passed
after**, and the verdict must be `VERIFIED` — or `PARTIALLY_VERIFIED` where the
recorded signals prove the reported failure changed shape rather than survived,
which is the second of the gate's two paths and not a softer reading of the
first. A run that reproduced your bug and stopped there pushes nothing and
says so on the job summary. That decision is made once, in the engine, and the
launcher reads the answer -- it has no opinion of its own about what counts as
proven.

**It will not clobber a branch.** The branch name is `credda/fix-issue-<n>`, so
a re-run on the same issue meets the branch its previous run pushed. If a pull
request is still open from it, the job says so and stops. If the branch exists
with no open pull request -- somebody closed it, or committed to it -- the job
refuses and names the branch. There is no force-push on any path.

**What it does when your admin has said no.** If the organisation has *Allow
GitHub Actions to create and approve pull requests* turned off, the branch is
pushed and `gh` refuses the proposal; the job fails naming that setting and its
location in Settings, and telling you the branch is there to open by hand. A
missing write scope, a branch protection rule and a patch that no longer
applies each get their own named message rather than the API's.

**What no patch may change, in any mode.** Before git sees a patch, Credda
refuses it if it touches `.github/` or any other CI configuration, a registry
file such as `.npmrc`, `.gitmodules` or `.gitattributes`, a path outside the
repository, a symbolic link or a submodule, or adds a URL to a lockfile. It also
refuses a file named without the `a/` and `b/` prefixes git writes, because git
would read that name as another path. Nothing is pushed and the summary names
the path.

**What has not been proven about this feature.** It has not been run against a
real repository from this checkout. The gate, the branch naming and the refusal
messages are covered by tests; the push, the `gh pr create` call and the
permission errors they produce are not, and cannot be from here.

### Slack, Linear and Jira

**All three are off by default, and each is opt-in on its own.** A step runs
only when its own inputs are set, so a default install makes none of these
requests. Every request goes from your runner to the service you named.
Nothing is sent to Credda.

Pass credentials only as inputs mapped from your own secrets. The action masks
each one before it prints anything. No log line and no job summary line carries
a webhook URL, key, token or Authorization header.

Each request is one attempt with a ten-second timeout, and redirects are not
followed. A destination that fails, answers 4xx or 5xx, or times out does not
fail the job and does not stop the others. Its result, with the status code,
is one line in the log and one in the job summary.

Each URL must be https on a public host. Loopback, private and link-local
addresses are refused, as are single-label names such as `https://jira`. This
checks the address you typed, not what a public name resolves to.

```yaml
on:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write
  security-events: write

jobs:
  credda:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Credda-io/action@v1
        with:
          mode: security
          # Slack: one message when something was proven.
          slack-webhook-url: ${{ secrets.SLACK_WEBHOOK_URL }}
          notify-on: findings          # or 'always'
          # Linear: one issue per proven finding.
          linear-api-key: ${{ secrets.LINEAR_API_KEY }}
          linear-team-id: ${{ vars.LINEAR_TEAM_ID }}
          # Jira Cloud: one issue per proven finding.
          jira-base-url: https://acme.atlassian.net
          jira-email: ${{ secrets.JIRA_EMAIL }}
          jira-api-token: ${{ secrets.JIRA_API_TOKEN }}
          jira-project-key: SEC
          max-issues: '10'
```

**Slack.** One Block Kit message with the repository, the outcome and the
count of proven findings. In security mode it lists up to 5 proven findings
(class, CWE, where, one sentence) and links the run. It never carries an
exploit program. Unproven patterns appear only as a count labelled unproven.
With `notify-on: findings` (the default) a run that proved nothing sends
nothing. With `always` that run sends one message saying no exploit succeeded,
and that this is not an audit. Outside security mode the message follows the
same rule as `notify-url`.

**Linear.** Security mode only. One issue per proven finding. The description
holds the sentence, the CWE, the site, the finding id, a fingerprint and the
run link, then the exploit program in a fenced block.

**Jira.** Security mode only. The same content as a `Bug` (or
`jira-issue-type`) through Jira Cloud's REST v3, in Atlassian Document Format.
Jira Server and Data Center do not have this API, so they are not supported.

**With `fix`.** When `fix` is on, the Slack message and each Linear or Jira
issue say what happened to the fix for that finding's class: fix proven by the
check-fix gates, with the pull request URL when one was opened; fix rejected,
with the engine's verdict or the step it stopped at; or not attempted. This
comes from the engine's fix record in `security.json` and from what delivery
reported. A model's own words are never sent. An issue that is already open is
skipped, so it does not get the outcome of a later run.

**De-duplication.** The fingerprint is a hash of the repository, the language
and the engine's finding id. The id has no seed in it, so the same finding
has the same fingerprint on every run. On a workspace report the id starts with
the package path, so the same finding in two packages gets two fingerprints,
and a report of one package keeps the fingerprints it always had. On a
workspace report the issue title and description also name the package, and
the Slack message says how many packages were exercised. Before it files, each step searches for
the fingerprint among open issues: Linear in the description, Jira in a label
it also writes. A finding already open is skipped. A closed one is filed again
if it comes back. A finding at a file and line gets a new fingerprint when its
line moves.

**Sizes.** Text from the scanned repository is escaped for each format, so a
file name or sentence cannot form a link or a mention. Slack text is cut to
Slack's limits with a note that says so. An issue description is kept under
30,000 characters. An exploit program that does not fit is left out whole,
with a note that points to the run's job summary. A program is never cut.

`max-issues` caps how many issues one run creates in each tracker. Findings
beyond it stay on the job summary, and the log line says how many were not
filed.

**What has not been proven.** These steps were tested against a local HTTP
server standing in for each API, with request shapes written from the vendors'
public documentation. No real Slack, Linear or Jira account was used.

### Notifying a channel

**Off by default.** Every competitor posts findings to Slack, and Credda now
can -- from your runner, to your URL, and nowhere else. Set one input:

```yaml
      - uses: Credda-io/action@v1
        with:
          notify-url: ${{ secrets.CREDDA_NOTIFY_URL }}
```

A `hooks.slack.com` incoming webhook gets one sentence in Slack's `{text}`
shape; any other URL gets a JSON body with seven fields: `investigationId`,
`repository`, `outcome`, `statedFindings`, `established`, `reportUrl` (this
run's URL on GitHub, or `null`) and `actionVersion`. Every one of them is
already an output of this action or a value GitHub provides; the step never
opens the report, so the body cannot carry issue text, code, paths or a
reporter's words.

**Why this runs on your runner and not on Credda's side.** Credda's backend
never receives a run's facts -- the metering receipt below carries salted
hashes, an outcome token and a version, and nothing else -- so there is no
server of ours that could tell your channel what a run found without first
being sent the things it has been promised it never sees. The POST leaves your
runner with your data for the address you typed. Nothing about it reaches
Credda.

**It sends nothing for a run that found nothing.** The request is made only
when the run established something (investigate mode) or stated at least one
finding (discover mode); otherwise the step says so in the log and sends
nothing. When `notify-url` is empty the step is skipped and says nothing at all.

**It cannot fail your job.** One request, a ten-second timeout, no retry. A
refusal, a hang or a 500 is one line in the log naming the status or the error,
and the job stays whatever colour the steps before it made it.

## How it fails

Every failure below names its own cause on the first line of the annotation,
because that list is what somebody reads before they open the log.

| What went wrong | Step that goes red | What you do |
| --- | --- | --- |
| The job has no `id-token: write` | *Fetch and verify the Credda engine* | Add the line. The message prints the whole `permissions:` block. |
| Private repository, no licence | *Fetch and verify the Credda engine* | `402`, with the sentence the service wrote and a link to the plans. Public repositories never see this. |
| Our service or bucket is down | *Fetch and verify the Credda engine* | Nothing on your side. Three attempts, then the job fails saying it is our outage. Mirror the archive if you cannot tolerate it. |
| The downloaded bytes do not match `engine.lock.json` | *Fetch and verify the Credda engine* | The job fails printing both digests and `NOTHING WAS EXECUTED`. Nothing was written to disk. |
| `sandbox: docker` on a non-Linux runner | *Refuse a plane the runner cannot isolate* | Use `ubuntu-latest`. The action refuses rather than falling back to running your code on the host. |
| The event is not the label this action runs on | *Run Credda* | Nothing. The step logs `Skipping:` and exits 0 -- a green job, not a red one. |
| The metering receipt fails | none | Nothing. It cannot redden a build, in any direction. See *It cannot break your job*. |
| `open-pull-request: 'true'`, and the org forbids Actions opening pull requests | *Open a pull request with the verified fix* | An admin turns on *Allow GitHub Actions to create and approve pull requests* under Settings -> Actions -> General. The branch was pushed; anyone can open the proposal by hand meanwhile. |
| `open-pull-request: 'true'` without `contents: write` / `pull-requests: write` | *Open a pull request with the verified fix* | Add both to your workflow's `permissions:` block. The message names them. The report comment is already posted by then. |
| `open-pull-request: 'true'`, and your checkout ran with `persist-credentials: false` | *Open a pull request with the verified fix* | Drop that setting on this workflow's `actions/checkout` step, or configure a credential for `origin` yourself. It removes the token git pushes with, and Credda has none of its own to fall back on. Adding scopes will not fix it, so the message says that rather than quoting git. |
| `open-pull-request: 'true'` and the run proved no fix | none | Nothing. No pull request is opened, the job stays green, and the job summary says which of the conditions was not met. |

A run that reproduces nothing is **not** a failure: the job is green, the report
says what it could not establish, and whether a comment is posted is the
`comment` input's decision.

## What comes back

The same document `credda report <id> --markdown` emits: a lead sentence stating
the strongest claim the evidence supports, the captured failure signature, the
evidence ledger, a **Root Cause** section, a **What was not done** section, and
an ordinal confidence class with the list of what this record does not
establish. If the reported failure could not be reproduced, the report says that
plainly instead of guessing.

The Root Cause section is named for what it holds when there is something to
hold, which is rarer than the heading suggests: it names a cause only where a
hypothesis was confirmed, and otherwise says "No hypothesis was confirmed, so
this report names no cause for the failure" and quotes the unconfirmed
hypothesis as unconfirmed. Do not read the heading as a promise.

Reruns post a fresh comment: remove and re-add the label to run again after a
push.

## Receipts, and the one thing a licence buys

The action reports **one receipt per run**, to
`https://backend.credda.io/v1/runs`. **This is on by default**, and it is
what the run count and the licence check are made of. On a private repository,
add your licence:

```yaml
with:
  license: ${{ secrets.CREDDA_LICENSE }}   # private repositories only
```

**What a licence now buys, and what changed about it.** Two things:

1. **Running at all on a private repository.** The engine endpoint refuses a
   private repository without a licence that verifies, is unexpired, is not
   revoked, and is bound to that repository's owner -- and the owner is read out
   of the OIDC token GitHub signed rather than out of anything the action sends,
   so it cannot be asserted around. This is new: before the engine moved out of
   this repository, a private repository could run everything and only lost
   decline replies.
2. **Decline replies on a private repository**, exactly as before, decided on
   the metering endpoint, which still fails open in every direction.

**Public repositories are unchanged in every respect.** They are never asked for
a licence by either endpoint, and reproductions stay free everywhere with no
signup. That is not a policy applied on trust: the engine endpoint reads
`repository_visibility` out of a claim GitHub signed.

### Exactly what is sent

One `POST`, at most once per job, of a JSON body under 400 bytes. It has nine
fields and there are no others:

| Field | Value | Form |
| --- | --- | --- |
| `v` | protocol version | the integer `1` |
| `orgHash` | your owner login | **HMAC-SHA256, hashed on your runner** |
| `repoHash` | `owner/repo` | **HMAC-SHA256, hashed on your runner** |
| `actorHash` | the login that triggered the run | **HMAC-SHA256, hashed on your runner** |
| `outcome` | one bounded uppercase token, e.g. `REPRODUCED_AND_DIAGNOSED` | plaintext |
| `durationMs` | how long the run took | a number |
| `actionVersion` | Credda's own release, e.g. `v1.4.0` | plaintext |
| `isPrivate` | whether the repository is private | `true` / `false` |
| `licenseKey` | the `license` input | **plaintext, over TLS, private repositories only** |

`licenseKey` is the one unhashed identifier, and it is sent only when
`isPrivate` is true and the input is non-empty -- it is omitted from the body
entirely on every public run. It is a bearer credential for the entitlement
check, so the server has to be able to read it.

The three hashes are computed on your own runner, with a fixed salt, before
anything is sent. The plain names never leave the machine you already own. That
is pseudonymisation and not anonymisation, and the metering protocol's own
header says exactly what that is and is not worth.

### What is never sent

There is no field on this endpoint that could carry any of it: your owner or
repository **name** in the clear, any URL, the issue title or body, any comment
or other text a human wrote, source code, diffs, patches, file names or paths,
command lines, stdout, stderr, stack traces, branch names, commit SHAs, pull
request numbers, email addresses, actor logins, or anything about model spend or
token counts. Time is recorded as the server's own UTC calendar **day**, never a
timestamp. `outcome` and `actionVersion` are additionally refused if they merely
*look* like a commit SHA, checked on your runner and again at the server.

### Turning it off

There is **one** switch, and it makes **no request of any kind** -- not a
shortened one, not a stripped one:

```yaml
with:
  metering-url: ''        # in the workflow
```

It is read before the metering client is imported and before anything is
hashed: `run.mjs` trims the value, and an empty one returns before the `import`.
Turning it off disables nothing you are paying for -- with metering off, a
decline reply on a private repository is still posted.

There is no environment-variable equivalent. Earlier revisions of this page
offered `CREDDA_TELEMETRY: off` in the job environment; **nothing in this
repository ever read that name**, so setting it did nothing and the receipt was
sent anyway. It is documented here rather than quietly deleted because a
workflow may still be carrying it: if yours sets `CREDDA_TELEMETRY`, that
workflow is metering, and `metering-url: ''` is what actually stops it.

### It cannot break your job

The call is bounded by a two-second race, never retries, never throws, and every
failure -- unreachable, hung, malformed, 500, 402 -- is treated as "carry on".
The whole of the reporting function in `run.mjs` sits inside one `try` whose
`catch` returns null, and every caller reads null as "carry on".

A licence changes exactly one thing: a **decline reply on a private
repository**. Reproductions are free on every repository and are never gated.
Public repositories are never asked for a licence. If the endpoint is
unreachable, hung, or answers something unexpected, the reply is posted anyway.

## Timing

Both modes first fetch and verify the engine: one request, an archive of about
1.9 MB, hashed in memory. On a hosted runner that is seconds, and it is paid on
every job -- the runner is fresh each time, so nothing about it is cached
between runs.

`investigate` then builds the sandbox image (minutes of `apt` on top of
`node:24-bookworm-slim`). Within one job, a rebuild is triggered only by a
change to the engine's `Dockerfile`, since the image tag is derived from that
file's bytes; across jobs on hosted runners, expect to pay for it again. Budget
`timeout-minutes: 30` and expect most runs to finish in a few minutes.

`triage` does none of that, and pays for no install at all. The engine starts in
about a tenth of a second and the triage decision itself is well under a second
on a real report, so after the fetch a triage job is a checkout, a Node setup
and a second or so of work.

## What is in this repository

```
action.yml                 the action metadata (root, so it can be listed)
run.mjs                    the runner: event in, report out. Dispatches the five
                           modes; imports sweep.mjs for the sweep branch and
                           security-fix.mjs for security mode's fix input
security-fix.mjs           security mode with fix on: writes the engine's fix
                           verdicts to the job summary and proposes each
                           FIX_PROVEN patch through deliver-core.mjs, then records
                           what delivery did for the Slack, Linear and Jira steps.
                           Imported by run.mjs; never a step of its own
sweep.mjs                  the sweep orchestration: discover, reproduce each
                           candidate up to max-candidates, and open a pull request
                           per verified fix through the shared delivery code.
                           Imported by run.mjs; never a step of its own
delivery.mjs               the pure decisions: the single predicate that decides
                           whether a run has a verified fix to deliver, the
                           branch names for the issue, sweep and security paths,
                           and the paths no patch may touch (CI, registry
                           configuration, outside the repository). Imported by
                           run.mjs, deliver-pr.mjs, deliver-core.mjs, sweep.mjs
                           and security-fix.mjs; never executed as a step of its own
deliver-core.mjs           the git-and-gh machinery that pushes a branch and opens
                           one pull request, reading no environment so the
                           single-investigate path, the sweep loop and security
                           fixes share it. It never force-pushes and never merges
deliver-pr.mjs             the single-investigate entry: reads this run's one
                           patch, issue and body from the environment, names the
                           branch from the issue number, and delivers it through
                           deliver-core.mjs. Reached only when open-pull-request is
                           on AND the run produced a verified fix. It never merges
notification.mjs           the decision, the body and the one bounded POST behind
                           notify-url, with fetch handed in so it can be tested
                           with no network. Imported by notify.mjs; never a step
findings.mjs               how security.json is read: the counts, the site text, the
                           exploit fence, each finding's fix outcome, and what the
                           run reached with the limited-reach rule. Imported by run.mjs,
                           integrations.mjs and security-fix.mjs, so the job
                           summary, a tracker issue and a fix pull request
                           describe a finding the same way
integrations.mjs           the Slack message, the Linear and Jira issue bodies, the
                           de-duplication searches and the bounded requests, with
                           fetch handed in so they can be tested with no network.
                           Imported by integrate.mjs; never a step of its own
integrate.mjs              delivers proven findings to Slack, Linear or Jira, one
                           destination per step. Reached only when that
                           destination's inputs are set; it masks each secret and
                           never fails the job
notify.mjs                 POSTs the run's facts to the URL in notify-url, from the
                           customer's runner. Reached only when that input is set;
                           it never opens the report and never fails the job
engine.lock.json           the SHA-256 of the engine archive and of every file
                           in it -- the trust anchor. Generated; never edited.
launcher/fetch-engine.mjs  mints the token, downloads, verifies, unpacks
launcher/integrity.mjs     the digest check: the security boundary of the
                           product, kept short and separate so it can be read
launcher/untar.mjs         a tar reader that can only produce pinned files
launcher/*.d.mts           types for the three files above
package.json               not installed from, and there is no lockfile because
                           there are no dependencies. It carries the one version
                           string that names both this action and its engine.
README.md                  this file
SYNC.md                    how a release is cut and verified
LICENSE                    Apache-2.0
.gitignore                 one line: `node_modules/`, which nothing here creates
.github/workflows/ci.yml   the two jobs below, on every pull request: what can be
                           proved with no engine, no network and no customer
.github/workflows/smoke.yml  asks the real endpoint for the real artifact with a
                           real OIDC token and checks the bytes against the
                           lockfile -- the one claim a laptop cannot prove
.github/check-shipped.mjs  proves the tree a customer fetches is complete: every
                           module parses, every import and every path action.yml
                           runs is TRACKED, and both files name one version
.github/check-manifest.rb  proves action.yml is valid YAML and would install, and
                           that every name its expressions, and its steps'
                           scripts, reach for is one that exists
test/integrations.test.mjs  node:test over integrations.mjs and integrate.mjs, against
                           a local HTTP server standing in for Slack, Linear and
                           Jira. No dependency; `node --test` runs it
test/fake-fetch.mjs        loaded only by that test with `--import`: sends each
                           request integrate.mjs makes to the local server. No
                           step loads it, so a real run cannot be redirected
.github/notify.test.mjs    node:test over notification.mjs: the body, the Slack
                           shape, silence with nothing to say, and a failed POST
                           that fails nothing. No dependency; `node --test` runs it
.github/security-fix.test.mjs  node:test over security-fix.mjs and the patch
                           refusals in delivery.mjs, with security.json files the
                           engine wrote, a local bare repository as origin and a
                           gh stub. No network; `node --test` runs it
.github/security-mode.test.mjs  node:test over security mode in run.mjs: the
                           extra-probes names, the engine flags they set, the
                           summary line per class, and hostile text in
                           security.json, with run.mjs run against a stand-in
                           engine. No network; `node --test` runs it
.github/security-reach.test.mjs  node:test over what a security run reached: the
                           summary section, the limited-reach rule, the
                           security-reach output, keep-report and the Slack line,
                           on engine outputs and on hostile module names and notes.
                           No network; `node --test` runs it
.github/security-workspace.test.mjs  node:test over workspace (monorepo) reports:
                           the limited and partial rules, the summary lead and
                           per-package reach, findings by package in the summary,
                           Slack, Linear and Jira, fingerprints, the Fixes
                           section, hostile paths and reasons, and every
                           single-package summary held to what it was before.
                           No network; `node --test` runs it
.github/fixtures/security-fix/  those engine outputs, and where they came from
.github/fixtures/security-reach/  real engine outputs for that test, and where they
                           came from
.github/fixtures/security-workspace/  real workspace reports the engine wrote on
                           three public monorepos, and where they came from
.github/ISSUE_TEMPLATE/    the two reports worth having: an install that failed,
                           and a run whose report was wrong
.github/PULL_REQUEST_TEMPLATE.md
.github/SECURITY.md        where to send a vulnerability, and what to expect back
```

That is the whole repository, and it is checked rather than asserted:
`.github/check-shipped.mjs` compares that listing against `git ls-files` in both
directions, so a file added here without a line above, or a line above naming a
path that no longer exists, fails CI. There is no `node_modules`, no lockfile,
no build step, and nothing here is compiled before it runs.

**There is no engine here, and that is the point.** It used to be committed as
`bundle/reef.mjs`, which meant the engine -- 27,957 unminified lines with the
agent prompts as plain string literals -- was published in a public repository.
Minifying does not help: a string literal survives it.

The engine source lives in a separate, private repository. `SYNC.md` records how
the artifact and its lockfile are regenerated; one command writes both, so they
cannot be released out of step with each other.

## Licence

Apache-2.0.
