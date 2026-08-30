# Credda

**Label an issue. Get back the fix.**

You label a bug report or a security vulnerability. Credda reproduces the
failure, diagnoses the cause, writes the patch, proves it with a test that fails
before and passes after, and hands back a diff. Opening a pull request is
`open-pull-request` below: opt-in, off by default. It proposes and never merges.

That first sentence used to read "Credda finds the bugs and security
vulnerabilities in a company's production and QA environments". Nothing in this
Action goes looking: the workflow below is triggered by a label, and the
`issue-body` it passes is the human description everything downstream depends
on. ADR 0024 in the engine repository amends the sentence at its source.

This repository is the GitHub Action that runs it in your own CI. The product
is at [credda.io](https://credda.io); the developer surface, including the
[API reference](https://api.credda.io/reference) and
[`openapi.json`](https://api.credda.io/openapi.json) for the three metering
routes this Action calls, is at [api.credda.io](https://api.credda.io).

**What this launcher runs today, and the promise this paragraph used to make.**
It said: "when the fix stage lands the workflow will ask for `contents: write`
and `pull-requests: write`, and this file will say so before it does." The fix
stage has landed. ADR 0019 in the engine repository put the fixer and the
verifier back on the investigation path on 2026-08-27, and on 2026-08-28 the
engine's forge delivery path was wired to open a pull request for a run that
reaches `READY_FOR_REVIEW` still carrying a patch, on either of two verdicts: a
`VERIFIED` one, or -- since 2026-08-29 -- a `PARTIALLY_VERIFIED` one whose
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

## Two modes

| `mode` | Fires on | Cost | What arrives |
| --- | --- | --- | --- |
| `investigate` (default) | a label | a runner, Docker, an install of your repository, minutes | a reproduction report |
| `triage` | an issue being opened | one download and one Node process, seconds | a short note saying what Credda could not use in the report -- **or nothing** |

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

> ### Read this before you copy the workflow below: `@v1` still wants the `codereef` label
>
> **Checked 2026-08-30.** The published `v1` tag is **8 commits behind `main`**,
> and one of those commits is the label rename. At `v1` the `label` input
> defaults to **`codereef` alone**; on `main` it defaults to `credda,codereef`
> and accepts either.
>
> The example below tells you to create a label called `credda`. Copy it as
> written against `@v1` and every part of it works except the part that
> matters: the workflow triggers, the job starts, the action resolves, the
> engine is fetched — and then the run **skips**, because the label it was
> given is not the label that tag runs on. A skip is exit 0. **You get a green
> check and no report, and nothing anywhere says why.** That is the worst
> failure mode this repository has, because it is indistinguishable from
> success.
>
> Until the tag is moved — a release decision, not a documentation one — pick
> one of these, both of which work on `@v1` today:
>
> ```yaml
>       - uses: Credda-io/action@v1
>         with:
>           label: credda        # name the label explicitly; do not rely on the default
> ```
>
> or pin the branch instead of the tag, which is the tree this README describes:
>
> ```yaml
>       - uses: Credda-io/action@main
> ```
>
> Pinning `@main` is not the recommendation for an install you leave alone —
> it moves under you — but it is what matches this file. Everything below
> describes `main`.
>
> **The label is not the only thing that tag is missing, and the second one is
> the promise.** `open-pull-request` **is not an input at `v1` at all.** It was
> added on `main`, in one of the same 8 commits. Set it on `@v1` and there is
> no error: an undeclared input evaluates to the empty string on the runner, so
> the feature is simply off. You will have added `contents: write` and
> `pull-requests: write` to your own workflow, watched the job go green, read a
> report on the issue — and no pull request will ever be opened, with nothing
> anywhere saying why. It is the label failure again, on the thing this action
> is for.
>
> The outputs `pull-request-opened` and `skipped` are absent at `v1` for the
> same reason, and a caller reading either of them gets `''` rather than a
> failure.
>
> So: **`open-pull-request` needs `@main` today.** There is no spelling of it
> that works on `@v1`, which is the difference between this and the label —
> that one had a workaround and this one does not. Everything the section
> *Opening a pull request* describes is `main`.

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
        # Optional. Without it the deterministic heuristic provider runs:
        # it reproduces and reports, and cannot reason over prose.
        # with:
        #   anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
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
Credda could not reach its engine service at https://metering.codereef.app/v1/engine
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
| `mode` | `investigate` | `investigate` reproduces a labelled issue; `triage` reads a newly opened one. |
| `label` | `credda,codereef` | Comma-separated list of labels that trigger an investigation (`*` accepts any). The default carries both names through the CodeReef -> Credda rename; `credda` is the one Credda names when it invites a maintainer to apply a label. In triage mode, the labels Credda stays quiet for. |
| `sandbox` | `docker` | Execution plane for repository code. `docker` is the only isolated plane, and needs a Linux runner. |
| `anthropic-api-key` | `''` | Optional. Without it the deterministic heuristic provider runs. Pass a secret. |
| `github-token` | `${{ github.token }}` | Posts the report comment, and -- only when `open-pull-request` is on -- makes the `gh` calls that open the proposal. The branch itself is pushed with the credential `actions/checkout` persisted, not with this value, so passing your own token here changes who opens the pull request and not who pushes the branch. |
| `comment` | `'true'` | `true` comments when something was established, `always` comments regardless, `false` never. |
| `open-pull-request` | `'false'` | **Opt-in, off by default.** `true` commits a *verified* fix to a branch and opens a pull request. Requires you to grant `contents: write` and `pull-requests: write` on your own `GITHUB_TOKEN`. A run that did not produce a verified fix opens nothing. See *Opening a pull request*. |
| `license` | `''` | **Required on a private repository**, which will not start without one; never asked for and never read on a public one. It also enables decline replies on a private repository. Pass a secret, never a literal. |
| `metering-url` | `https://metering.codereef.app/v1/runs` | Where one run receipt goes. Set to `''` for no request of any kind. |
| `engine-url` | `https://metering.codereef.app/v1/engine` | Where the engine is fetched from. Whatever it returns is still checked against the digest in this repository's `engine.lock.json`, so pointing it somewhere hostile produces a failed job, not a compromised one. |
| `engine-archive` | `''` | Path on the runner to a mirrored copy of the engine archive. When set, **no request is made to Credda and no OIDC token is minted**; the copy goes through the identical digest check. |

Every input has a default and none is required on a public repository, so
`uses:` with no `with:` block at all is a working configuration.

### Why the defaults above still say `codereef.app`

The name is Credda; two of these URLs are not, yet. That is a deployment fact
rather than an oversight, and it is stated here because you can read the
defaults and would otherwise have to guess.

The endpoints are moving to **`api.credda.io`**. One half of that move has
happened and the other has not, and they are different kinds of thing:

- **The OIDC audience has moved** to `https://backend.credda.io/v1/engine` --
  the value of `ENGINE_AUDIENCE` in `launcher/fetch-engine.mjs`, and *not*
  `api.credda.io`, which serves the developer website and routes no `/v1/*`
  path at all. An
  audience is a string the service compares, not an address anything connects
  to, and the metering Worker already accepts both the new and the old name, so
  moving it cannot strand a pinned workflow. (`ACCEPTED_ENGINE_AUDIENCES` in the
  engine repository is the set that does this.)
- **`metering-url` and `engine-url` have not moved**, because they are addresses
  that must answer. `api.credda.io` resolves today and, as of 2026-08-28, serves
  Credda's developer surface — a landing page, [the API
  reference](https://api.credda.io/reference), and
  [`openapi.json`](https://api.credda.io/openapi.json), which *describes*
  `/v1/engine` and `/v1/runs`. It does not yet *serve* them: that host is
  AWS-hosted and the metering service is a Cloudflare Worker, and both paths
  return `404 NOT_FOUND` there on `GET` and on `POST` (checked 2026-08-28).
  Documented is not routed.

So the remaining work is a routing change somebody has to configure -- getting
those two paths on `api.credda.io` in front of the Cloudflare Worker, and
keeping `metering.codereef.app` answering until no supported pin still uses it.
**Until that is configured and observed answering, these defaults stay where
they are.** `engine-url` is the one input that can genuinely fail your build, so
it is the last thing that should move on optimism.

If you have pinned either input explicitly, nothing here affects you.

## Outputs

| Output | Mode | Value |
| --- | --- | --- |
| `engine-version` | either | The engine version this run verified and executed, from `engine.lock.json`. The same number as the action's own release. |
| `should-post` | either | Whether a comment was posted. One predicate, computed in `run.mjs`, read by the posting step. |
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
      # `@main`, not `@v1`: this input does not exist at the published tag, and
      # an undeclared input is '' on the runner, which is 'off'. See the note
      # at the top of this file.
      - uses: Credda-io/action@main
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

**What has not been proven about this feature.** It has not been run against a
real repository from this checkout. The gate, the branch naming and the refusal
messages are covered by tests; the push, the `gh pr create` call and the
permission errors they produce are not, and cannot be from here.

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
| `open-pull-request: 'true'` on `@v1` | none | Nothing, and that is the problem: the input does not exist at that tag, so it evaluates to `''` and the feature is off. The job is green and the report is posted. Use `@main` until the tag moves. |
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
`https://metering.codereef.app/v1/runs`. **This is on by default**, and it is
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

Either of these makes **no request of any kind** -- not a shortened one, not a
stripped one:

```yaml
with:
  metering-url: ''        # in the workflow
```

```yaml
env:
  CREDDA_TELEMETRY: off # in the job environment
```

Both are read before anything is imported or hashed. Neither disables anything
you are paying for: with metering off, a decline reply on a private repository
is still posted.

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
run.mjs                    the runner: event in, report out
delivery.mjs               the single predicate that decides whether a run has a
                           verified fix to deliver. Imported by run.mjs and by
                           deliver-pr.mjs; never executed as a step of its own
deliver-pr.mjs             commits the patch, pushes the branch and opens the
                           pull request. Reached only when open-pull-request is
                           on AND the run produced a verified fix. It never merges
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
