// The Credda action's runner: event in, report out, nothing else.
//
// WHAT CHANGED FROM THE IN-MONOREPO VERSION, AND WHAT DID NOT. This file is a
// port of core's `action/run.mjs`. Every rule it enforces is unchanged -- the
// untrusted-text handling, the one-predicate comment gate, the two exit codes
// triage is allowed to return, the fail-open metering. Three things moved:
//
//   1. The engine CLI is a PREBUILT BUNDLE, spawned as plain `node reef.mjs`
//      -- the bundle file still ships under its pre-rename name, and
//      `engine.lock.json` hashes it under that name. It used
//      to be `node --import tsx apps/cli/src/main.ts` against a checked-out
//      monorepo, which is why installing the action needed the monorepo to be
//      public. No package manager, no loader, no lockfile.
//   2. The metering client is a second prebuilt bundle beside it
//      (bundle/metering.mjs), imported by path exactly as the TypeScript
//      source used to be. It exports the same three names this file calls.
//   3. `CREDDA_ACTION_ROOT` is now `${{ github.action_path }}` itself, not
//      its parent. No path this file computes leaves the action's own
//      directory.
//
// AND ONE THING CHANGED AGAIN AFTER THAT. The bundle is no longer committed in
// the action repository. Committing it meant publishing the engine -- 27,957
// unminified lines with the agent prompts as plain string literals -- which is
// the thing `Credda-io/core` going private was for. So the action repository
// now holds a launcher and no engine: `launcher/fetch-engine.mjs` runs first,
// proves which repository is asking with a GitHub OIDC token, downloads the
// engine, VERIFIES IT AGAINST A DIGEST COMMITTED IN THIS REPOSITORY, and
// unpacks it under `CREDDA_ENGINE_ROOT`. This file reads that directory and
// is otherwise unchanged.
//
// The cost is stated where a customer will meet it rather than only here: the
// workflow needs `id-token: write` on top of `contents: read` and
// `issues: write`, and a Credda outage now stops a job that nothing could
// stop before. README.md has both under their own headings.
//
// SECURITY SHAPE, AND WHY THIS FILE EXISTS INSTEAD OF SHELL STEPS. An issue
// body is text a stranger typed. Interpolating it into a workflow `run:` block
// -- `echo "${{ github.event.issue.body }}"` -- executes whatever shell syntax
// the stranger put there, with the job's token in the environment. That is the
// canonical GitHub Actions injection, and the way to be immune rather than
// careful is to never let the body near a shell at all: this script reads it
// out of the event JSON with Node, writes it to a file, and hands the CLI the
// FILE NAME. The comment step posts with --body-file for the same reason, and
// because shells truncate multi-line arguments. Both modes below follow that
// shape; neither has an exception.
//
// TWO MODES, ONE RUNNER, AND WHY THEY ARE NOT TWO SCRIPTS. `investigate` is the
// labelled path: a maintainer asks for a reproduction and gets a report.
// `triage` is the opened path: no sandbox, no install of the repository under
// test, no model call, no network -- it reads the report and either says what
// Credda could not use in it or says nothing at all. They share the event
// parsing, the untrusted-text handling, the comment gate and the posting shape,
// and every one of those is a thing that must not come to have two answers. The
// parts that differ are two functions.
//
// WHAT A FAILED INVESTIGATION MEANS HERE. `credda investigate` exits non-zero
// for outcomes that are not successes, and those runs still produce the
// product: a report that says what was established and what was not. So the
// gate is not the exit code, it is whether a result was recorded at all --
// result.json present means report, absent means Credda itself broke and the
// job should fail without posting anything.
//
// REPORTING IS NOT COMMENTING, AND THIS IS WHERE THEY SEPARATE. Every run that
// records a result produces a report, and this script always writes that report
// to the job summary, where the person who installed Credda will look. Only a
// run that established something about the repository earns a comment on the
// issue. An INCONCLUSIVE run produces a truthful document whose every section
// says nothing was established -- that document is about Credda, and posting
// it into someone's issue tracker is how the label gets removed and never put
// back. The decision itself is not made here: `establishedSomething` comes off
// the CLI's own result, so this file cannot hold a different opinion about what
// a success is than the report and the check run do.
//
// THE SAME RULE, IN TRIAGE'S SPELLING. `credda triage` exits 6 when it produced a
// comment and 0 when it correctly had nothing to say, and about half of real
// inbound is the second one. Silence is not a failure and must never fail a
// job. Anything else out of that command is Credda broken, and then nothing
// is posted.
//
// METERING IS ADVISORY AND CANNOT BREAK THE JOB. One receipt per run, reported
// through the metering client, which is documented to fail open inside a
// bounded race and never to throw. The receipt goes to the endpoint the action
// defaults to; a caller who sets `metering-url` to the empty string gets no
// request of any kind, and so does `CREDDA_TELEMETRY=off`. What one receipt
// contains is written out in the `metering-url` input description in action.yml
// and in README.md, in the fields it actually sends.
//
// This file adds two guards of its own on top of the client's: an endpoint
// that is empty after trimming means no call is attempted at all, and the
// whole of `meter()` is inside a `try` whose `catch` returns null. A telemetry
// call that reddens a customer's build is the catastrophe that client was
// written against, and this is the caller refusing to be the hole in it.

import { spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { decideDelivery } from './delivery.mjs';

function env(name, fallback = null) {
  const value = process.env[name];
  if (value !== undefined && value !== '') return value;
  if (fallback !== null) return fallback;
  console.error(`${name} is not set. This script only runs inside a GitHub Actions job.`);
  process.exit(1);
}

function output(name, value) {
  // GITHUB_OUTPUT is the supported channel; values here are ids and paths this
  // script produced itself, never reporter text.
  appendFileSync(env('GITHUB_OUTPUT'), `${name}=${value}\n`, 'utf8');
}

const startedAt = Date.now();

const actionRoot = resolve(env('CREDDA_ACTION_ROOT'));
const workspace = resolve(env('GITHUB_WORKSPACE'));
/**
 * The label(s) that trigger a run. A COMMA-SEPARATED LIST, and the default
 * carries two names rather than one.
 *
 * WHY. This action shipped as CodeReef with a default label of `codereef`, and
 * a repository using the default has that label applied to its issues and
 * written into its workflow's `if:`. Renaming the default to `credda` alone
 * would leave those repositories silently inert: the workflow still runs, the
 * action still starts, and it skips every issue because the label no longer
 * matches. Nothing errors, so nobody finds out until they notice the bot went
 * quiet, which is the worst shape a breaking change can take.
 *
 * So both are accepted through the rename. The FIRST entry is the primary --
 * it is the one the decline reply invites a maintainer to add, so new readers
 * are told the new name while old repositories keep working. Drop `codereef`
 * from this default when the deprecation window closes, and say so in the
 * release notes when you do.
 *
 * '*' still means "any label" and is checked before the list, so a caller
 * passing it is not silently turned into a two-name list.
 */
const expectedLabels = env('CREDDA_LABEL', 'credda,codereef')
  .split(',')
  .map((name) => name.trim())
  .filter(Boolean);
const anyLabel = expectedLabels.includes('*');
/** The name a message should NAME, when it names one. */
const primaryLabel = expectedLabels[0] ?? 'credda';
const sandbox = env('CREDDA_SANDBOX', 'docker');
const mode = env('CREDDA_MODE', 'investigate');

// The engine. A single prebuilt ESM file with its own createRequire shim, with
// the sandbox Dockerfile and the database migrations beside it -- the CLI finds
// both by probing its own directory, so this path is the only one that matters.
//
// IT IS NO LONGER IN THIS REPOSITORY. `launcher/fetch-engine.mjs` runs in the
// step before this one: it proves to Credda's service which repository is
// asking, downloads the engine, verifies it against the SHA-256 digest pinned
// in this repository's own `engine.lock.json`, and unpacks it. This variable is
// where it put it. Nothing here re-decides whether those bytes are acceptable
// -- that decision was made once, in one file, and duplicating it would create
// a second answer that could disagree.
//
// The layout under CREDDA_ENGINE_ROOT is the one this action used to ship
// in-repo (`package.json` at the root, engine under `bundle/`), so every path
// below is unchanged from the version that had the bundle committed.
const engineRoot = resolve(env('CREDDA_ENGINE_ROOT', actionRoot));
const creddaBundle = join(engineRoot, 'bundle', 'reef.mjs');
const meteringBundle = join(engineRoot, 'bundle', 'metering.mjs');

if (!existsSync(creddaBundle)) {
  console.error(
    `The Credda engine is not at ${creddaBundle}. The step that downloads and verifies it should ` +
      'have run before this one and should have failed loudly if it could not -- so reaching here ' +
      'means the action manifest is broken, not that a download failed silently. Nothing was run.',
  );
  process.exit(1);
}

const event = JSON.parse(readFileSync(env('GITHUB_EVENT_PATH'), 'utf8'));
const issue = event.issue;

const work = join(env('RUNNER_TEMP'), 'credda');
const home = join(work, 'home');

function credda(args, stdio) {
  // Plain `node`, no loader. `cwd` is the verified engine's own directory so
  // that a relative path the CLI resolves resolves under the engine and never
  // under the repository being investigated; every path this script passes is
  // absolute anyway.
  return spawnSync(process.execPath, [creddaBundle, ...args], {
    cwd: engineRoot,
    stdio,
    env: {
      ...process.env,
      CREDDA_HOME: home,
    },
    maxBuffer: 64 * 1024 * 1024,
  });
}

function skip(reason) {
  console.log(`Skipping: ${reason}`);
  output('skipped', 'true');
  process.exit(0);
}

/**
 * The issue title and body, in one file, as the CLI wants them.
 *
 * Title first, because the CLI derives issueTitle from the description's first
 * line; then the body verbatim. An empty body is legal on GitHub and legal
 * here: the title alone is still a report to fail honestly against.
 */
function writeIssueFile() {
  mkdirSync(work, { recursive: true });
  const issueFile = join(work, 'issue.md');
  writeFileSync(issueFile, `${issue.title ?? 'Untitled issue'}\n\n${issue.body ?? ''}`, 'utf8');
  return issueFile;
}

/** The label names already on this issue, whichever shape the payload used. */
function labelsOnIssue() {
  if (!Array.isArray(issue?.labels)) return [];
  return issue.labels
    .map((label) => (typeof label === 'string' ? label : label?.name))
    .filter((name) => typeof name === 'string' && name !== '');
}

/**
 * The link back to this run, appended to everything this script posts.
 *
 * A comment nobody can trace to a job is a comment nobody can check, and both
 * modes publish under Credda's name on somebody else's thread.
 */
function runUrl() {
  return `${env('GITHUB_SERVER_URL', 'https://github.com')}/${env('GITHUB_REPOSITORY')}/actions/runs/${env('GITHUB_RUN_ID', '0')}`;
}

function writeSummary(text) {
  // GITHUB_STEP_SUMMARY is optional in the environment only because this script
  // is runnable outside a job for local checks, so a missing one is skipped
  // rather than fatal.
  const summaryFile = process.env['GITHUB_STEP_SUMMARY'];
  if (summaryFile !== undefined && summaryFile !== '') appendFileSync(summaryFile, text, 'utf8');
}

/* --------------------------------- metering -------------------------------- */

/**
 * The version string that goes on a receipt.
 *
 * Read out of this action's own manifest rather than from `GITHUB_ACTION_REF`,
 * and that is not a stylistic choice. `GITHUB_ACTION_REF` is whatever the
 * caller pinned, and a caller who pins by commit SHA -- the thing every
 * hardening guide tells them to do -- would put a 40-character SHA in this
 * field. `buildRunReport` THROWS on a value shaped like a SHA, because the
 * endpoint's privacy statement says categorically that it cannot store one, and
 * that throw would land inside a customer's job. The manifest version is the
 * honest answer to "which Credda produced this run" and cannot be a SHA.
 */
function creddaVersion() {
  try {
    const parsed = JSON.parse(readFileSync(join(actionRoot, 'package.json'), 'utf8'));
    return typeof parsed.version === 'string' && parsed.version !== '' ? `v${parsed.version}` : 'unknown';
  } catch {
    return 'unknown';
  }
}

/**
 * Reports one run, and returns the entitlement decision or null.
 *
 * Null means no decision was reached, for any reason: no endpoint, a broken
 * import, a throw, a timeout, an unreachable host. Every caller treats null as
 * "carry on", which is the same policy `declineRepliesAllowed` applies to an
 * `'unknown'` entitlement, and for the same commercial reason -- an outage that
 * gives away a few decline replies costs almost nothing, and an outage that
 * silently disables a feature somebody pays for costs a customer.
 *
 * ON BY DEFAULT, AND AN EMPTY ENDPOINT STILL MEANS NO CALL. `action.yml`
 * defaults `metering-url` to `https://metering.codereef.app/v1/runs`, the same
 * endpoint the client carries as `DEFAULT_ENDPOINT`, so a run receipt and the
 * licence check both happen without the customer having to assemble them --
 * which is what the paid plans are actually sold against, and a gate somebody
 * has to switch on for themselves is not a gate.
 *
 * That makes this an outbound call on every job, so it is written down rather
 * than inferred: the body is the nine fields `buildRunReport` produces, the
 * three identifiers in it are HMAC'd HERE on the customer's own runner, and the
 * licence key is the only unhashed identifier and travels only on a private
 * repository. The full list, and the list of what no field can carry, is in the
 * `metering-url` description in action.yml and in README.md.
 *
 * The endpoint is still passed EXPLICITLY rather than left to the client's own
 * default, because that keeps one switch: whatever `metering-url` resolves to
 * is what is dialled, and setting it to the empty string disables the call
 * outright here, before the client is even imported.
 *
 * The `try` around everything is the second guard. `reportRun` is built never
 * to throw, but this function also imports a module, reads an environment and
 * hashes two strings, and none of those promises anything. What must be true is
 * that no line in this file can end a customer's job, and the only way to have
 * that structurally is for the whole body to be inside a `catch` that returns.
 */
async function meter(outcome) {
  try {
    const endpoint = (process.env['CREDDA_METERING_URL'] ?? '').trim();
    if (endpoint === '') {
      console.log(
        'metering-url is empty, so no receipt was reported and no request of any kind was made.',
      );
      return null;
    }

    const client = await import(pathToFileURL(meteringBundle).href);

    const report = await client.buildRunReport({
      org: env('GITHUB_REPOSITORY_OWNER', 'unknown'),
      repo: env('GITHUB_REPOSITORY', 'unknown/unknown'),
      // GITHUB_ACTOR is the login that caused this workflow to run, which for
      // the issue-labelled trigger is whoever applied the label. It is hashed
      // inside buildRunReport and never sent in clear, and it is what a seat is
      // counted from -- a seat is a person who used Credda this month, not a
      // member of the organisation, because most members never label anything
      // and billing for them prices the product on a number nobody controls.
      actor: env('GITHUB_ACTOR', 'unknown'),
      outcome,
      durationMs: Date.now() - startedAt,
      actionVersion: creddaVersion(),
      isPrivate: event.repository?.private === true,
      licenseKey: process.env['CREDDA_LICENSE'] ?? '',
    });

    const decision = await client.reportRun(report, { endpoint });
    console.log(
      `Metering: entitlement ${decision.entitlement}, recorded ${decision.recorded ? 'yes' : 'no'}.`,
    );
    return decision;
  } catch (error) {
    // Swallowed on purpose and logged once. There is nothing a customer can do
    // about our receipt endpoint and nothing about their job that depends on it.
    console.log(`Metering was skipped: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
}

/**
 * Whether a decline reply may be posted, given what metering said.
 *
 * Reproductions are free everywhere, decline replies are free on public
 * repositories and paid on private ones. This is the only place in the Action
 * where a licence changes behaviour, and it fails open in every direction -- no
 * decision, an unreachable endpoint, a malformed answer and an opt-out all end
 * up here as `true`.
 */
async function declineRepliesAllowed(decision) {
  if (decision === null) return true;
  try {
    const client = await import(pathToFileURL(meteringBundle).href);
    return client.declineRepliesAllowed(decision);
  } catch {
    return true;
  }
}

/* ------------------------------- investigate ------------------------------- */

async function investigate() {
  // Defence in depth: the workflow's `if:` should already gate on the label, but
  // an action that trusts its caller's gating runs on every labeled event the
  // day someone copies the workflow without the `if:`.
  const labelName = event.label?.name;
  if (issue === undefined || (!anyLabel && !expectedLabels.includes(labelName))) {
    skip(
      `event is ${issue === undefined ? 'not an issue event' : `labeled '${labelName ?? ''}'`}, ` +
        `and this action runs on ${expectedLabels.length > 1 ? `these labels: ${expectedLabels.map((n) => `'${n}'`).join(', ')}` : `the '${primaryLabel}' label`}.`,
    );
  }

  const issueFile = writeIssueFile();
  const resultFile = join(work, 'result.json');

  console.log(`Investigating issue #${issue.number} against ${workspace} (sandbox: ${sandbox})`);

  /*
   * The investigation's log lines can quote reporter text, and the Actions
   * runner parses `::` workflow commands out of anything a step prints. The
   * surviving commands are the cosmetic ones (error/notice/add-mask), so the
   * blast radius is faked annotations rather than code execution, but the guard
   * GitHub built for exactly this costs two lines: commands are suspended around
   * the untrusted stream, keyed on a token the reporter cannot know.
   */
  const guard = `credda-${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
  console.log(`::stop-commands::${guard}`);
  const run = credda(
    ['investigate', workspace, `@${issueFile}`, '--sandbox', sandbox, '--out', resultFile],
    'inherit',
  );
  console.log(`::${guard}::`);

  let result;
  try {
    result = JSON.parse(readFileSync(resultFile, 'utf8'));
  } catch {
    console.error(
      `Credda did not record a result (investigate exited ${run.status ?? 'null'}). ` +
        'This is a Credda failure, not a finding about the repository, and nothing will be posted.',
    );
    process.exit(1);
  }

  console.log(`Investigation ${result.investigationId} reached ${result.outcome}`);

  // Reproductions are free on every repository, so the receipt is reported and
  // the entitlement is deliberately not consulted here.
  await meter(result.outcome);

  /*
   * Older CLIs did not carry this field. `=== true` rather than a truthiness test
   * so an absent field reads as "did not establish anything" -- the quiet side is
   * the safe default, because the failure mode being avoided is posting, not
   * staying silent.
   */
  const established = result.establishedSomething === true;

  /*
   * Whether a comment will actually be posted, decided here rather than half here
   * and half in the step below.
   *
   * The gate used to live in two places that shared no input: this file knew
   * whether the run established anything, and the workflow step knew what the
   * `comment` input said. So the summary line asserted a comment had been posted
   * whenever the run established something -- untrue with `comment: false` -- and
   * asserted none had been, on `comment: always`, while one was being posted a
   * step later. Both halves are now one boolean, and the step below reads it
   * rather than re-deciding.
   */
  const commentMode = env('CREDDA_COMMENT', 'true');
  const willComment = commentMode !== 'false' && (commentMode === 'always' || established);

  const report = credda(['report', result.investigationId, '--markdown'], ['ignore', 'pipe', 'inherit']);
  if (report.status !== 0 || report.stdout === null || report.stdout.length === 0) {
    console.error(`credda report exited ${report.status ?? 'null'} with no document; not posting.`);
    process.exit(1);
  }

  const reportFile = join(work, 'report.md');
  writeFileSync(reportFile, `${String(report.stdout).trimEnd()}\n\n[Action run](${runUrl()})\n`, 'utf8');

  /*
   * The job summary always gets the report, whatever the outcome.
   *
   * Nothing is suppressed by the comment gate below -- an operator debugging a
   * quiet run needs the same document a loud one produces, and needs it without
   * downloading an artifact or re-running anything.
   */
  const verdict = willComment
    ? 'This report was posted as a comment on the issue.'
    : established
      ? `Reached ${result.outcome}, but commenting is disabled for this run, so nothing was posted. The report follows in full.`
      : `Reached ${result.outcome}, which established nothing about the repository, so no comment was posted. The report follows in full.`;
  writeSummary(`${verdict}

${readFileSync(reportFile, 'utf8')}
`);

  /*
   * ---------------------------- the delivery gate ---------------------------
   *
   * Whether this run's patch is pushed to a branch and offered as a pull
   * request. OFF unless the calling workflow asked for it, and off whatever the
   * workflow asked unless the run PROVED a change.
   *
   * The proof is not judged here. `result.delivery.deliverable` is computed by
   * the engine on the executed record -- the terminal state, the patch row that
   * survived, the verification verdict, and the regression test's FAIL-then-PASS
   * pair -- by the same predicate the GitHub App's delivery uses. This script
   * reads it, exactly as it reads `establishedSomething` rather than keeping a
   * list of outcomes. A pull request is the loudest claim this product makes,
   * and it must not be reachable from an opinion formed in the launcher.
   *
   * `decideDelivery` lives in `delivery.mjs` because it is a pure function of
   * two values and therefore the one part of this that a test can hold.
   */
  const openPullRequest = env('CREDDA_OPEN_PULL_REQUEST', 'false').trim() === 'true';
  const decision = decideDelivery({ enabled: openPullRequest, result });

  let patchFile = '';
  let deliveryNote = decision.reason;

  if (decision.deliver) {
    // Emitted by the engine, byte-exact, straight to a file. Not routed through
    // a shell and not reassembled from the result file: whitespace is the whole
    // of a diff.
    const patch = credda(['report', result.investigationId, '--patch'], ['ignore', 'pipe', 'inherit']);
    if (patch.status !== 0 || patch.stdout === null || String(patch.stdout).trim() === '') {
      // The engine said this run carries a verified change and then could not
      // produce it. That is an inconsistency in Credda, so nothing is pushed and
      // the refusal says whose fault it is.
      deliveryNote =
        'Credda recorded a verified change for this run and then could not emit the diff for it ' +
        `(credda report --patch exited ${String(patch.status ?? 'null')}). Nothing was pushed. ` +
        'This is a Credda failure, not a finding about the repository.';
      decision.deliver = false;
    } else {
      patchFile = join(work, 'verified.patch');
      writeFileSync(patchFile, String(patch.stdout), 'utf8');
    }
  }

  writeSummary(`\n${deliveryNote}\n`);

  output('issue-number', String(issue.number));
  output('investigation-id', result.investigationId);
  output('outcome', result.outcome);
  output('established', established ? 'true' : 'false');
  output('should-post', willComment ? 'true' : 'false');
  output('report-path', reportFile);
  output('deliver', decision.deliver ? 'true' : 'false');
  output('patch-path', patchFile);
  // The two names are not a duplicate. `report-path` is part of this action's
  // published interface and means the report; `body-path` is what the single
  // posting step reads, and both modes write it, so there is one posting step
  // rather than one per mode with a predicate each.
  output('body-path', reportFile);
}

/* ---------------------------------- triage --------------------------------- */

/**
 * The opened path: read the report, post what Credda could not use, or post
 * nothing.
 *
 * ## Two gates, both of which exist so a reporter never gets two bots
 *
 * `opened` only. An `edited` or `reopened` event would re-run this on a body
 * that has already been triaged, and the decline-reply renderer is a pure
 * function that remembers nothing, so the same comment would be posted again.
 * The workflow's own trigger should already say `types: [opened]`; this is the
 * same defence in depth the label check above is.
 *
 * Not when the issue already carries the investigate label. An issue opened
 * with the label on it is about to get a full sandboxed reproduction, and a
 * decline reply arriving first -- followed twenty minutes later by a report
 * that reproduces the bug -- reads as two unrelated bots disagreeing on one
 * thread. Where both would fire, the investigation wins: it is the one that
 * actually ran something.
 *
 * The other order, opened first and labelled later, cannot be gated away
 * because the reply is already posted by then. That one is handled in the copy
 * instead: the reply states that nothing was run and names the label that runs
 * it, so the report that arrives later is the follow-up the reply promised
 * rather than a contradiction of it.
 */
async function triage() {
  if (issue === undefined) skip('this is not an issue event, and triage runs on an opened issue.');
  if (event.action !== undefined && event.action !== 'opened') {
    skip(
      `the issue was '${event.action}', not 'opened'. Triage runs once, when an issue is filed; ` +
        'nothing here remembers what it has already said, so a second run would post the same comment twice.',
    );
  }

  const labels = labelsOnIssue();
  const alreadyLabelled = anyLabel ? labels.length > 0 : labels.some((name) => expectedLabels.includes(name));
  if (alreadyLabelled) {
    skip(
      `this issue was opened already carrying ${anyLabel ? 'a label' : `one of the labels this action runs on (${expectedLabels.map((n) => `'${n}'`).join(', ')})`}, ` +
        'so a full investigation is about to run on it and a triage note would be the second bot on the thread.',
    );
  }

  const issueFile = writeIssueFile();

  /*
   * The checkout is passed whether or not one was made, and that is safe by
   * construction rather than by luck: `credda triage --repo` looks for a
   * package.json and, finding none, falls back to the reading that assumes
   * nothing is known about the repository. The failure being avoided is the
   * opposite one -- an empty GITHUB_WORKSPACE answering "no" to every "does this
   * file exist", which manufactures specific, quotable, entirely wrong refusals
   * about files that are sitting in the repository.
   */
  console.log(
    `Triaging issue #${issue.number} against ${workspace} ` +
      `(${existsSync(join(workspace, 'package.json')) ? 'checked out' : 'no manifest found; treating the repository as unknown'})`,
  );

  const guard = `credda-${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
  console.log(`::stop-commands::${guard}`);
  const run = credda(['triage', issueFile, '--repo', workspace], ['ignore', 'pipe', 'inherit']);
  console.log(`::${guard}::`);

  /*
   * 6 is a comment, 0 is correct silence, anything else is Credda broken.
   *
   * The two success codes are read explicitly rather than as "zero or not",
   * because this command's whole contract is that its two successes are
   * different answers and neither of them is a failure.
   */
  const status = run.status;
  if (status !== 0 && status !== 6) {
    console.error(
      `credda triage exited ${status ?? 'null'}, which is neither a comment (6) nor silence (0). ` +
        'This is a Credda failure, not a finding about the report, and nothing will be posted.',
    );
    process.exit(1);
  }

  const comment = status === 6 ? String(run.stdout ?? '').trimEnd() : '';
  const spoke = comment !== '';

  const decision = await meter(spoke ? 'TRIAGE_COMMENT' : 'TRIAGE_SILENT');
  const entitled = await declineRepliesAllowed(decision);

  /*
   * One predicate, computed once here, exactly as the investigate path does.
   * `always` is accepted and means `true`: there is no "post regardless" for a
   * comment that does not exist, and inventing one would be inventing the
   * generic disclaimer this whole product refuses to post.
   */
  const commentMode = env('CREDDA_COMMENT', 'true');
  const willComment = commentMode !== 'false' && spoke && entitled;

  let commentFile = '';
  if (spoke) {
    commentFile = join(work, 'decline-reply.md');
    writeFileSync(commentFile, `${comment}\n\n${footer()}\n`, 'utf8');
  }

  const verdict = willComment
    ? 'This decline reply was posted as a comment on the issue.'
    : spoke
      ? `A decline reply was produced but not posted (${entitled ? `comment is '${commentMode}'` : 'this private repository has no licence'}). It follows in full.`
      : 'Credda had nothing specific to ask for in this report, so nothing was posted. That is the correct outcome for about half of all issues.';
  writeSummary(`${verdict}

${spoke ? readFileSync(commentFile, 'utf8') : ''}
`);

  output('issue-number', String(issue.number));
  // Triage runs nothing and produces no patch, so it can never deliver one. The
  // output is written rather than left unset so the delivery step reads one
  // answer whichever mode ran, exactly as the posting step does.
  output('deliver', 'false');
  output('patch-path', '');
  output('triage-outcome', spoke ? 'COMMENT' : 'SILENT');
  output('should-post', willComment ? 'true' : 'false');
  output('comment-path', commentFile);
  output('body-path', commentFile);
}

/**
 * The two sentences appended to a decline reply, which the renderer does not
 * write and must not.
 *
 * The decline-reply renderer is a pure function pinned by golden files, and it
 * has no idea it is running inside an Action, which label triggers the
 * investigation, or that there is a job to link to. Those are facts about this
 * deployment, so they are added by this deployment.
 *
 * The label sentence is the whole answer to "what happens when an issue is
 * opened and then labelled". Without it, a decline reply followed by a full
 * report reads as two bots that have never met; with it, the report is the
 * thing the reply said could be asked for.
 */
function footer() {
  const invite = anyLabel
    ? 'A maintainer can label this issue to have Credda check it out, run what it can in a sandbox, and report what it did and did not establish.'
    : `A maintainer can add the \`${primaryLabel}\` label to have Credda check this repository out, run what it can in a sandbox, and report what it did and did not establish.`;
  return `---\n\nNothing was run to produce this note; it comes from reading the report alone. ${invite}\n\n[Action run](${runUrl()})`;
}

/* -------------------------------- dispatch -------------------------------- */

if (mode === 'triage') {
  await triage();
} else if (mode === 'investigate') {
  await investigate();
} else {
  console.error(`CREDDA_MODE is '${mode}'. It must be 'investigate' or 'triage'.`);
  process.exit(1);
}
