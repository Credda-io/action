// Pushes a proven fix and opens a pull request, on the customer's own runner
// with the customer's own token. THE SINGLE-INVESTIGATE ENTRY POINT.
//
// WHAT THIS IS, IN ONE PARAGRAPH. Everything before this step reproduces a
// reported bug, diagnoses it, writes a patch and proves the patch with a
// regression test that FAILED on the unpatched tree and PASSED after. Until
// 2026-08-29 that proof reached the customer as text inside an issue comment
// and went no further: somebody had to copy a diff out of a comment. This step
// commits it instead. It is OPT-IN and OFF BY DEFAULT, because the sentence
// that lets a stranger paste the published workflow without reading it is "the
// default install cannot write to your repository", and that sentence has to
// stay true.
//
// WHOSE CREDENTIAL DOES THIS USE. The customer's, and only the customer's.
// `GITHUB_TOKEN` is minted by GitHub for this job, in this repository, and the
// scopes it carries are whatever the calling workflow's `permissions:` block
// granted. Credda has no OAuth app here, no GitHub App, no key of its own, and
// no copy of the repository. If the customer does not grant `contents: write`
// and `pull-requests: write`, this step fails with a message naming those two
// lines and nothing is pushed. That is the correct outcome, not a bug.
//
// CREDDA PROPOSES AND NEVER MERGES. There is no merge call anywhere on this
// path, no `--auto`, no `gh pr merge`, no review approval, and no
// branch-protection bypass. A test asserts that. The pull request is a claim
// made to a human, and the human decides.
//
// WHERE THE GUARDRAILS NOW LIVE, AND WHY THIS FILE GOT SHORTER. The git and gh
// machinery -- the deterministic branch, the no-force-push rule, the
// already-open-proposal check, the named forge refusals -- moved to
// `deliver-core.mjs` as `deliverPullRequest`, unchanged, so that `sweep.mjs`
// can push its own per-candidate proposals through exactly the same code rather
// than a second copy of it. This file is now the SINGLE-INVESTIGATE HALF: it
// reads this run's one patch, issue number and body out of the environment,
// names the branch from the issue number, and maps the shared function's
// decision back to the exit code and job-summary shape this step has always
// had -- a refusal reddens the job, an opened or already-open proposal is a
// green success. Nothing about the single-investigate outcome changed.
//
// UNTRUSTED TEXT, THE SAME RULE AS EVERYWHERE ELSE. Nothing a reporter typed
// reaches a shell: `deliverPullRequest` spawns every command as an argv array
// with no shell, passes the body as `--body-file`, and this file composes the
// title from an integer it parses itself.

import { appendFileSync } from 'node:fs';

import { deliverPullRequest } from './deliver-core.mjs';
import { branchNameFor, pullRequestTitle } from './delivery.mjs';

function env(name, fallback = null) {
  const value = process.env[name];
  if (value !== undefined && value !== '') return value;
  if (fallback !== null) return fallback;
  console.error(`${name} is not set. This script only runs inside a GitHub Actions job.`);
  process.exit(1);
}

function summary(text) {
  const file = process.env['GITHUB_STEP_SUMMARY'];
  if (file !== undefined && file !== '') appendFileSync(file, text, 'utf8');
}

/**
 * Stops with a named refusal rather than a stack trace.
 *
 * A refusal is written to the job summary as well as the log, because the
 * summary is where the person who installed Credda looks and the log is where
 * they do not. Exits 1: the customer asked for a pull request, they did not get
 * one, and a green job would be this action denying something it failed to do.
 */
function refuse(headline, detail) {
  console.error(`::error::${headline}`);
  if (detail !== undefined && detail !== '') console.error(detail);
  summary(`### Credda did not open a pull request\n\n${headline}\n\n${detail ?? ''}\n`);
  process.exit(1);
}

const workspace = env('GITHUB_WORKSPACE');
const patchPath = env('CREDDA_PATCH_PATH');
const bodyPath = env('CREDDA_BODY_PATH');
const issueNumber = env('CREDDA_ISSUE_NUMBER');
const repository = env('GITHUB_REPOSITORY');

// Through `refuse` rather than as a throw. `branchNameFor` is strict about the
// issue number on purpose and throws a sentence written for a customer, and an
// uncaught throw here prints it as a stack trace with no annotation and nothing
// on the job summary -- which is the one shape this file's own `refuse` exists
// to avoid.
let branch;
try {
  branch = branchNameFor(issueNumber);
} catch (error) {
  refuse('Credda could not name a branch for this proposal, so nothing was pushed.', error.message);
}

const decision = deliverPullRequest({
  workspace,
  repository,
  branch,
  patchPath,
  bodyPath,
  commitSubject: `Credda: a verified fix for issue #${String(Number.parseInt(issueNumber, 10))}`,
  commitBody:
    'Written and verified by Credda. The regression test in this commit failed on the unpatched ' +
    'tree and passes on this one. Credda proposes; a human decides.',
  prTitle: pullRequestTitle(issueNumber),
});

if (decision.outcome === 'refused') {
  refuse(decision.message, decision.detail);
}

if (decision.outcome === 'already-proposed') {
  console.log(decision.message);
  summary(`### Credda has already proposed this fix\n\n${decision.message}\n`);
  process.exit(0);
}

console.log(decision.message);
summary(`### Credda opened a pull request\n\n${decision.message}\n`);
