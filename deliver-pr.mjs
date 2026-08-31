// Pushes a proven fix and opens a pull request, on the customer's own runner
// with the customer's own token.
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
// CREDDA PROPOSES AND NEVER MERGES. There is no merge call in this file, no
// `--auto`, no `gh pr merge`, no review approval, and no branch-protection
// bypass. A test asserts that. The pull request is a claim made to a human, and
// the human decides.
//
// THE ONE THING THAT MUST NEVER HAPPEN HERE is clobbering somebody's work. The
// branch name is deterministic (see `delivery.mjs`), so a re-run on the same
// issue meets the branch its previous run pushed. There is no force-push on any
// path in this file: an existing branch with an open pull request means the
// proposal already exists and this run says so and stops; an existing branch
// with no open pull request means a human has been in there, and this run
// refuses and names the branch rather than overwriting it.
//
// UNTRUSTED TEXT, THE SAME RULE AS EVERYWHERE ELSE. Nothing a reporter typed
// reaches a shell. Every command below is spawned as an argv array with no
// shell, the pull request body is passed as `--body-file`, and the title is
// composed from an integer this script parses itself.

import { spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, readFileSync } from 'node:fs';

import { branchNameFor, explainForgeRefusal, pullRequestTitle } from './delivery.mjs';

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

/** Runs a command with no shell, and returns its status and combined output. */
function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? workspace,
    encoding: 'utf8',
    env: { ...process.env, ...(options.env ?? {}) },
    maxBuffer: 32 * 1024 * 1024,
  });
  const said = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  return { status: result.status, out: String(result.stdout ?? '').trim(), said };
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

if (!existsSync(patchPath)) {
  refuse(
    'The verified patch is not on disk, so nothing was pushed.',
    `Expected it at ${patchPath}. The step that runs Credda writes it and fails loudly when it ` +
      'cannot, so reaching here means the action manifest is wired wrong rather than that a run ' +
      'failed quietly.',
  );
}

const diff = readFileSync(patchPath, 'utf8');
if (diff.trim() === '') {
  refuse(
    'The verified patch is empty, so there is nothing to propose.',
    'An empty document and an empty change are different facts, and opening a pull request ' +
      'containing no change would be a claim with nothing behind it.',
  );
}

// Through `refuse` rather than as a throw. `branchNameFor` is strict about the
// issue number on purpose and throws a sentence written for a customer, and an
// uncaught throw here prints it as a stack trace with no annotation and nothing
// on the job summary -- which is the one shape this file's own `refuse` exists
// to avoid. Unreachable in practice, since the number comes from the event
// payload; the handling is here because "unreachable" is what every other
// stack trace in a red job was too.
let branch;
try {
  branch = branchNameFor(issueNumber);
} catch (error) {
  refuse('Credda could not name a branch for this proposal, so nothing was pushed.', error.message);
}

/*
 * The commit this branch starts from.
 *
 * A workflow triggered by `issues: labeled` runs on the DEFAULT BRANCH, and the
 * checkout in the job is the tree the engine reproduced the bug against and
 * verified the patch on. So the branch is cut from HEAD of that checkout and
 * from nothing else: cutting it from the remote default branch instead would
 * mean proposing a diff that was proven against a different tree from the one it
 * would be applied to, which is the whole failure this product exists to stop
 * other tools doing.
 */
const head = run('git', ['rev-parse', 'HEAD']);
if (head.status !== 0) {
  refuse(
    'The workspace is not a git checkout, so no branch could be cut.',
    'This action expects `actions/checkout` to have run before it. ' + head.said,
  );
}

/*
 * Does the branch already exist on the remote?
 *
 * Asked before anything is created, and answered without writing. A re-run on
 * the same issue is the normal case, not the exception -- a label removed and
 * re-applied fires the workflow again -- so meeting an existing branch has to be
 * an outcome this script handles rather than an error it produces.
 */
const remote = run('git', ['ls-remote', '--heads', 'origin', `refs/heads/${branch}`]);
if (remote.status !== 0) {
  const named = explainForgeRefusal(remote.said);
  refuse(
    named ?? 'Could not read the remote, so nothing was pushed.',
    named === null ? remote.said : '',
  );
}
const branchExists = remote.out !== '';

if (branchExists) {
  /*
   * An existing branch is never overwritten. Two cases, and the difference
   * matters to the person reading this:
   *
   *   - a pull request is already open from it: the proposal exists, this run
   *     has nothing to add, and saying "already proposed" with the link is the
   *     honest end of the job. Exits 0, because nothing failed.
   *   - no open pull request: somebody closed it, or pushed to the branch, or
   *     is working on it. Force-pushing over that is the one unrecoverable
   *     thing this script could do, so it refuses and names the branch.
   */
  const open = run('gh', [
    'pr', 'list',
    '--repo', repository,
    '--head', branch,
    '--state', 'open',
    '--json', 'url',
    '--jq', '.[0].url // ""',
  ]);

  if (open.status === 0 && open.out !== '') {
    const line =
      `Credda already proposed this fix: ${open.out}. The branch \`${branch}\` is the one that ` +
      'pull request is built from, and this re-run pushed nothing over it.';
    console.log(line);
    summary(`### Credda has already proposed this fix\n\n${line}\n`);
    process.exit(0);
  }

  refuse(
    `The branch \`${branch}\` already exists and has no open pull request, so nothing was pushed.`,
    'Credda will not force-push over a branch: a closed proposal, a maintainer\'s own commit and ' +
      'an abandoned experiment all look like this, and overwriting any of them is the one thing ' +
      'here that cannot be undone. Delete or rename the branch to have the next run propose again.',
  );
}

/*
 * The identity on the commit.
 *
 * Named as Credda rather than borrowed from the person who applied the label. A
 * commit is attributable and this one was written by a machine; putting a
 * maintainer's name on it would make them the author of a diff they have not
 * read yet.
 */
run('git', ['config', 'user.name', 'Credda']);
run('git', ['config', 'user.email', 'credda@users.noreply.github.com']);

const created = run('git', ['checkout', '-b', branch]);
if (created.status !== 0) {
  refuse(`Could not create the branch \`${branch}\`, so nothing was pushed.`, created.said);
}

/*
 * Applying the diff, with --index so the commit carries exactly what was
 * verified and nothing the runner happened to leave lying around.
 *
 * A failure here is not a permission problem and must not be reported as one:
 * it means the diff does not apply to this tree, which is a real finding about
 * the run and is said as such.
 */
const applied = run('git', ['apply', '--index', '--whitespace=nowarn', patchPath]);
if (applied.status !== 0) {
  refuse(
    'The verified patch does not apply to this checkout, so nothing was committed.',
    'This is a finding about the run rather than a permission problem: the tree the patch was ' +
      'proven against and the tree in this job are not the same. The patch is in the report ' +
      'comment and on the job summary, unchanged.\n\n' +
      applied.said,
  );
}

const committed = run('git', [
  'commit',
  '-m',
  `Credda: a verified fix for issue #${String(Number.parseInt(issueNumber, 10))}`,
  '-m',
  'Written and verified by Credda. The regression test in this commit failed on the unpatched ' +
    'tree and passes on this one. Credda proposes; a human decides.',
]);
if (committed.status !== 0) {
  refuse('Nothing was committed.', committed.said);
}

const pushed = run('git', ['push', 'origin', `HEAD:refs/heads/${branch}`]);
if (pushed.status !== 0) {
  const named = explainForgeRefusal(pushed.said);
  refuse(
    named ?? `Could not push \`${branch}\`, so no pull request was opened.`,
    named === null ? pushed.said : '',
  );
}

/*
 * The base branch, asked for rather than assumed.
 *
 * `gh pr create` defaults to the repository's default branch, which is what this
 * wants in nearly every case; it is asked for explicitly so the pull request
 * cannot be opened against whatever branch the checkout happened to leave as the
 * remote HEAD. A failure to read it is not fatal -- the default is then gh's own.
 */
const base = run('gh', [
  'repo', 'view', repository,
  '--json', 'defaultBranchRef',
  '--jq', '.defaultBranchRef.name // ""',
]);

const args = [
  'pr', 'create',
  '--repo', repository,
  '--head', branch,
  '--title', pullRequestTitle(issueNumber),
  // The body is the report Credda already rendered: what it reproduced, what it
  // could not establish, and the verification behind the change. Passed as a
  // file because shells truncate multi-line arguments and because that document
  // is the point of the pull request.
  '--body-file', bodyPath,
];
if (base.status === 0 && base.out !== '') args.push('--base', base.out);

const opened = run('gh', args);
if (opened.status !== 0) {
  const named = explainForgeRefusal(opened.said);
  refuse(
    named ??
      `The branch \`${branch}\` was pushed, but the pull request could not be opened.`,
    named === null ? opened.said : '',
  );
}

const url = opened.out.split('\n').filter((line) => line.startsWith('http')).at(-1) ?? '';
const line =
  `Credda opened a pull request from \`${branch}\`${url === '' ? '' : `: ${url}`}. It carries the ` +
  'patch and the regression test that failed before it and passes after. Credda proposes; ' +
  'nothing here merges anything.';
console.log(line);
summary(`### Credda opened a pull request\n\n${line}\n`);
