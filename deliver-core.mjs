// The push-and-open-a-pull-request logic, as a pure-of-environment function two
// callers share.
//
// WHY THIS FILE EXISTS, AND WHY IT READS NO ENVIRONMENT. `deliver-pr.mjs` used
// to hold both the reading of the environment (which patch, which issue) AND the
// git/gh machinery that pushes a branch and opens a proposal. `sweep.mjs` needs
// the second half without the first: it delivers many candidates in one run, so
// there is no single `CREDDA_PATCH_PATH` to read, and it is reached from
// `run.mjs`'s own step rather than from the delivery step. `.github/check-manifest.rb`
// assertion 7 scans every module a step's script imports and requires each
// environment name read there to be set by that step's `env:` block -- so if the
// shared push logic read `process.env`, every name it read would have to be added
// to the `Run Credda` step too, for the sweep path, where those names do not
// belong. The way to be immune rather than careful is for this file to read NO
// environment at all: everything it needs arrives as an argument, and the two
// callers each read their own configuration in their own place.
//
// EVERY GUARDRAIL THE ORIGINAL HAD IS HERE UNCHANGED. No force-push on any path.
// An existing branch with an open pull request means the proposal already exists
// and this says so and stops. An existing branch with no open pull request means
// a human has been in there, and this refuses and names the branch. A `gh pr list`
// that FAILED is never read as "no open proposal". Nothing a reporter typed
// reaches a shell: every command is an argv array with no shell, and the body is
// passed as `--body-file`. Credda proposes and never merges: there is no merge
// call here.
//
// WHAT CHANGED IS ONLY THE SHAPE OF THE ANSWER. The original `process.exit`ed and
// wrote the job summary itself. This RETURNS a decision -- `opened`,
// `already-proposed` or `refused`, with the human sentence and, for a refusal,
// whether it was one GitHub named (a permission or protection refusal, which
// tells a sweep to stop attempting the rest) or one specific to this candidate (a
// patch that does not apply, which does not). The caller decides what a refusal
// means for the job: `deliver-pr.mjs` reddens it, exactly as before, and
// `sweep.mjs` records it and carries on.

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';

import { explainForgeRefusal } from './delivery.mjs';

/** Runs a command with no shell, in the given checkout, and returns its status. */
function run(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    // The runner's own environment, unmodified. `gh` reads its token from it,
    // and `git` reads the credential `actions/checkout` persisted on `origin`.
    // Passed as the whole object rather than by name so this module reads no
    // environment variable of its own -- see the file header.
    env: process.env,
    maxBuffer: 32 * 1024 * 1024,
  });
  const said = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  return { status: result.status, out: String(result.stdout ?? '').trim(), said };
}

/** A refusal decision, tagging whether GitHub named it (so a sweep can stop). */
function refused(headline, detail, said) {
  return {
    outcome: 'refused',
    message: headline,
    detail: detail ?? '',
    // A forge refusal (a missing scope, a protected branch, no credential) is
    // the same answer for every candidate in a sweep, so the caller stops
    // attempting the rest. A patch that does not apply is specific to one
    // candidate, and the caller carries on to the next.
    forgeRefusal: said !== undefined && explainForgeRefusal(said) !== null,
    url: '',
  };
}

/**
 * Pushes a verified patch to a deterministic branch and opens a pull request for
 * it, on the customer's own runner with the customer's own credentials.
 *
 * Reads no environment. Returns a decision and never exits the process.
 *
 * @param {{
 *   workspace: string,
 *   repository: string,
 *   branch: string,
 *   patchPath: string,
 *   bodyPath: string,
 *   commitSubject: string,
 *   commitBody: string,
 *   prTitle: string,
 * }} input
 * @returns {{ outcome: 'opened'|'already-proposed'|'refused', message: string, detail: string, url: string, forgeRefusal: boolean }}
 */
export function deliverPullRequest({
  workspace,
  repository,
  branch,
  patchPath,
  bodyPath,
  commitSubject,
  commitBody,
  prTitle,
}) {
  if (!existsSync(patchPath)) {
    return refused(
      'The verified patch is not on disk, so nothing was pushed.',
      `Expected it at ${patchPath}. The step that runs Credda writes it and fails loudly when it ` +
        'cannot, so reaching here means the action manifest is wired wrong rather than that a run ' +
        'failed quietly.',
    );
  }

  const diff = readFileSync(patchPath, 'utf8');
  if (diff.trim() === '') {
    return refused(
      'The verified patch is empty, so there is nothing to propose.',
      'An empty document and an empty change are different facts, and opening a pull request ' +
        'containing no change would be a claim with nothing behind it.',
    );
  }

  const head = run('git', ['rev-parse', 'HEAD'], workspace);
  if (head.status !== 0) {
    return refused(
      'The workspace is not a git checkout, so no branch could be cut.',
      'This action expects `actions/checkout` to have run before it. ' + head.said,
    );
  }

  // Does the branch already exist on the remote? Asked before anything is
  // created, and answered without writing.
  const remote = run('git', ['ls-remote', '--heads', 'origin', `refs/heads/${branch}`], workspace);
  if (remote.status !== 0) {
    const named = explainForgeRefusal(remote.said);
    return refused(
      named ?? 'Could not read the remote, so nothing was pushed.',
      named === null ? remote.said : '',
      remote.said,
    );
  }

  if (remote.out !== '') {
    // An existing branch is never overwritten.
    const open = run(
      'gh',
      [
        'pr', 'list',
        '--repo', repository,
        '--head', branch,
        '--state', 'open',
        '--json', 'url',
        '--jq', '.[0].url // ""',
      ],
      workspace,
    );

    // A query that FAILED is not an answer of "none".
    if (open.status !== 0) {
      const named = explainForgeRefusal(open.said);
      return refused(
        `Credda could not ask GitHub whether a pull request is already open for \`${branch}\`, so nothing was pushed.`,
        named ??
          'The branch exists and may or may not have an open proposal on it, and Credda will not ' +
            'force-push over a branch whose state it cannot read. Check that the workflow grants ' +
            '`pull-requests: read` and that the run is authenticated, then re-run. No branch needs ' +
            `deleting on the strength of this message. GitHub said: ${open.said.trim()}`,
        open.said,
      );
    }

    if (open.out !== '') {
      return {
        outcome: 'already-proposed',
        message:
          `Credda already proposed this fix: ${open.out}. The branch \`${branch}\` is the one that ` +
          'pull request is built from, and this re-run pushed nothing over it.',
        detail: '',
        url: open.out,
        forgeRefusal: false,
      };
    }

    return refused(
      `The branch \`${branch}\` already exists and has no open pull request, so nothing was pushed.`,
      'Credda will not force-push over a branch: a closed proposal, a maintainer\'s own commit and ' +
        'an abandoned experiment all look like this, and overwriting any of them is the one thing ' +
        'here that cannot be undone. Delete or rename the branch to have the next run propose again.',
    );
  }

  // The identity on the commit: Credda, not the person who triggered the run.
  run('git', ['config', 'user.name', 'Credda'], workspace);
  run('git', ['config', 'user.email', 'credda@users.noreply.github.com'], workspace);

  const created = run('git', ['checkout', '-b', branch], workspace);
  if (created.status !== 0) {
    return refused(`Could not create the branch \`${branch}\`, so nothing was pushed.`, created.said, created.said);
  }

  // --index so the commit carries exactly what was verified.
  const applied = run('git', ['apply', '--index', '--whitespace=nowarn', patchPath], workspace);
  if (applied.status !== 0) {
    return refused(
      'The verified patch does not apply to this checkout, so nothing was committed.',
      'This is a finding about the run rather than a permission problem: the tree the patch was ' +
        'proven against and the tree in this job are not the same. The patch is in the report ' +
        'comment and on the job summary, unchanged.\n\n' +
        applied.said,
    );
  }

  const committed = run('git', ['commit', '-m', commitSubject, '-m', commitBody], workspace);
  if (committed.status !== 0) {
    return refused('Nothing was committed.', committed.said, committed.said);
  }

  const pushed = run('git', ['push', 'origin', `HEAD:refs/heads/${branch}`], workspace);
  if (pushed.status !== 0) {
    const named = explainForgeRefusal(pushed.said);
    return refused(
      named ?? `Could not push \`${branch}\`, so no pull request was opened.`,
      named === null ? pushed.said : '',
      pushed.said,
    );
  }

  // The base branch, asked for rather than assumed; a failure to read it is not
  // fatal -- the default is then gh's own.
  const base = run(
    'gh',
    ['repo', 'view', repository, '--json', 'defaultBranchRef', '--jq', '.defaultBranchRef.name // ""'],
    workspace,
  );

  const args = [
    'pr', 'create',
    '--repo', repository,
    '--head', branch,
    '--title', prTitle,
    '--body-file', bodyPath,
  ];
  if (base.status === 0 && base.out !== '') args.push('--base', base.out);

  const opened = run('gh', args, workspace);
  if (opened.status !== 0) {
    const named = explainForgeRefusal(opened.said);
    return refused(
      named ?? `The branch \`${branch}\` was pushed, but the pull request could not be opened.`,
      named === null ? opened.said : '',
      opened.said,
    );
  }

  const url = opened.out.split('\n').filter((line) => line.startsWith('http')).at(-1) ?? '';
  return {
    outcome: 'opened',
    message:
      `Credda opened a pull request from \`${branch}\`${url === '' ? '' : `: ${url}`}. It carries the ` +
      'patch and the regression test that failed before it and passes after. Credda proposes; ' +
      'nothing here merges anything.',
    detail: '',
    url,
    forgeRefusal: false,
  };
}
