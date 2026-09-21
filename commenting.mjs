// The sentence a customer gets when posting the report fails.
//
// WHY THIS FILE IS SEPARATE FROM THE STEP THAT POSTS. The same split as
// `delivery.mjs`/`deliver-pr.mjs` and `notification.mjs`/`notify.mjs`, for the
// same reason: everything here is a pure function of one string, so it can be
// tested with no network, no token and no runner, by `.github/comment.test.mjs`.
//
// WHY IT EXISTS AT ALL. Posting the report is the thing this product owes, and
// it was the one failure in the whole action that said nothing about itself.
// The step ran `gh issue comment` bare: a job missing `issues: write` -- the
// single likeliest mistake in a hand-written workflow -- ended with
//
//     gh: Resource not accessible by integration (HTTP 403)
//
// and nothing else. No annotation, so the failure had no entry in the list a
// person reads before opening the log; nothing on the job summary, where every
// other refusal in this action writes; and no mention anywhere of the two words
// that fix it. README.md's "How it fails" opens by asserting that every failure
// names its own cause on the first line of the annotation, and had no row for
// this step at all -- the assertion was true of every failure the table listed
// and false of the one it had forgotten.
//
// THE RULE THESE FOLLOW is `explainForgeRefusal`'s in delivery.mjs: name the
// switch somebody has to change, in the vocabulary of the settings page rather
// than of the API, and return null for anything unrecognised so the caller
// quotes what gh actually said. Inventing a diagnosis for an unknown error is
// worse than quoting it.

/**
 * What to tell a customer whose report comment was refused, or null when the
 * failure is not one of the known ones.
 *
 * ORDER MATTERS, AND IT IS THE POINT OF THE FIRST TWO CLAUSES. A rate limit and
 * a missing permission are both 403, and they need opposite remedies -- "wait
 * and re-run" against "add a line to your workflow". Testing for the generic
 * 403 first would tell every rate-limited customer to grant a permission they
 * already have.
 *
 * @param {string} text combined stdout and stderr of the failed command
 * @returns {string|null}
 */
export function explainCommentRefusal(text) {
  const said = String(text ?? '');

  if (/rate limit|secondary rate|abuse detection|was submitted too quickly/i.test(said)) {
    return (
      'GitHub rate-limited the report comment, so it was not posted. This is not a permission ' +
      'problem and granting one will not help: the token this job holds has spent its allowance ' +
      'for this hour. Re-run the job later. The report itself is on the job summary of this run ' +
      'and is not lost.'
    );
  }

  if (/GH_TOKEN|GITHUB_TOKEN environment variable|authentication token not found|must be authenticated|gh auth login/i.test(said)) {
    return (
      'The gh CLI had no token to post with, so the report was not posted. The `github-token` ' +
      'input defaults to `${{ github.token }}` and needs nothing set; an empty value here means ' +
      'the workflow passed `github-token:` explicitly from a secret that does not exist in this ' +
      'repository, which evaluates to the empty string rather than to an error. Remove the input ' +
      'to use the job\'s own token, or check the secret name.'
    );
  }

  if (/Issues are disabled|has disabled issues/i.test(said)) {
    return (
      'This repository has its issue tracker turned off, so there is nothing to comment on. ' +
      'Credda reproduces from an issue and reports back to it; with issues disabled there is no ' +
      'thread for the report. The report is on the job summary of this run.'
    );
  }

  if (/repository was archived|archived repository|Repository .* is archived/i.test(said)) {
    return (
      'This repository is archived, so GitHub refuses every write to it including a comment. ' +
      'Nothing in the workflow can change that; unarchive the repository, or set `comment: false` ' +
      'so Credda reports to the job summary alone.'
    );
  }

  if (/Could not resolve to an Issue|Not Found \(HTTP 404\)|HTTP 404/i.test(said)) {
    return (
      'GitHub could not find the issue this report belongs to. Either it was deleted or ' +
      'transferred while the run was in progress, or the token this job holds cannot see it. The ' +
      'report is on the job summary of this run and nothing about it is lost.'
    );
  }

  if (/Resource not accessible by integration|HTTP 403|not authorized|Permission .* denied/i.test(said)) {
    return (
      'GitHub refused the report comment because the token this job was given may not write ' +
      'issues. Add `issues: write` to the calling workflow\'s `permissions:` block -- it is in ' +
      'the published install and is the line most often dropped when a workflow is written by ' +
      'hand:\n\n' +
      '    permissions:\n' +
      '      contents: read\n' +
      '      issues: write\n' +
      '      id-token: write\n\n' +
      'A workflow triggered by `pull_request` from a FORK is the one case where adding the line ' +
      'does not help: GitHub hands those runs a read-only token whatever the block says. Trigger ' +
      'Credda on `issues` rather than on a fork\'s pull request, or set `comment: false` and read ' +
      'the report on the job summary.'
    );
  }

  if (/dial tcp|connection refused|i\/o timeout|no such host|TLS handshake|EAI_AGAIN|network is unreachable/i.test(said)) {
    return (
      'The runner could not reach GitHub\'s API to post the comment, so the report was not ' +
      'posted. This is a network failure on the runner rather than anything about your ' +
      'repository or your permissions. Re-running the job usually clears it; the report is on ' +
      'the job summary of this run.'
    );
  }

  return null;
}
