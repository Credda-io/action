/*
 * What a customer reads when the report comment is refused.
 *
 * WHY THIS ONE LIVES HERE, beside `notify.test.mjs` and for the same reason:
 * `commenting.mjs` is a pure function of one string, `node --test` is Node's
 * own runner, and this repository installs nothing. The half that touches a
 * runner is `comment-failure.mjs`, and what it does -- annotate, summarise,
 * exit 1 -- is three lines with no branching worth a harness.
 *
 * EVERY CASE BELOW IS A REAL MESSAGE. Each `said` string is the text gh or the
 * API actually produces for that failure, not a paraphrase of it, because a
 * matcher tested against an invented sentence is a matcher that has only been
 * tested against itself.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { explainCommentRefusal } from '../commenting.mjs';

describe('a refused report comment names the fix', () => {
  it('names `issues: write` when the token may not write issues', () => {
    const said = explainCommentRefusal('gh: Resource not accessible by integration (HTTP 403)');
    assert.notEqual(said, null);
    assert.match(said, /issues: write/);
  });

  it('warns that a fork PR is the case adding the line does not fix', () => {
    const said = explainCommentRefusal('gh: Resource not accessible by integration (HTTP 403)');
    assert.match(said, /fork/i);
    assert.match(said, /read-only/i);
  });

  /*
   * THE ONE ORDERING THIS FILE EXISTS FOR. A rate limit and a missing
   * permission are both 403 and need opposite remedies. Matching the generic
   * 403 first would tell every rate-limited customer to grant a permission
   * they already hold, which is a wrong instruction rather than a vague one.
   */
  it('does not call a rate limit a permission problem', () => {
    const said = explainCommentRefusal(
      'gh: API rate limit exceeded for installation ID 12345. (HTTP 403)',
    );
    assert.match(said, /rate-limited/i);
    assert.doesNotMatch(said, /issues: write/);
  });

  it('does not call a secondary rate limit a permission problem', () => {
    const said = explainCommentRefusal(
      'gh: You have exceeded a secondary rate limit and have been temporarily blocked from content creation. (HTTP 403)',
    );
    assert.match(said, /rate-limited/i);
    assert.doesNotMatch(said, /issues: write/);
  });

  it('blames an empty github-token rather than a permission', () => {
    const said = explainCommentRefusal(
      'gh: To use GitHub CLI in a GitHub Actions workflow, set the GH_TOKEN environment variable.',
    );
    assert.match(said, /github-token/);
    assert.doesNotMatch(said, /issues: write/);
  });

  it('names an archived repository as the cause when it is one', () => {
    const said = explainCommentRefusal(
      'gh: Repository was archived so is read-only. (HTTP 403)',
    );
    assert.match(said, /archived/i);
    assert.doesNotMatch(said, /issues: write/);
  });

  it('names a disabled issue tracker as the cause when it is one', () => {
    const said = explainCommentRefusal('gh: Issues are disabled for this repo (HTTP 410)');
    assert.match(said, /issue tracker/i);
  });

  it('does not blame the repository for a missing issue', () => {
    const said = explainCommentRefusal(
      'gh: Could not resolve to an Issue with the number of 41.',
    );
    assert.match(said, /deleted or\s+transferred|deleted/i);
    assert.doesNotMatch(said, /issues: write/);
  });

  it('does not blame permissions for a network failure', () => {
    const said = explainCommentRefusal(
      'error connecting to api.github.com: dial tcp: lookup api.github.com: no such host',
    );
    assert.match(said, /network/i);
    assert.doesNotMatch(said, /issues: write/);
  });

  /*
   * The rule delivery.mjs's `explainForgeRefusal` states: inventing a
   * diagnosis for an error nobody recognises is worse than quoting it, so an
   * unknown returns null and the caller prints what gh said.
   */
  it('returns null for a failure it does not recognise', () => {
    assert.equal(explainCommentRefusal('gh: something nobody has seen before'), null);
    assert.equal(explainCommentRefusal(''), null);
    assert.equal(explainCommentRefusal(undefined), null);
  });

  /*
   * Every named refusal says where the report still is. A customer whose
   * comment failed has not lost the document -- run.mjs wrote it to the job
   * summary before this step ran -- and the message that does not say so
   * invites them to re-run a thirty-minute reproduction to get it back.
   */
  it('every named refusal says the report is not lost', () => {
    const messages = [
      'gh: Resource not accessible by integration (HTTP 403)',
      'gh: API rate limit exceeded for installation ID 12345. (HTTP 403)',
      'gh: Issues are disabled for this repo (HTTP 410)',
      'gh: Repository was archived so is read-only. (HTTP 403)',
      'gh: Could not resolve to an Issue with the number of 41.',
      'error connecting to api.github.com: dial tcp: no such host',
    ].map((one) => explainCommentRefusal(one));

    // Asserted before the loop, so an empty list cannot pass this by having
    // nothing to check.
    assert.equal(messages.length, 6);
    for (const said of messages) {
      assert.notEqual(said, null);
      assert.match(said, /job summary|comment: false/);
    }
  });
});
