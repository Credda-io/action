// The decisions behind delivering a proven fix as a pull request.
//
// WHY THIS FILE IS SEPARATE FROM THE SCRIPT THAT PUSHES. Everything here is a
// pure function of values: whether to deliver, what to call the branch, and
// what to say when the answer is no. `deliver-pr.mjs` is the half that touches
// git, the network and a customer's repository, and it can only be exercised
// against a real repository. This half can be tested, and it is -- by
// `core/apps/cli/test/action-delivery.test.ts`, which imports this file out of
// the sibling checkout the way the other Action tests read `action.yml` and
// `run.mjs`. The gate that decides whether a stranger's repository gets a
// branch pushed to it is the last thing that should be reachable only through
// a live GitHub token.
//
// WHAT IS NOT DECIDED HERE, AND MUST NOT BE. Whether the run produced a change
// worth proposing. That is `carriesVerifiedChange` in the engine, computed on
// the executed record -- the terminal state, the patch row that survived, the
// verification verdict, and the regression test's FAIL-then-PASS pair -- and it
// arrives on the result file as `delivery.deliverable`. This file reads that
// boolean and never re-derives it, for the same reason `run.mjs` reads
// `establishedSomething` rather than keeping its own list of outcomes: two
// opinions about one run is how a surface comes to claim something the report
// denies. A pull request is a much louder claim than a comment, so the rule is
// stricter here, not looser.

/**
 * Whether this run may be delivered as a pull request, and why not when it may
 * not.
 *
 * Three ways to a `false`, and all three are said out loud rather than logged
 * as "skipped":
 *
 *   1. The customer did not ask for it. This is the default and it is not a
 *      failure -- it is the reason the published workflow can be pasted by
 *      someone who has not read it.
 *   2. The run produced nothing proven to deliver. The engine's own sentence is
 *      used verbatim; this file does not paraphrase a verdict it did not reach.
 *   3. The result file is not shaped like one this version can read. An absent
 *      or malformed `delivery` block reads as "no", never as "probably yes" --
 *      an older engine that predates the block must not have its silence taken
 *      for consent to push.
 *
 * @param {{ enabled: boolean, result: unknown }} input
 * @returns {{ deliver: boolean, reason: string }}
 */
export function decideDelivery({ enabled, result }) {
  if (!enabled) {
    return {
      deliver: false,
      reason:
        'open-pull-request is off, which is the default. Nothing was pushed and no pull request ' +
        'was opened; the report above is the whole of what this run delivered.',
    };
  }

  const delivery = isObject(result) && isObject(result.delivery) ? result.delivery : null;
  if (delivery === null) {
    return {
      deliver: false,
      reason:
        'this run recorded no delivery evidence at all, so there is nothing to check a pull ' +
        'request against. That is what an engine older than the delivery block looks like, and ' +
        'an unknown is read as a no rather than as a yes.',
    };
  }

  if (delivery.deliverable !== true) {
    const why = typeof delivery.reason === 'string' && delivery.reason !== ''
      ? delivery.reason
      : 'the run did not reach a verified change';
    return {
      deliver: false,
      reason:
        `no pull request was opened because ${why}. A pull request is a claim that something ` +
        'was proven, and this run did not prove it.',
    };
  }

  return {
    deliver: true,
    reason:
      'the run reached a verified change: a patch survived the run, a verification ran, and the ' +
      'regression test failed before it and passed after.',
  };
}

/**
 * The branch a proposal is pushed to.
 *
 * DETERMINISTIC, and that is the whole of the idempotency argument. A workflow
 * triggered by `issues: labeled` fires again every time the label is removed and
 * re-applied, and a fresh branch per run would leave a repository carrying one
 * abandoned branch per re-label. The same issue produces the same name, so a
 * re-run meets its own previous branch and `deliver-pr.mjs` decides what to do
 * about it -- which is never to force-push over it.
 *
 * The issue number alone, not the investigation id: the id changes on every run
 * and would defeat the point. Nothing untrusted reaches this name -- an issue
 * NUMBER is an integer GitHub assigned, and it is coerced to one here rather
 * than trusted to be one.
 *
 * @param {number|string} issueNumber
 * @returns {string}
 */
export function branchNameFor(issueNumber) {
  const raw = String(issueNumber);
  // Strictly all digits, not `parseInt`'s prefix reading. `parseInt('1; rm -rf /')`
  // is 1, and a function that quietly accepts a string like that is a function
  // that has stopped checking its input -- even where the digits it salvages
  // would have produced a harmless name.
  const n = /^[0-9]+$/.test(raw) ? Number.parseInt(raw, 10) : Number.NaN;
  if (!Number.isInteger(n) || n <= 0) {
    throw new Error(
      `A pull request branch needs the issue number, and got '${String(issueNumber)}'. ` +
        'Nothing was pushed.',
    );
  }
  return `credda/fix-issue-${String(n)}`;
}

/**
 * The pull request title.
 *
 * NO CLOSING KEYWORD, deliberately. `Fix #12` in a title or body closes the
 * issue the moment somebody merges, and Credda proposes -- deciding that the
 * report is answered is a maintainer's act, not a side effect of a title this
 * script wrote. The issue number is still named so the two are findable from
 * each other.
 *
 * The reporter's own words are not interpolated. They are untrusted text, this
 * title is rendered in a dozen places nobody audits, and the title is not where
 * a maintainer learns what the bug was -- the linked issue is.
 *
 * @param {number|string} issueNumber
 * @returns {string}
 */
export function pullRequestTitle(issueNumber) {
  const n = Number.parseInt(String(issueNumber), 10);
  return `Credda: a verified fix for issue #${String(n)}`;
}

/**
 * The sentence a customer gets when GitHub refuses the proposal, in place of
 * the API's own.
 *
 * Each of these is a setting somebody has to change, and the raw message says
 * so in the vocabulary of the API rather than of the settings page. A red job
 * is where most people will read about this for the first time, so it names
 * the switch.
 *
 * Returns null when the failure is not one of the known refusals, and the
 * caller then prints what git or gh actually said -- inventing a diagnosis for
 * an error nobody recognises is worse than quoting it.
 *
 * @param {string} text combined stdout and stderr of the failed command
 * @returns {string|null}
 */
export function explainForgeRefusal(text) {
  const said = String(text ?? '');

  if (/not permitted to create or approve pull requests/i.test(said)) {
    return (
      'GitHub refused to open the pull request because this organisation (or this repository) ' +
      'has "Allow GitHub Actions to create and approve pull requests" turned OFF. An admin turns ' +
      'it on under Settings -> Actions -> General -> Workflow permissions. Nothing else is ' +
      'wrong: the branch and the commit were pushed, and a person can open the pull request ' +
      'from that branch by hand in the meantime.'
    );
  }

  if (/refusing to allow (a )?(GitHub App|OAuth App|an? integration)/i.test(said)) {
    return (
      'GitHub refused the push because the token this job was given may not write to this ' +
      'repository. Opening a pull request needs `contents: write` and `pull-requests: write` in ' +
      'the calling workflow\'s `permissions:` block -- see README.md, "Opening a pull request". ' +
      'They are not in the default install on purpose.'
    );
  }

  if (/403|Permission to .* denied|not authorized|Resource not accessible by integration/i.test(said)) {
    return (
      'GitHub returned a permission error. Opening a pull request needs BOTH `contents: write` ' +
      '(to push the branch) and `pull-requests: write` (to open the proposal) in the calling ' +
      "workflow's `permissions:` block, and the default install grants neither. Add them to the " +
      'workflow that runs Credda, not to anything of Credda\'s -- this job used your own ' +
      'GITHUB_TOKEN throughout.'
    );
  }

  if (/protected branch|required status check|branch protection/i.test(said)) {
    return (
      'A branch protection rule refused this push. Credda will not ask for a bypass and has no ' +
      'way to grant itself one; a maintainer decides whether the rule should exempt this branch ' +
      'prefix.'
    );
  }

  return null;
}

function isObject(value) {
  return typeof value === 'object' && value !== null;
}
