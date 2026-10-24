// The mode that discovers, reproduces, and PROPOSES -- the surface that makes
// Credda's autonomous loop ship pull requests.
//
// WHAT IT IS, AND WHAT IT IS BUILT OUT OF. `discover` reads a checkout and lists
// the defects nobody filed, and stops at the list. `investigate` takes ONE
// report and reproduces it in a sandbox. `sweep` is the two composed: it runs
// discover to get candidate reports, reproduces each of the first
// `max-candidates` of them exactly as `investigate` would, and -- for the ones
// that reach a VERIFIED change -- opens a pull request through the same
// `deliverPullRequest` the single-investigate path uses. It reimplements none of
// reproduce, fix, verify or push: those are the shipped engine verbs and
// `deliver-core.mjs`, called in a loop.
//
// WHY THE LOOP IS HERE AND NOT IN action.yml. A composite action cannot iterate
// a step over an unknown number of candidates, and the number is only known
// after discovery has run. So the loop is in this script, invoked from
// `run.mjs`'s one `Run Credda` step, and it calls the shared delivery function
// in-process. That is the reason `run.mjs`'s step is handed `GH_TOKEN` in sweep
// mode: the pull requests are opened from here, not from the separate delivery
// step, which sweep leaves switched off (`deliver` output stays `false`) so a
// single patch is not delivered a second time.
//
// THE GATE, AND WHY A DEFAULT INSTALL PROPOSES NOTHING. Delivery happens only
// when `open-pull-request` is on. Off -- the default -- sweep still discovers and
// reproduces, and the summary says of every verified candidate that it WOULD be
// proposed, but nothing is pushed and the run holds a token that cannot write.
// When it is on but the workflow granted no write scopes, the first push is
// refused by GitHub with a named message; sweep records it, stops attempting the
// rest, and stays green -- an autonomous sweep must not redden a whole run over a
// permission it was never granted, and the summary tells the operator exactly
// which two lines to add.
//
// THE GUARDRAILS, PRESERVED AND EXTENDED. `deliver-core.mjs` keeps every rule the
// single-investigate path has: a deterministic branch, no force-push ever, an
// existing open proposal met with "already proposed" and skipped, an existing
// branch with no open proposal refused rather than overwritten. Sweep adds the
// two a fan-out needs: a HARD CAP on how many candidates are ever touched
// (`max-candidates`, never unbounded), and a branch named deterministically and
// DISTINCTLY per candidate from its provenance (`branchNameForFinding`), so two
// findings can never collide on one branch and a re-run meets its own previous
// branches.
//
// SECURITY, THE SAME RULE AS EVERY OTHER MODE. A candidate report is text the
// engine wrote about the repository, and it reaches the CLI as a FILE (`@path`),
// never through a shell; the investigation's own output is bracketed in
// `::stop-commands::` exactly as `investigate` brackets it, so nothing in a
// candidate body can forge a workflow command.

import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

import { deliverPullRequest } from './deliver-core.mjs';
import { branchNameForFinding, decideDelivery, pullRequestTitleForFinding } from './delivery.mjs';

/** A guard token a candidate body cannot know, to suspend workflow commands. */
function guardToken() {
  return `credda-${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
}

/**
 * The whole of sweep. Everything it needs -- how to spawn the engine, where the
 * scratch directory is, how to write outputs and the summary -- arrives as
 * arguments, so this module reads no environment of its own (see
 * `.github/check-manifest.rb` assertion 7 and the header of `deliver-core.mjs`).
 *
 * @param {{
 *   credda: (args: string[], stdio: unknown) => { status: number|null, stdout: unknown, stderr: unknown, error?: Error },
 *   workspace: string,
 *   repository: string,
 *   sandbox: string,
 *   work: string,
 *   maxFiles: string,
 *   maxCandidates: number,
 *   openPullRequest: boolean,
 *   output: (name: string, value: string) => void,
 *   writeSummary: (text: string) => void,
 *   runUrl: () => string,
 * }} ctx
 */
export async function sweep(ctx) {
  const {
    credda,
    workspace,
    repository,
    sandbox,
    work,
    maxFiles,
    maxCandidates,
    openPullRequest,
    output,
    writeSummary,
    runUrl,
  } = ctx;

  mkdirSync(work, { recursive: true });
  const candidatesDir = join(work, 'candidates');
  mkdirSync(candidatesDir, { recursive: true });

  /* ------------------------------- discover ------------------------------- */

  // `--out` writes one candidate report per finding into the directory. Reading
  // nothing is executed here, exactly as `discover` mode executes nothing.
  const discovered = credda(
    ['discover', workspace, '--out', candidatesDir, '--max-files', String(maxFiles)],
    'pipe',
  );
  if (discovered.error !== undefined || discovered.status === null) {
    console.error(`Credda discovery could not be started: ${discovered.error?.message ?? 'unknown error'}`);
    process.exit(1);
  }
  if (discovered.status !== 0) {
    // A non-zero discover is Credda failing to read the repository, not a clean
    // repository. Reporting "0 candidates" for it would read exactly like a
    // clean tree, which is the one thing this must not do.
    console.error(String(discovered.stderr ?? '').slice(0, 4000));
    console.error('Credda discovery did not finish, so nothing is being reported.');
    process.exit(1);
  }

  // Every regular file the discovery wrote is a candidate report. Sorted so the
  // cap below always takes the same first N, and the same candidate always maps
  // to the same branch on a re-run.
  const reportFiles = readdirSync(candidatesDir)
    .filter((name) => {
      try {
        return statSync(join(candidatesDir, name)).isFile();
      } catch {
        return false;
      }
    })
    .sort();

  const discoveredCount = reportFiles.length;
  // THE HARD CAP. Never unbounded: at most `max-candidates` are ever reproduced,
  // whatever discovery found.
  const chosen = reportFiles.slice(0, Math.max(0, maxCandidates));

  /* ------------------------- reproduce each one --------------------------- */
  //
  // Run every investigation FIRST, against the pristine checkout. An
  // investigation reproduces in its own sandbox and leaves the workspace tree
  // untouched; delivery (below) is the only thing that mutates it. Keeping the
  // two phases apart means each candidate is investigated against the same tree
  // discovery read, never against a tree a previous candidate's patch changed.

  /** @type {{ provenance: string, verified: boolean, reason: string, outcome: string, investigationId: string, patchFile: string, bodyFile: string, broke: boolean }[]} */
  const results = [];

  for (let index = 0; index < chosen.length; index += 1) {
    const provenance = chosen[index];
    const reportPath = join(candidatesDir, provenance);
    const resultFile = join(work, `sweep-result-${String(index)}.json`);

    console.log(`Sweep: investigating candidate ${index + 1}/${chosen.length} (${provenance})`);

    const guard = guardToken();
    console.log(`::stop-commands::${guard}`);
    credda(
      ['investigate', workspace, `@${reportPath}`, '--sandbox', sandbox, '--out', resultFile],
      'inherit',
    );
    console.log(`::${guard}::`);

    let result;
    try {
      result = JSON.parse(readFileSync(resultFile, 'utf8'));
    } catch {
      // Credda did not record a result for this candidate. In the single-issue
      // path this reddens the job; in a fan-out it must not stop the other
      // candidates, so it is raised to the annotation list and the candidate is
      // marked broken rather than silently dropped.
      console.log(
        `::error::Credda recorded no result for candidate ${provenance}. This is a Credda failure, ` +
          'not a finding about the repository; this candidate was skipped and the sweep continued.',
      );
      results.push({
        provenance,
        verified: false,
        reason: 'Credda recorded no result for this candidate (a Credda failure, not a finding).',
        outcome: 'NO_RESULT',
        investigationId: '',
        patchFile: '',
        bodyFile: '',
        broke: true,
      });
      continue;
    }

    const outcome = typeof result.outcome === 'string' ? result.outcome : 'UNKNOWN';
    const investigationId = typeof result.investigationId === 'string' ? result.investigationId : '';

    // Whether the run PROVED a change, judged by the engine's own predicate on
    // the executed record -- the same `decideDelivery` the single-investigate
    // path reads. `enabled: true` here so the answer is "did it verify",
    // independent of whether we will actually push; the push gate is separate.
    const verdict = decideDelivery({ enabled: true, result });

    if (!verdict.deliver || investigationId === '') {
      results.push({
        provenance,
        verified: false,
        reason: investigationId === '' ? 'the run recorded no investigation id' : verdict.reason,
        outcome,
        investigationId,
        patchFile: '',
        bodyFile: '',
        broke: false,
      });
      continue;
    }

    // Verified: render the patch and the report body to files now, so delivery
    // is a pure git/gh operation. Byte-exact, straight from the engine.
    const patch = credda(['report', investigationId, '--patch'], ['ignore', 'pipe', 'inherit']);
    const report = credda(['report', investigationId, '--markdown'], ['ignore', 'pipe', 'inherit']);
    if (
      patch.status !== 0 ||
      patch.stdout === null ||
      String(patch.stdout).trim() === '' ||
      report.status !== 0 ||
      report.stdout === null ||
      String(report.stdout).length === 0
    ) {
      console.log(
        `::error::Credda recorded a verified change for candidate ${provenance} and then could not ` +
          'emit its patch or report. Nothing was proposed for it; the sweep continued.',
      );
      results.push({
        provenance,
        verified: false,
        reason:
          'Credda recorded a verified change and then could not emit its patch or report (a Credda failure).',
        outcome,
        investigationId,
        patchFile: '',
        bodyFile: '',
        broke: true,
      });
      continue;
    }

    const patchFile = join(work, `sweep-${String(index)}.patch`);
    const bodyFile = join(work, `sweep-${String(index)}.md`);
    writeFileSync(patchFile, String(patch.stdout), 'utf8');
    writeFileSync(
      bodyFile,
      `${String(report.stdout).trimEnd()}\n\n[Action run](${runUrl()})\n`,
      'utf8',
    );

    results.push({
      provenance,
      verified: true,
      reason: verdict.reason,
      outcome,
      investigationId,
      patchFile,
      bodyFile,
      broke: false,
    });
  }

  /* ------------------------------- deliver -------------------------------- */
  //
  // Only verified candidates, only when `open-pull-request` is on. Each proposal
  // is cut from the pristine base commit, so a candidate's branch never carries a
  // previous candidate's patch.

  const verified = results.filter((one) => one.verified);
  /** @type {Map<string, { status: string, message: string, url: string }>} */
  const delivery = new Map();

  if (openPullRequest && verified.length > 0) {
    const base = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: workspace, encoding: 'utf8' });
    const baseSha = String(base.stdout ?? '').trim();
    if (base.status !== 0 || baseSha === '') {
      // No base commit means no checkout to cut branches from. Report it against
      // every verified candidate rather than pretending they were proposed.
      for (const one of verified) {
        delivery.set(one.provenance, {
          status: 'error',
          message:
            'The workspace is not a git checkout, so no branch could be cut. This action expects ' +
            '`actions/checkout` to have run before it.',
          url: '',
        });
      }
    } else {
      let forgeBlocked = false;
      for (const one of verified) {
        if (forgeBlocked) {
          delivery.set(one.provenance, {
            status: 'would-propose',
            message:
              'Not attempted: an earlier candidate\'s push was refused by GitHub for a reason that ' +
              'applies to every candidate (a missing write scope or a protected branch), so the rest ' +
              'were not attempted. Grant the scopes named above and re-run.',
            url: '',
          });
          continue;
        }

        // Return to the pristine base before cutting each branch, discarding the
        // previous candidate's working-tree changes.
        const reset = spawnSync('git', ['checkout', '--force', baseSha], { cwd: workspace, encoding: 'utf8' });
        if (reset.status !== 0) {
          delivery.set(one.provenance, {
            status: 'error',
            message: `Could not return the checkout to its base commit, so this candidate was not proposed.`,
            url: '',
          });
          continue;
        }

        let branch;
        try {
          branch = branchNameForFinding(one.provenance);
        } catch (error) {
          delivery.set(one.provenance, { status: 'error', message: error.message, url: '' });
          continue;
        }

        const decision = deliverPullRequest({
          workspace,
          repository,
          branch,
          patchPath: one.patchFile,
          bodyPath: one.bodyFile,
          commitSubject: 'Credda: a verified fix for a discovered issue',
          commitBody:
            'Written and verified by Credda from a defect it discovered in this repository. The ' +
            'regression test in this commit failed on the unpatched tree and passes on this one. ' +
            'Credda proposes; a human decides.',
          prTitle: pullRequestTitleForFinding(),
        });

        delivery.set(one.provenance, {
          status: decision.outcome,
          message: decision.message,
          url: decision.url,
        });
        if (decision.outcome === 'refused' && decision.forgeRefusal) forgeBlocked = true;
      }

      // Leave the checkout back on its base commit, not on the last candidate's
      // branch.
      spawnSync('git', ['checkout', '--force', baseSha], { cwd: workspace, encoding: 'utf8' });
    }
  }

  /* ------------------------------- report --------------------------------- */

  const openedCount = [...delivery.values()].filter((d) => d.status === 'opened').length;
  writeSummary(
    sweepSummary({
      discoveredCount,
      chosen: chosen.length,
      results,
      openPullRequest,
      delivery,
      runUrl,
    }),
  );

  // Outputs. Sweep opens its own pull requests in-process, so the action's
  // separate delivery step must stay off: `deliver` is `false`. There is no
  // issue to comment on (sweep runs on a push), so `should-post` is `false` and
  // the report lives on the job summary, exactly as discover's does. The counts
  // are written for a caller wiring a notification or a gate.
  output('skipped', 'false');
  output('issue-number', '');
  output('deliver', 'false');
  output('patch-path', '');
  output('should-post', 'false');
  output('comment-path', '');
  output('body-path', '');
  output('outcome', '');
  output('investigation-id', '');
  // `stated-findings` here is the count of candidates that reached a verified
  // change (the sweep's real yield), and `candidates` is how many discovery
  // wrote. `established` drives the notify step: true when anything was verified.
  output('stated-findings', String(verified.length));
  output('candidates', String(discoveredCount));
  output('established', verified.length > 0 ? 'true' : 'false');

  // ALWAYS GREEN, findings or none -- like discover. A candidate is a report and
  // a proposal is a claim to a human; a red check beside them is a build failure
  // a maintainer cannot act on. Per-candidate Credda breakages and refused
  // pushes are raised to the annotation list above and named in the summary.
}

/** The job summary: what was discovered, what verified, and what was proposed. */
function sweepSummary({ discoveredCount, chosen, results, openPullRequest, delivery, runUrl }) {
  const lines = ['## Credda sweep', ''];

  lines.push(
    `Discovery wrote ${discoveredCount} candidate${discoveredCount === 1 ? '' : 's'}; ` +
      `${chosen} ${chosen === 1 ? 'was' : 'were'} reproduced (capped by max-candidates). ` +
      'Discovery executed nothing in this repository; each reproduction ran in a sandbox.',
    '',
  );

  if (discoveredCount === 0) {
    lines.push(
      'No candidate was written. That is not a statement that this repository has no defects, and ' +
        'it is not an audit -- it says the shapes Credda looks for were not seen in the files it read.',
      '',
      `[Action run](${runUrl()})`,
      '',
    );
    return lines.join('\n');
  }

  const verified = results.filter((one) => one.verified);
  const unverified = results.filter((one) => !one.verified);

  if (verified.length > 0) {
    lines.push(`### ${verified.length} verified fix${verified.length === 1 ? '' : 'es'}`, '');
    for (const one of verified) {
      const d = delivery.get(one.provenance);
      let note;
      if (!openPullRequest) {
        note =
          'WOULD be proposed. open-pull-request is off (the default), so nothing was pushed. Turn ' +
          'it on and grant `contents: write` + `pull-requests: write` to have this opened as a PR.';
      } else if (d === undefined) {
        note = 'verified, but no delivery was attempted.';
      } else if (d.status === 'opened') {
        note = `pull request opened${d.url === '' ? '' : `: ${d.url}`}.`;
      } else if (d.status === 'already-proposed') {
        note = d.message;
      } else if (d.status === 'would-propose') {
        note = d.message;
      } else {
        note = `not proposed. ${d.message}`;
      }
      lines.push(`- \`${one.provenance}\` (${one.outcome}) — ${note}`, '');
    }
  }

  if (unverified.length > 0) {
    lines.push(
      `### ${unverified.length} reproduced, none proven`,
      '',
      'Each was reproduced but did not reach a verified change, so none is proposed. A pull request ' +
        'is a claim that something was proven, and these did not prove it.',
      '',
      '<details><summary>Show</summary>',
      '',
    );
    for (const one of unverified) {
      lines.push(`- \`${one.provenance}\` (${one.outcome}) — ${one.reason}`, '');
    }
    lines.push('</details>', '');
  }

  lines.push(`[Action run](${runUrl()})`, '');
  return lines.join('\n');
}
