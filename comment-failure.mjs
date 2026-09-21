// Turns a refused report comment into a refusal that names the fix.
//
// Reached only when `gh issue comment` has already failed. The step captures
// what gh said into a file and hands that file to this script, which is the
// half that touches a runner: it reads the log, asks `commenting.mjs` what the
// failure means, writes the answer to the annotation list and to the job
// summary, and exits 1 so the step stays red.
//
// IT NEVER MAKES THE STEP GREEN. The customer asked for the report to reach the
// issue and it did not; a green job would be this action denying something it
// failed to do, which is the argument `deliver-pr.mjs` makes for its own exit
// code. This script only changes what the failure SAYS.
//
// THE REPORT IS NOT LOST WHEN THIS RUNS, and every message says so. `run.mjs`
// writes the full document to the job summary before the posting step begins,
// precisely so that a posting failure costs the comment and not the report.

import { appendFileSync, readFileSync } from 'node:fs';

import { explainCommentRefusal } from './commenting.mjs';

const logPath = process.argv[2] ?? '';
let said = '';
try {
  said = logPath === '' ? '' : readFileSync(logPath, 'utf8');
} catch {
  /* gh failing before it wrote anything is itself only a missing detail */
}

const named = explainCommentRefusal(said);

// Unrecognised failures quote gh rather than inventing a diagnosis, and the
// headline still names the step and the consequence so the annotation list is
// never empty for this failure.
const headline =
  named === null
    ? 'Credda could not post the report as a comment on the issue. The full report is on this job summary.'
    : named.split('\n')[0];
const detail =
  named === null
    ? `Credda has no named cause for this one, so here is what gh said:\n\n${said.trim()}`
    : `${named}\n\nWhat gh said: ${said.trim()}`;

console.log(`::error::${headline}`);
console.error(detail);

const summaryFile = process.env['GITHUB_STEP_SUMMARY'];
if (summaryFile !== undefined && summaryFile !== '') {
  appendFileSync(summaryFile, `### Credda could not post the report\n\n${detail}\n`, 'utf8');
}

process.exit(1);
