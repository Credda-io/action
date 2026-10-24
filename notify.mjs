// Posts what a run found to a webhook the customer named, from the customer's
// own runner.
//
// WHAT THIS IS, IN ONE PARAGRAPH. The report reaches the issue, the job summary
// and -- when asked -- a pull request. None of those is where a team looks
// first; a channel is. This step POSTs the facts the action already publishes
// as outputs to one URL. It is OPT-IN and OFF BY DEFAULT: `notify-url` is empty
// unless a caller sets it, and this file is not reached at all until it is.
//
// WHOSE DATA GOES WHERE. The customer's, to an address the customer typed, and
// nowhere else. The POST leaves this runner for that URL and no copy of it
// goes to Credda: there is no second request in this file, and the metering
// receipt (see `metering-url` in action.yml) carries none of these fields.
//
// WHAT IT CARRIES. This action's own outputs and two runner-provided values:
// the investigation id, the repository name, the outcome token, the count of
// stated findings, whether anything was established, the run's URL on the
// forge, and Credda's version. Never the report body, the issue text, a diff, a
// path or a reporter's words -- nothing here reads the report file.
//
// IT CANNOT FAIL THE JOB. One request, ten seconds, no retry, and every
// failure -- refused, hung, 500 -- is one line in the log and exit 0. The
// thing this product owes is the report, and the report was delivered by the
// steps before this one; a channel being down must not redden a run that
// found something.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { decideNotification, sendNotification } from './notification.mjs';

function env(name, fallback = null) {
  const value = process.env[name];
  if (value !== undefined && value !== '') return value;
  if (fallback !== null) return fallback;
  console.error(`${name} is not set. This script only runs inside a GitHub Actions job.`);
  process.exit(1);
}

/*
 * The same string `run.mjs` puts on a metering receipt, read the same way:
 * from this action's manifest, never from `GITHUB_ACTION_REF`, which is
 * whatever the caller pinned and may be a commit SHA.
 */
function creddaVersion() {
  try {
    const parsed = JSON.parse(readFileSync(join(env('CREDDA_ACTION_ROOT'), 'package.json'), 'utf8'));
    return typeof parsed.version === 'string' && parsed.version !== '' ? `v${parsed.version}` : 'unknown';
  } catch {
    return 'unknown';
  }
}

const url = env('CREDDA_NOTIFY_URL', '').trim();
const stated = Number.parseInt(env('CREDDA_STATED_FINDINGS', '0'), 10);
const statedFindings = Number.isInteger(stated) && stated > 0 ? stated : 0;
const established = env('CREDDA_ESTABLISHED', 'false') === 'true';

const decision = decideNotification({ url, statedFindings, established });
if (!decision.notify) {
  // Said rather than skipped, as every "no" in this action is -- except the
  // default one, which action.yml never lets reach this file.
  console.log(`No notification: ${decision.reason}`);
  process.exit(0);
}

// The run's own URL, the same shape `runUrl()` in run.mjs signs the comment
// with. Null rather than a guess when the runner did not say which run this is.
const runId = process.env['GITHUB_RUN_ID'] ?? '';
const reportUrl =
  runId === ''
    ? null
    : `${env('GITHUB_SERVER_URL', 'https://github.com')}/${env('GITHUB_REPOSITORY')}/actions/runs/${runId}`;

const result = await sendNotification({
  url,
  fetch: globalThis.fetch,
  facts: {
    investigationId: env('CREDDA_INVESTIGATION_ID', ''),
    repository: env('GITHUB_REPOSITORY'),
    outcome: env('CREDDA_OUTCOME', ''),
    statedFindings,
    established,
    reportUrl,
    actionVersion: creddaVersion(),
  },
});

console.log(result.line);
