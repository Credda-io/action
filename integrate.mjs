// Runs one delivery destination: `node integrate.mjs slack|linear|jira`.
//
// Reached only from a step in action.yml whose `if:` requires that destination's
// inputs, so a default install runs none of this. Every path ends in exit 0: the
// report was delivered by the steps before this one, and a tracker being down
// must not redden a run that found something. Each result, delivered or not, is
// one line in the log and one in the job summary. See integrations.mjs.

import { appendFileSync } from 'node:fs';

import { LINE_BREAK } from './findings.mjs';

import {
  checkUrl,
  decideSlack,
  deliverJira,
  deliverLinear,
  readFindings,
  scrub,
  sendSlack,
  slackMessage,
} from './integrations.mjs';

const get = (name) => (process.env[name] ?? '').trim();
const destination = process.argv[2] ?? '';

const secretNames = {
  slack: ['CREDDA_SLACK_WEBHOOK_URL'],
  linear: ['CREDDA_LINEAR_API_KEY'],
  jira: ['CREDDA_JIRA_EMAIL', 'CREDDA_JIRA_API_TOKEN'],
};
const secrets = (secretNames[destination] ?? []).map(get).filter((v) => v !== '');
// The webhook's path is its secret part, and the Basic header is the Jira pair in another form.
if (destination === 'slack' && secrets.length === 1) {
  try {
    secrets.push(new URL(secrets[0]).pathname);
  } catch {
    // Not a URL: checkUrl says so below, and the value itself is already a secret.
  }
}
if (destination === 'jira' && secrets.length === 2) secrets.push(Buffer.from(`${secrets[0]}:${secrets[1]}`).toString('base64'));
// Masked first, before anything else can be printed.
// One mask per line: a mask command is one line, so a secret with a line break is masked line by line.
for (const part of secrets.flatMap((s) => s.split(LINE_BREAK))) {
  if (part.length >= 4) {
    console.log(`::add-mask::${part}`);
    if (!secrets.includes(part)) secrets.push(part);
  }
}

const names = { slack: 'Slack', linear: 'Linear', jira: 'Jira' };
const say = (line) => {
  const clean = scrub(line, secrets);
  console.log(clean);
  const summary = get('GITHUB_STEP_SUMMARY');
  if (summary === '') return;
  try {
    appendFileSync(summary, `**Credda to ${names[destination] ?? 'an unknown destination'}:** ${clean}\n\n`, 'utf8');
  } catch {
    // The log line above is the record; a summary that cannot be written is not a failure.
  }
};

const runId = get('GITHUB_RUN_ID');
const repository = get('GITHUB_REPOSITORY');
const runUrl =
  runId === '' || repository === ''
    ? null
    : `${get('GITHUB_SERVER_URL') || 'https://github.com'}/${repository}/actions/runs/${runId}`;
const mode = get('CREDDA_MODE');
const asCount = (v) => (Number.isInteger(Number.parseInt(v, 10)) && Number.parseInt(v, 10) > 0 ? Number.parseInt(v, 10) : 0);

try {
  const file = get('CREDDA_SECURITY_JSON');
  const loaded = mode === 'security' && file !== '' ? readFindings(file, get('CREDDA_FIX_DELIVERY')) : null;

  if (destination === 'slack') {
    const url = get('CREDDA_SLACK_WEBHOOK_URL');
    const bad = checkUrl(url, 'slack-webhook-url');
    if (bad !== null) {
      say(`Slack was not delivered: ${bad}. This run is unaffected.`);
    } else {
      const findings = loaded?.proven ?? [];
      const provenFindings = mode === 'security' ? (loaded ? findings.length : asCount(get('CREDDA_SECURITY_FINDINGS'))) : 0;
      const statedFindings = asCount(get('CREDDA_STATED_FINDINGS'));
      const decision = decideSlack({
        notifyOn: get('CREDDA_NOTIFY_ON'),
        mode,
        provenFindings,
        statedFindings,
        established: get('CREDDA_ESTABLISHED') === 'true',
      });
      if (!decision.notify) {
        say(`No Slack message: ${decision.reason}`);
      } else {
        const message = slackMessage({
          repository,
          mode,
          outcome: get('CREDDA_OUTCOME'),
          runUrl,
          findings,
          unprovenCount: loaded?.unproven ?? 0,
          statedFindings: mode === 'security' ? provenFindings : statedFindings,
          probes: loaded?.probes ?? 0,
          fuzzed: loaded?.fuzzed ?? 0,
        });
        say((await sendSlack({ webhookUrl: url, message, fetch: globalThis.fetch })).line);
      }
    }
  } else if (destination === 'linear' || destination === 'jira') {
    const maxRaw = Number.parseInt(get('CREDDA_MAX_ISSUES') || '10', 10);
    const max = Number.isInteger(maxRaw) && maxRaw >= 0 ? maxRaw : 10;
    if (loaded === null) {
      say(`No ${destination} issues: ${mode === 'security' ? 'security.json could not be read' : 'issues are filed only in security mode'}, so nothing was filed. This run is unaffected.`);
    } else if (loaded.proven.length === 0) {
      say(`No ${destination} issues: no finding was proven.`);
    } else if (destination === 'linear') {
      const r = await deliverLinear({
        apiKey: get('CREDDA_LINEAR_API_KEY'),
        teamId: get('CREDDA_LINEAR_TEAM_ID'),
        repository,
        findings: loaded.proven,
        runUrl,
        max,
        fetch: globalThis.fetch,
      });
      say(r.line);
    } else {
      const base = get('CREDDA_JIRA_BASE_URL');
      const bad = checkUrl(base, 'jira-base-url');
      if (bad !== null) {
        say(`Jira was not delivered: ${bad}. This run is unaffected.`);
      } else {
        const r = await deliverJira({
          baseUrl: base,
          email: get('CREDDA_JIRA_EMAIL'),
          apiToken: get('CREDDA_JIRA_API_TOKEN'),
          projectKey: get('CREDDA_JIRA_PROJECT_KEY'),
          issueType: get('CREDDA_JIRA_ISSUE_TYPE') || 'Bug',
          repository,
          findings: loaded.proven,
          runUrl,
          max,
          fetch: globalThis.fetch,
        });
        say(r.line);
      }
    }
  } else {
    say(`integrate.mjs was given '${destination}', which is not slack, linear or jira. Nothing was sent.`);
  }
} catch (error) {
  say(`Delivery to ${destination} stopped: ${error instanceof Error ? error.message : String(error)}. This run is unaffected.`);
}
process.exit(0);
