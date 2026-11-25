// Runs one delivery destination: `node integrate.mjs slack|linear|jira`.
//
// Reached only from a step in action.yml whose `if:` requires that destination's
// inputs, so a default install runs none of this. Every path ends in exit 0: the
// report was delivered by the steps before this one, and a tracker being down
// must not redden a run that found something. See integrations.mjs.

import {
  allowedUrl,
  decideSlack,
  deliverJira,
  deliverLinear,
  LINEAR_API,
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
// Masked first, before anything else can be printed.
for (const s of secrets) console.log(`::add-mask::${s}`);
if (destination === 'jira' && secrets.length === 2) {
  console.log(`::add-mask::${Buffer.from(`${secrets[0]}:${secrets[1]}`).toString('base64')}`);
}

const say = (line) => console.log(scrub(line, secrets));

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
  const loaded = mode === 'security' && file !== '' ? readFindings(file) : null;

  if (destination === 'slack') {
    const url = get('CREDDA_SLACK_WEBHOOK_URL');
    if (!allowedUrl(url)) {
      say('Slack was not delivered: slack-webhook-url must be an https URL. This run is unaffected.');
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
      const override = get('CREDDA_LINEAR_API_URL');
      const apiUrl = override !== '' && allowedUrl(override) && override.startsWith('http://') ? override : LINEAR_API;
      const r = await deliverLinear({
        apiKey: get('CREDDA_LINEAR_API_KEY'),
        teamId: get('CREDDA_LINEAR_TEAM_ID'),
        findings: loaded.proven,
        runUrl,
        max,
        fetch: globalThis.fetch,
        apiUrl,
      });
      say(r.line);
    } else {
      const base = get('CREDDA_JIRA_BASE_URL');
      if (!allowedUrl(base)) {
        say('Jira was not delivered: jira-base-url must be an https URL. This run is unaffected.');
      } else {
        const r = await deliverJira({
          baseUrl: base,
          email: get('CREDDA_JIRA_EMAIL'),
          apiToken: get('CREDDA_JIRA_API_TOKEN'),
          projectKey: get('CREDDA_JIRA_PROJECT_KEY'),
          issueType: get('CREDDA_JIRA_ISSUE_TYPE') || 'Bug',
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
