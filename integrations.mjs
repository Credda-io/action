// Slack, Linear and Jira delivery for what `mode: security` proved.
//
// The rules are the ones notification.mjs states, kept:
//   * The customer's data goes only to destinations the customer configured. Nothing
//     here sends anything to Credda.
//   * Opt-in and off by default: action.yml skips each step unless its inputs are set.
//   * It can never fail the job. One attempt per request, a 10 s timeout, and every
//     failure is one log line. Nothing in this file throws to its caller.
//   * Secrets arrive only as inputs the customer mapped from their own secrets. They
//     are masked by integrate.mjs and scrubbed from every line this file returns.
//
// What is sent is what security.json already holds for each PROVEN finding: class,
// CWE, site, the probe's sentence and the exploit program. Unproven patterns are a
// count, labelled unproven, and never an issue.
//
// Everything here is a function of values plus a `fetch` handed in, so
// test/integrations.test.mjs runs it against a local HTTP server.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { decideNotification } from './notification.mjs';

const TIMEOUT_MS = 10_000;
const PROGRAM_LIMIT = 8000;
export const LINEAR_API = 'https://api.linear.app/graphql';

/** Replaces every secret in a line, so no failure message can carry one. */
export function scrub(text, secrets) {
  let out = String(text);
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret.length >= 4) out = out.split(secret).join('***');
  }
  return out;
}

/** https, or http on a loopback host (so a local test server can stand in). */
export function allowedUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol === 'https:') return true;
    return url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  } catch {
    return false;
  }
}

export function siteText(site) {
  if (site === null || site === undefined) return '';
  if (typeof site === 'string') return site;
  if (site.kind === 'package') return 'package (through package.json)';
  return `${site.file}${site.line ? `:${site.line}` : ''}`;
}

const oneLine = (text, max) => String(text ?? '').split('\n')[0].trim().slice(0, max);

/**
 * The proven findings and the unproven count out of a security.json. Returns null
 * when the file is missing or unreadable, so a caller can say so in one line.
 */
export function readFindings(path) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
  const proven = (Array.isArray(parsed.findings) ? parsed.findings : []).map((f) => {
    const site = siteText(f.site);
    return {
      id: String(f.id ?? `${f.class}@${site}`),
      class: String(f.class ?? 'UNKNOWN'),
      cwe: f.cwe ? String(f.cwe) : '',
      site,
      sentence: oneLine(f.sentence, 300),
      program: typeof f.program === 'string' ? f.program : '',
    };
  });
  return { proven, unproven: Array.isArray(parsed.unproven) ? parsed.unproven.length : 0 };
}

/* ---------------------------------- Slack ---------------------------------- */

/**
 * Whether Slack hears about this run. `findings` (the default) is the existing
 * decideNotification rule, so a clean run is quiet; security mode counts proven
 * findings. `always` posts every run.
 */
export function decideSlack({ notifyOn, mode, provenFindings, statedFindings, established }) {
  const always = notifyOn === 'always';
  const bad = notifyOn !== '' && notifyOn !== 'findings' && notifyOn !== 'always';
  const prefix = bad ? `notify-on '${notifyOn}' is not 'findings' or 'always', so 'findings' applies. ` : '';
  if (always) return { notify: true, reason: 'notify-on is always.' };
  if (mode === 'security') {
    return provenFindings > 0
      ? { notify: true, reason: `${prefix}the run proved ${provenFindings} finding(s).` }
      : { notify: false, reason: `${prefix}no finding was proven and notify-on is findings, so Slack was not told.` };
  }
  const d = decideNotification({ url: 'x', statedFindings, established });
  return { notify: d.notify, reason: prefix + d.reason };
}

const mrkdwn = (text) => String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** Block Kit message. At most 5 proven findings; unproven only as a labelled count. */
export function slackMessage({ repository, mode, outcome, runUrl, findings, unprovenCount, statedFindings }) {
  const security = mode === 'security';
  const count = security ? findings.length : statedFindings;
  const headline = security
    ? `Credda proved ${count} finding${count === 1 ? '' : 's'} in ${repository}`
    : `Credda ${outcome === '' ? 'ran' : `reached ${outcome}`} in ${repository}`;
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: headline.slice(0, 150) } },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: `*Repository*\n${mrkdwn(repository)}` },
        { type: 'mrkdwn', text: `*Outcome*\n${mrkdwn(security ? (count > 0 ? 'findings proven by exploit' : 'nothing proven') : outcome || 'established a result')}` },
        { type: 'mrkdwn', text: `*${security ? 'Proven findings' : 'Stated findings'}*\n${count}` },
      ],
    },
  ];
  for (const f of findings.slice(0, 5)) {
    const head = `*${mrkdwn(f.class)}*${f.cwe ? ` (${mrkdwn(f.cwe)})` : ''} at \`${f.site.replace(/`/g, "'")}\``;
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `${head}\n${mrkdwn(f.sentence)}` } });
  }
  if (findings.length > 5) {
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: `${findings.length - 5} more proven finding(s) on the job summary.` }] });
  }
  if (security && unprovenCount > 0) {
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: `${unprovenCount} unproven pattern(s), not findings: no exploit ran for them.` }] });
  }
  if (runUrl) {
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `<${runUrl}|View the run>` } });
  }
  return { text: headline, blocks };
}

async function request(fetch, url, init, timeoutMs) {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
  const raw = await response.text().catch(() => '');
  let json = null;
  try {
    json = raw === '' ? null : JSON.parse(raw);
  } catch {
    json = null;
  }
  return { status: response.status, ok: response.ok, json };
}

function failure(label, error, secrets) {
  const code = error?.cause?.code ?? error?.code;
  const said = error instanceof Error ? `${error.name}${code ? ` ${code}` : ''}: ${error.message}` : String(error);
  return `${label} was not delivered: ${scrub(said, secrets)}. This run is unaffected.`;
}

/** Posts the Slack message. Never throws; the URL is never in the returned line. */
export async function sendSlack({ webhookUrl, message, fetch, timeoutMs = TIMEOUT_MS }) {
  const secrets = [webhookUrl];
  try {
    const r = await request(fetch, webhookUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(message),
    }, timeoutMs);
    if (!r.ok) return { sent: false, line: `Slack was not delivered: the webhook answered ${r.status}. This run is unaffected.` };
    return { sent: true, line: 'Slack message sent.' };
  } catch (error) {
    return { sent: false, line: failure('Slack', error, secrets) };
  }
}

/* ---------------------------------- Linear ---------------------------------- */

const issueTitle = (f) => `Credda: ${f.class} in ${f.site}`;
const programFor = (f) =>
  f.program.length > PROGRAM_LIMIT ? `${f.program.slice(0, PROGRAM_LIMIT)}\n// ...truncated; the full program is in security.json` : f.program;

export function linearDescription(f, runUrl) {
  const lines = [f.sentence, '', `CWE: ${f.cwe || 'n/a'}`, `Site: ${f.site}`, `Credda finding id: ${f.id}`, ''];
  if (f.program) lines.push('The exploit program that proved it:', '', '```js', programFor(f), '```', '');
  if (runUrl) lines.push(`Run: ${runUrl}`);
  return lines.join('\n');
}

const LINEAR_SEARCH =
  'query($teamId: ID!, $fp: String!) { issues(first: 1, filter: { team: { id: { eq: $teamId } }, ' +
  'description: { contains: $fp }, state: { type: { nin: ["completed", "canceled"] } } }) { nodes { id identifier } } }';
const LINEAR_CREATE =
  'mutation($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url } } }';

/**
 * One Linear issue per proven finding, skipping any whose finding id already
 * appears in an open issue's description, capped at `max` created. Stops at the
 * first failure with one line. Unproven patterns are never passed in.
 */
export async function deliverLinear({ apiKey, teamId, findings, runUrl, max, fetch, apiUrl = LINEAR_API, timeoutMs = TIMEOUT_MS }) {
  const secrets = [apiKey];
  const headers = { 'content-type': 'application/json', authorization: apiKey };
  const gql = async (query, variables) => {
    const r = await request(fetch, apiUrl, { method: 'POST', headers, body: JSON.stringify({ query, variables }) }, timeoutMs);
    if (!r.ok) throw new Error(`Linear answered ${r.status}`);
    if (r.json === null || (Array.isArray(r.json.errors) && r.json.errors.length > 0)) {
      throw new Error(`Linear returned errors: ${oneLine(r.json?.errors?.[0]?.message ?? 'no JSON body', 120)}`);
    }
    return r.json.data;
  };
  let created = 0;
  let skipped = 0;
  try {
    for (const f of findings) {
      if (created >= max) break;
      const found = await gql(LINEAR_SEARCH, { teamId, fp: f.id });
      if ((found?.issues?.nodes?.length ?? 0) > 0) {
        skipped += 1;
        continue;
      }
      const made = await gql(LINEAR_CREATE, {
        input: { teamId, title: issueTitle(f), description: linearDescription(f, runUrl) },
      });
      if (made?.issueCreate?.success !== true) throw new Error('Linear did not confirm issueCreate');
      created += 1;
    }
  } catch (error) {
    return { created, skipped, line: failure('Linear', error, secrets) };
  }
  const capped = findings.length - skipped - created;
  return {
    created,
    skipped,
    line: `Linear: ${created} issue(s) created, ${skipped} already open${capped > 0 ? `, ${capped} not filed (max-issues ${max})` : ''}.`,
  };
}

/* ----------------------------------- Jira ----------------------------------- */

/** A single-token, label-safe fingerprint of the finding id. */
export function jiraFingerprint(id) {
  return `creddafp${createHash('sha256').update(id).digest('hex').slice(0, 20)}`;
}

const p = (...content) => ({ type: 'paragraph', content });
const t = (text, marks) => ({ type: 'text', text, ...(marks ? { marks } : {}) });

/** The issue description in Atlassian Document Format. */
export function jiraDescription(f, runUrl) {
  const content = [
    p(t(f.sentence || f.class)),
    p(t(`CWE: ${f.cwe || 'n/a'}`)),
    p(t(`Site: ${f.site}`)),
    p(t(`Credda finding id: ${f.id}`)),
    p(t(`Credda fingerprint: ${jiraFingerprint(f.id)}`)),
  ];
  if (f.program) {
    content.push(p(t('The exploit program that proved it:')));
    content.push({ type: 'codeBlock', attrs: { language: 'javascript' }, content: [t(programFor(f))] });
  }
  if (runUrl) content.push(p(t('Run: '), t(runUrl, [{ type: 'link', attrs: { href: runUrl } }])));
  return { type: 'doc', version: 1, content };
}

const jqlString = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

/**
 * One Jira Cloud issue per proven finding (REST v3). De-duplication is a JQL
 * search for the finding's fingerprint, which is also set as a label so the
 * match is exact rather than a text-index guess.
 */
export async function deliverJira({ baseUrl, email, apiToken, projectKey, issueType, findings, runUrl, max, fetch, timeoutMs = TIMEOUT_MS }) {
  const auth = `Basic ${Buffer.from(`${email}:${apiToken}`).toString('base64')}`;
  const secrets = [apiToken, email, auth, Buffer.from(`${email}:${apiToken}`).toString('base64')];
  const headers = { 'content-type': 'application/json', accept: 'application/json', authorization: auth };
  const base = baseUrl.replace(/\/+$/, '');
  let created = 0;
  let skipped = 0;
  try {
    for (const f of findings) {
      if (created >= max) break;
      const fp = jiraFingerprint(f.id);
      const jql = `project = ${jqlString(projectKey)} AND statusCategory != Done AND labels = ${jqlString(fp)}`;
      const search = await request(fetch, `${base}/rest/api/3/search/jql`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ jql, maxResults: 1, fields: ['key'] }),
      }, timeoutMs);
      if (!search.ok) throw new Error(`Jira search answered ${search.status}`);
      if ((search.json?.issues?.length ?? 0) > 0) {
        skipped += 1;
        continue;
      }
      const made = await request(fetch, `${base}/rest/api/3/issue`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          fields: {
            project: { key: projectKey },
            issuetype: { name: issueType },
            summary: issueTitle(f).slice(0, 255),
            description: jiraDescription(f, runUrl),
            labels: ['credda', fp],
          },
        }),
      }, timeoutMs);
      if (!made.ok) throw new Error(`Jira create answered ${made.status}`);
      created += 1;
    }
  } catch (error) {
    return { created, skipped, line: failure('Jira', error, secrets) };
  }
  const capped = findings.length - skipped - created;
  return {
    created,
    skipped,
    line: `Jira: ${created} issue(s) created, ${skipped} already open${capped > 0 ? `, ${capped} not filed (max-issues ${max})` : ''}.`,
  };
}
