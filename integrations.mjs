// Slack, Linear and Jira delivery for what `mode: security` proved.
//
// The rules are the ones notification.mjs states, kept:
//   * The customer's data goes only to destinations the customer configured. Nothing
//     here sends anything to Credda.
//   * Opt-in and off by default: action.yml skips each step unless its inputs are set.
//   * It can never fail the job. One attempt per request, a 10 s timeout, no
//     redirects, and every failure is one line. Nothing in this file throws to its caller.
//   * Secrets arrive only as inputs the customer mapped from their own secrets. They
//     are masked by integrate.mjs and scrubbed from every line this file returns.
//
// What is sent is what security.json already holds for each PROVEN finding: class,
// CWE, site, the probe's sentence and the exploit program. Unproven patterns are a
// count, labelled unproven, and never an issue. The sentence and the site come from
// the scanned repository, so each format escapes them.
//
// Everything here is a function of values plus a `fetch` handed in, so
// test/integrations.test.mjs runs it against a local HTTP server.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';

import {
  exercisedSentence,
  exploitLanguage,
  fenceFor,
  findingPackage,
  fixFor,
  markdownText,
  missedText,
  NOTHING_PROVEN,
  oneLine,
  packageWords,
  ranText,
  reachSummaryText,
  reachWarning,
  securityCounts,
  siteText,
  workspaceReach,
} from './findings.mjs';
import { decideNotification } from './notification.mjs';

const TIMEOUT_MS = 10_000;
export const LINEAR_API = 'https://api.linear.app/graphql';
/** Slack's limit on a section's text. */
export const SLACK_TEXT_LIMIT = 3000;
/**
 * The largest issue description sent. Jira Cloud refuses a field over 32,767
 * characters; this is measured on the JSON sent, which is longer than the text.
 * Linear gets the same cap.
 */
export const DESCRIPTION_LIMIT = 30_000;

/** Replaces every secret in a line, so no failure message can carry one. */
export function scrub(text, secrets) {
  let out = String(text);
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret.length >= 4) out = out.split(secret).join('***');
  }
  return out;
}

/** Whether a host name or address is loopback, private, link-local or a bare intranet name. */
export function privateHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  if (isIP(host) === 4) {
    const [a, b] = host.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19)) || a >= 224;
  }
  if (isIP(host) === 6) {
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(host);
    if (mapped) return privateHost(mapped[1]);
    // 64:ff9b::/96 is NAT64: an IPv4 address, private ones included, inside an IPv6 one.
    return host === '::' || host === '::1' || /^f[cd]/.test(host) || /^fe[89ab]/.test(host) || host.startsWith('::ffff:') ||
      host.startsWith('64:ff9b:') || /^ff/.test(host);
  }
  return !host.includes('.') || /\.(localhost|local|internal|lan|home\.arpa)$/.test(host);
}

/**
 * An https URL on a public host, or the reason it is not one. Literal addresses
 * and names are checked; what a public name resolves to is not.
 */
export function checkUrl(value, input) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return `${input} is not a URL`;
  }
  if (url.protocol !== 'https:') return `${input} must be an https URL`;
  if (url.username !== '' || url.password !== '') return `${input} must not carry a user name or password`;
  if (privateHost(url.hostname)) return `${input} must name a public host, not a loopback or private one`;
  return null;
}

const firstLine = (text) => oneLine(text).trim();

/** The first line of a text, cut to `max` with "..." as the job summary cuts it. Not escaped: slackText escapes the whole block. */
const cutLine = (text, max) => {
  const line = oneLine(text);
  return line.length > max ? `${line.slice(0, max)}...` : line;
};

/**
 * Cuts text to `max` characters with a stated note, at a space when one is near,
 * so nothing is shortened without saying so.
 */
export function cap(text, max, note = ' [cut; the full text is on the run page]') {
  const s = String(text);
  if (s.length <= max) return s;
  const room = Math.max(0, max - note.length);
  const space = s.lastIndexOf(' ', room);
  return `${s.slice(0, space > room * 0.8 ? space : room)}${note}`;
}

/**
 * The proven findings and the run's counts out of a security.json, through the
 * same reader the job summary uses. Returns null when the file is missing or
 * unreadable, so a caller can say so in one line. With `fix` on, `deliveryPath`
 * is the record run.mjs wrote of what delivery did, and each finding carries
 * `fix` from fixFor; with `fix` off, `fix` is null.
 */
export function readFindings(path, deliveryPath = '') {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
  let delivered = [];
  try {
    delivered = deliveryPath === '' ? [] : JSON.parse(readFileSync(deliveryPath, 'utf8'));
  } catch {
    delivered = [];
  }
  const { findings, probes, fuzzed } = securityCounts(parsed);
  const proven = findings.map((f) => ({
    id: String(f.id ?? f.class),
    class: String(f.class ?? 'UNKNOWN'),
    cwe: f.cwe ? String(f.cwe) : '',
    language: exploitLanguage(f),
    site: firstLine(siteText(f.site)),
    fuzzFunction: typeof f.fuzz?.function === 'string' ? firstLine(f.fuzz.function) : '',
    sentence: firstLine(f.sentence),
    program: typeof f.program === 'string' ? f.program : '',
    fix: fixFor(parsed.fixes, delivered, f.id),
    // '' on a report of one package; the path (or `.`) on a workspace report, from the id's prefix.
    package: firstLine(findingPackage(f, parsed)),
  }));
  const w = workspaceReach(parsed);
  return {
    proven,
    unproven: Array.isArray(parsed.unproven) ? parsed.unproven.length : 0,
    probes,
    fuzzed,
    reach: reachSummaryText(parsed),
    warning: reachWarning(parsed),
    // A workspace report's "Credda exercised 3 of 30 packages", with the ones it did not (untrusted text), or null.
    workspace: w === null ? null : { lead: exercisedSentence(w), missed: w.missed, partial: w.missed.length > 0 },
  };
}

/**
 * The de-duplication key: one hex token from the repository, the language and the
 * engine's finding id. The id carries no seed (`CLASS@fuzz:fn`, `CLASS@file:line`
 * or the probe name), so it is the same on every run of the same code. The
 * repository is in it because one Linear team or Jira project can serve many.
 * On a workspace report the engine prefixes the id with the package path
 * (`packages/a/CLASS@...`), so two packages' findings differ, and a report of one
 * package keeps the key it always had. The root's ids are not prefixed.
 */
export function fingerprint(repository, f) {
  return `creddafp${createHash('sha256').update(`${repository}\n${f.language}\n${f.id}`).digest('hex').slice(0, 20)}`;
}

/** "PROTOTYPE_POLLUTION through unflatten (fuzzing)" or "PROTOTYPE_POLLUTION at src/a.js:3". */
const findingWords = (f) =>
  `${f.fuzzFunction ? `${f.class} through ${f.fuzzFunction} (fuzzing)` : `${f.class}${f.site ? ` ${f.site}` : ''}`}${f.package ? ` ${packageWords(f.package)}` : ''}`;

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

/**
 * Text for a Slack mrkdwn field. `&`, `<` and `>` are Slack's control characters,
 * so `<!channel>` and `<url|text>` arrive as text; a bare @channel, @here or
 * @everyone gets a zero-width space so no client reads it as a mention.
 */
export const mrkdwn = (text) =>
  String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/@(?=(channel|here|everyone)\b)/gi, '@​');

/** Escaped mrkdwn cut to fit `max` after escaping, with the note. */
const slackText = (raw, max) => {
  let room = max;
  let out = mrkdwn(cap(raw, room));
  while (out.length > max) out = mrkdwn(cap(raw, (room -= out.length - max)));
  return out;
};

/**
 * Block Kit message. At most 5 proven findings; unproven only as a labelled count.
 * `reach` is findings.mjs's one line of counts and `warning` its reachWarning, so
 * a run that could not exercise the code never posts as "No exploit succeeded".
 */
export function slackMessage({ repository, mode, outcome, runUrl, findings, unprovenCount, statedFindings, probes = 0, fuzzed = 0, reach = '', warning = null, workspace = null }) {
  const security = mode === 'security';
  const count = security ? findings.length : statedFindings;
  const limited = security && count === 0 && warning !== null;
  // A workspace where some packages were not exercised never posts as "No exploit succeeded".
  const partial = security && count === 0 && !limited && workspace?.partial === true;
  const headline = security
    ? count > 0
      ? `Credda proved ${count} finding${count === 1 ? '' : 's'} in ${repository}`
      : limited
        ? `Credda could not exercise the code in ${repository}`
        : partial
          ? `${workspace.lead.replace(/\.$/, '')} in ${repository}`
          : `No exploit succeeded in ${repository}`
    : `Credda ${outcome === '' ? 'ran' : `reached ${outcome}`} in ${repository}`;
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: cap(headline, 150, '...') } },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: `*Repository*\n${slackText(repository, 1900)}` },
        { type: 'mrkdwn', text: `*Outcome*\n${slackText(security ? (count > 0 ? 'findings proven by exploit' : limited ? 'could not exercise the code' : partial ? 'nothing proven in the packages exercised' : 'nothing proven') : outcome || 'established a result', 1900)}` },
        { type: 'mrkdwn', text: `*${security ? 'Proven findings' : 'Stated findings'}*\n${count}` },
      ],
    },
  ];
  if (limited) {
    // The engine's words are the repository's text, escaped by slackText like every other field.
    const said = warning.said ? ` The engine said: ${warning.said}` : '';
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: slackText(`${warning.lead} ${warning.why}${said}`, SLACK_TEXT_LIMIT) } });
  }
  if (security && workspace !== null) {
    // The paths and the engine's reasons are the repository's text, escaped by slackText.
    const missed = workspace.missed.length > 0 ? ` It did not exercise ${missedText(workspace.missed, (s) => s, cutLine)}.` : '';
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: slackText(`${workspace.lead}${missed}`, SLACK_TEXT_LIMIT) } });
  }
  if (security && count === 0) {
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: slackText(`${ranText(probes, fuzzed)}. ${NOTHING_PROVEN}`, SLACK_TEXT_LIMIT) } });
  }
  for (const f of findings.slice(0, 5)) {
    const head = `*${mrkdwn(f.class)}*${f.cwe ? ` (${mrkdwn(f.cwe)})` : ''}`;
    const where = `${f.fuzzFunction ? ` through ${f.fuzzFunction} (fuzzing)` : f.site ? ` ${f.site}` : ''}${f.package ? ` ${packageWords(f.package)}` : ''}`;
    // The URL passed pullRequestUrl, so it holds no character mrkdwn acts on.
    const fix = f.fix ? `\n${mrkdwn(f.fix.text)}${f.fix.url ? ` <${f.fix.url}|${f.fix.url}>` : ''}` : '';
    const room = SLACK_TEXT_LIMIT - head.length - fix.length - 1;
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `${head}${slackText(`${where}\n${f.sentence}`, room)}${fix}` } });
  }
  if (findings.length > 5) {
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: `${findings.length - 5} more proven finding(s) on the job summary.` }] });
  }
  if (security && reach) {
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: slackText(reach, SLACK_TEXT_LIMIT) }] });
  }
  if (security && unprovenCount > 0) {
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: `${unprovenCount} unproven pattern(s), not findings: no exploit ran for them.` }] });
  }
  if (runUrl) {
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `<${runUrl}|View the run>` } });
  }
  return { text: mrkdwn(headline), blocks };
}

async function request(fetch, url, init, timeoutMs) {
  const response = await fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
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
  return `${label} was not delivered: ${firstLine(scrub(said, secrets))}. This run is unaffected.`;
}

/** Posts the Slack message. Never throws; the URL is never in the returned line. */
export async function sendSlack({ webhookUrl, message, fetch, timeoutMs = TIMEOUT_MS }) {
  let path = '';
  try {
    path = new URL(webhookUrl).pathname;
  } catch {
    path = '';
  }
  const secrets = [webhookUrl, path];
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

/* ------------------------------ issue bodies ------------------------------ */

const issueTitle = (f) => cap(`Credda: ${findingWords(f)}`, 255, '...');

/** Says where the exploit is when it does not fit. */
const programNote = (f, runUrl) =>
  `The exploit program (${f.program.length} characters) is too long for this description. ` +
  `It is on the run's job summary${runUrl ? ` (${runUrl})` : ''} and in the SARIF file, under this result's exploitProgram.`;

export { markdownText };

export function linearDescription(f, runUrl, fp) {
  const head = [
    markdownText(f.sentence),
    '',
    `CWE: ${markdownText(f.cwe || 'n/a')}`,
    `Site: ${markdownText(f.site || 'not stated')}`,
    ...(f.package ? [`Package: ${markdownText(f.package === '.' ? 'the workspace root' : f.package)}`] : []),
    `Credda finding id: ${markdownText(f.id)}`,
    `Credda fingerprint: ${fp}`,
    ...(f.fix ? [`${markdownText(f.fix.text)}${f.fix.url ? ` ${f.fix.url}` : ''}`] : []),
    '',
  ];
  const tail = runUrl ? [`Run: ${runUrl}`] : [];
  if (f.program) {
    const fence = fenceFor(f.program);
    const full = [...head, 'The exploit program that proved it:', '', `${fence}${f.language}`, f.program, fence, '', ...tail].join('\n');
    if (full.length <= DESCRIPTION_LIMIT) return full;
    head.push(markdownText(programNote(f, null)), '');
  }
  return cap([...head, ...tail].join('\n'), DESCRIPTION_LIMIT);
}

const p = (...content) => ({ type: 'paragraph', content });
// ADF text nodes may not be empty, so an empty value becomes a dash.
const t = (text, marks) => ({ type: 'text', text: String(text) === '' ? '-' : String(text), ...(marks ? { marks } : {}) });

/** The issue description in Atlassian Document Format. Text nodes are plain text, so no markup forms. */
export function jiraDescription(f, runUrl, fp) {
  const content = [
    p(t(cap(f.sentence || f.class, 2000))),
    p(t(`CWE: ${f.cwe || 'n/a'}`)),
    p(t(`Site: ${cap(f.site || 'not stated', 2000)}`)),
    ...(f.package ? [p(t(`Package: ${cap(f.package === '.' ? 'the workspace root' : f.package, 2000)}`))] : []),
    p(t(`Credda finding id: ${cap(f.id, 2000)}`)),
    p(t(`Credda fingerprint: ${fp}`)),
    ...(f.fix ? [f.fix.url ? p(t(`${f.fix.text} `), t(f.fix.url, [{ type: 'link', attrs: { href: f.fix.url } }])) : p(t(f.fix.text))] : []),
  ];
  const run = runUrl ? [p(t('Run: '), t(runUrl, [{ type: 'link', attrs: { href: runUrl } }]))] : [];
  if (f.program) {
    const code = { type: 'codeBlock', attrs: { language: f.language === 'python' ? 'python' : 'javascript' }, content: [t(f.program)] };
    const full = { type: 'doc', version: 1, content: [...content, p(t('The exploit program that proved it:')), code, ...run] };
    if (JSON.stringify(full).length <= DESCRIPTION_LIMIT) return full;
    content.push(p(t(programNote(f, null))));
  }
  return { type: 'doc', version: 1, content: [...content, ...run] };
}

/* ---------------------------------- Linear ---------------------------------- */

const LINEAR_SEARCH =
  'query($teamId: ID!, $fp: String!) { issues(first: 1, filter: { team: { id: { eq: $teamId } }, ' +
  'description: { contains: $fp }, state: { type: { nin: ["completed", "canceled"] } } }) { nodes { id identifier } } }';
const LINEAR_CREATE =
  'mutation($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url } } }';

const issueLine = (name, created, skipped, capped, max) =>
  `${name}: ${created} issue(s) created, ${skipped} already open${capped > 0 ? `, ${capped} not filed (max-issues ${max})` : ''}.`;

/**
 * One Linear issue per proven finding, skipping any whose fingerprint already
 * appears in an open issue's description, capped at `max` created. Stops at the
 * first failure with one line. Unproven patterns are never passed in.
 */
export async function deliverLinear({ apiKey, teamId, repository, findings, runUrl, max, fetch, apiUrl = LINEAR_API, timeoutMs = TIMEOUT_MS }) {
  const secrets = [apiKey];
  const headers = { 'content-type': 'application/json', authorization: apiKey };
  const gql = async (query, variables) => {
    const r = await request(fetch, apiUrl, { method: 'POST', headers, body: JSON.stringify({ query, variables }) }, timeoutMs);
    if (!r.ok) throw new Error(`Linear answered ${r.status}`);
    if (r.json === null || (Array.isArray(r.json.errors) && r.json.errors.length > 0)) {
      // The server's own words reach the log and the job summary, so only letters, digits and plain punctuation pass.
      const said = firstLine(r.json?.errors?.[0]?.message ?? 'no JSON body').replace(/[^A-Za-z0-9 ,'_-]/g, ' ');
      throw new Error(`Linear returned errors: ${cap(said, 120, '...')}`);
    }
    return r.json.data;
  };
  let created = 0;
  let skipped = 0;
  try {
    for (const f of findings) {
      if (created >= max) break;
      const fp = fingerprint(repository, f);
      const found = await gql(LINEAR_SEARCH, { teamId, fp });
      if ((found?.issues?.nodes?.length ?? 0) > 0) {
        skipped += 1;
        continue;
      }
      const made = await gql(LINEAR_CREATE, {
        input: { teamId, title: issueTitle(f), description: linearDescription(f, runUrl, fp) },
      });
      if (made?.issueCreate?.success !== true) throw new Error('Linear did not confirm issueCreate');
      created += 1;
    }
  } catch (error) {
    return { created, skipped, line: failure('Linear', error, secrets) };
  }
  return { created, skipped, line: issueLine('Linear', created, skipped, findings.length - skipped - created, max) };
}

/* ----------------------------------- Jira ----------------------------------- */

const jqlString = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

/**
 * One Jira Cloud issue per proven finding (REST v3). De-duplication is a JQL
 * search for the finding's fingerprint, which is also set as a label so the
 * match is exact rather than a text-index guess.
 */
export async function deliverJira({ baseUrl, email, apiToken, projectKey, issueType, repository, findings, runUrl, max, fetch, timeoutMs = TIMEOUT_MS }) {
  const basic = Buffer.from(`${email}:${apiToken}`).toString('base64');
  const auth = `Basic ${basic}`;
  const secrets = [apiToken, email, auth, basic];
  const headers = { 'content-type': 'application/json', accept: 'application/json', authorization: auth };
  const base = baseUrl.replace(/\/+$/, '');
  let created = 0;
  let skipped = 0;
  try {
    for (const f of findings) {
      if (created >= max) break;
      const fp = fingerprint(repository, f);
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
            summary: issueTitle(f),
            description: jiraDescription(f, runUrl, fp),
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
  return { created, skipped, line: issueLine('Jira', created, skipped, findings.length - skipped - created, max) };
}
