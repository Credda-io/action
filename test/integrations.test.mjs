/*
 * Slack, Linear and Jira delivery, against a local HTTP server standing in for
 * each API. No real Slack, Linear or Jira account was used: the request shapes
 * are written from the vendors' public documentation as known, and this file
 * proves what this action sends, not that a vendor accepts it.
 *
 * Run with `node --test test/integrations.test.mjs`. Nothing is installed.
 */

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  allowedUrl,
  decideSlack,
  deliverJira,
  deliverLinear,
  jiraFingerprint,
  readFindings,
  sendSlack,
  slackMessage,
} from '../integrations.mjs';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const RUN = 'https://github.com/acme/widgets/actions/runs/42';

const finding = (n, extra = {}) => ({
  id: `PROTOTYPE_POLLUTION@src/merge${n}.js:${n}`,
  class: 'PROTOTYPE_POLLUTION',
  cwe: 'CWE-1321',
  site: { kind: 'source', file: `src/merge${n}.js`, line: n },
  sentence: `merge${n} lets __proto__ be set. Second line.`,
  program: `console.log('exploit ${n}');`,
  programFile: `probe${n}.js`,
  ...extra,
});

function securityJson(count, unproven = 0) {
  const dir = mkdtempSync(join(tmpdir(), 'credda-int-'));
  const path = join(dir, 'security.json');
  writeFileSync(
    path,
    JSON.stringify({
      version: 1,
      probes: [],
      findings: Array.from({ length: count }, (_, i) => finding(i + 1)),
      ...(unproven > 0 ? { unproven: Array.from({ length: unproven }, (_, i) => ({ id: `u${i}`, rule: 'R', reason: 'x' })) } : {}),
    }),
  );
  return path;
}

/** A local server that records requests and answers through `handler`. */
async function stub(handler) {
  const seen = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const entry = { method: req.method, url: req.url, headers: req.headers, body: body === '' ? null : JSON.parse(body) };
      seen.push(entry);
      handler(entry, res, seen);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}`;
  const close = () => new Promise((r) => (server.closeAllConnections(), server.close(r)));
  return { url, seen, close };
}
const json = (res, status, body) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};

const servers = [];
const make = async (handler) => {
  const s = await stub(handler);
  servers.push(s);
  return s;
};
after(() => Promise.all(servers.map((s) => s.close())));

const SECRET = 'lin_api_SECRETVALUE1234';

describe('readFindings and the unproven tier', () => {
  it('reads proven findings with site text, and counts unproven without listing them', () => {
    const got = readFindings(securityJson(2, 3));
    assert.equal(got.proven.length, 2);
    assert.equal(got.proven[0].site, 'src/merge1.js:1');
    assert.equal(got.proven[0].sentence, 'merge1 lets __proto__ be set. Second line.'.split('\n')[0]);
    assert.equal(got.unproven, 3);
  });
  it('returns null for a missing file', () => {
    assert.equal(readFindings('/nonexistent/security.json'), null);
  });
});

describe('Slack', () => {
  it('sends a Block Kit body with repo, outcome, count, at most 5 findings, and the run link', async () => {
    const s = await make((req, res) => json(res, 200, {}));
    const { proven, unproven } = readFindings(securityJson(7, 2));
    const message = slackMessage({ repository: 'acme/widgets', mode: 'security', outcome: '', runUrl: RUN, findings: proven, unprovenCount: unproven, statedFindings: 7 });
    const r = await sendSlack({ webhookUrl: `${s.url}/services/T/B/XXXX`, message, fetch });
    assert.equal(r.sent, true);
    const [req] = s.seen;
    assert.equal(req.method, 'POST');
    assert.equal(req.headers['content-type'], 'application/json');
    const blocks = req.body.blocks;
    assert.equal(blocks[0].type, 'header');
    assert.match(blocks[0].text.text, /proved 7 findings in acme\/widgets/);
    const findingBlocks = blocks.filter((b) => b.type === 'section' && /PROTOTYPE_POLLUTION/.test(b.text?.text ?? ''));
    assert.equal(findingBlocks.length, 5);
    assert.match(findingBlocks[0].text.text, /CWE-1321/);
    assert.match(findingBlocks[0].text.text, /src\/merge1\.js:1/);
    const all = JSON.stringify(blocks);
    assert.match(all, /2 more proven finding/);
    assert.match(all, /2 unproven pattern\(s\), not findings/);
    assert.match(all, new RegExp(RUN.replace(/\//g, '\\/')));
    assert.ok(!all.includes('exploit 1'), 'the exploit program is not sent to Slack');
  });

  it('never lists unproven patterns, only a labelled count', () => {
    const m = slackMessage({ repository: 'a/b', mode: 'security', outcome: '', runUrl: null, findings: [], unprovenCount: 4, statedFindings: 0 });
    assert.match(JSON.stringify(m.blocks), /4 unproven pattern\(s\), not findings/);
  });

  it('decides: findings is quiet on a clean run, always is not, and a bad value falls back', () => {
    const base = { mode: 'security', provenFindings: 0, statedFindings: 0, established: false };
    assert.equal(decideSlack({ ...base, notifyOn: 'findings' }).notify, false);
    assert.equal(decideSlack({ ...base, notifyOn: '' }).notify, false);
    assert.equal(decideSlack({ ...base, notifyOn: 'always' }).notify, true);
    assert.equal(decideSlack({ ...base, notifyOn: 'findings', provenFindings: 1 }).notify, true);
    const bad = decideSlack({ ...base, notifyOn: 'loud' });
    assert.equal(bad.notify, false);
    assert.match(bad.reason, /not 'findings' or 'always'/);
    // Non-security modes reuse decideNotification.
    assert.equal(decideSlack({ mode: 'discover', notifyOn: 'findings', provenFindings: 0, statedFindings: 2, established: false }).notify, true);
    assert.equal(decideSlack({ mode: 'discover', notifyOn: 'findings', provenFindings: 0, statedFindings: 0, established: false }).notify, false);
  });

  it('a 500 is one line, no throw, and the webhook URL is not in it', async () => {
    const s = await make((req, res) => json(res, 500, {}));
    const url = `${s.url}/services/T/SECRETPATH`;
    const r = await sendSlack({ webhookUrl: url, message: { text: 'x' }, fetch });
    assert.equal(r.sent, false);
    assert.match(r.line, /answered 500/);
    assert.ok(!r.line.includes('SECRETPATH'));
    assert.equal(r.line.split('\n').length, 1);
  });

  it('a refused connection is one line without the URL', async () => {
    const dead = await stub(() => {});
    const url = `${dead.url}/services/T/SECRETPATH`;
    await dead.close();
    const r = await sendSlack({ webhookUrl: url, message: { text: 'x' }, fetch });
    assert.equal(r.sent, false);
    assert.equal(r.line.split('\n').length, 1);
    assert.ok(!r.line.includes('SECRETPATH'));
  });

  it('a hang times out', async () => {
    const s = await make(() => {});
    const r = await sendSlack({ webhookUrl: `${s.url}/hook`, message: { text: 'x' }, fetch, timeoutMs: 150 });
    assert.equal(r.sent, false);
    assert.match(r.line, /was not delivered/);
  });
});

describe('Linear', () => {
  const linear = (s, over = {}) => ({
    apiKey: SECRET,
    teamId: 'team-1',
    findings: readFindings(securityJson(3)).proven,
    runUrl: RUN,
    max: 10,
    fetch,
    apiUrl: `${s.url}/graphql`,
    ...over,
  });
  const ok = (req, res) => {
    const q = req.body.query;
    if (q.includes('issueCreate')) return json(res, 200, { data: { issueCreate: { success: true, issue: { id: 'i', identifier: 'ENG-1', url: 'u' } } } });
    return json(res, 200, { data: { issues: { nodes: [] } } });
  };

  it('searches by finding id then creates one issue per finding with the documented fields', async () => {
    const s = await make(ok);
    const r = await deliverLinear(linear(s));
    assert.equal(r.created, 3);
    const creates = s.seen.filter((x) => x.body.query.includes('issueCreate'));
    assert.equal(creates.length, 3);
    const first = creates[0];
    assert.equal(first.method, 'POST');
    assert.equal(first.url, '/graphql');
    assert.equal(first.headers.authorization, SECRET);
    const input = first.body.variables.input;
    assert.equal(input.teamId, 'team-1');
    assert.equal(input.title, 'Credda: PROTOTYPE_POLLUTION in src/merge1.js:1');
    assert.match(input.description, /merge1 lets __proto__ be set/);
    assert.match(input.description, /CWE: CWE-1321/);
    assert.match(input.description, /Credda finding id: PROTOTYPE_POLLUTION@src\/merge1\.js:1/);
    assert.match(input.description, /```js\nconsole\.log\('exploit 1'\);\n```/);
    assert.match(input.description, /Run: https:\/\/github\.com\/acme\/widgets\/actions\/runs\/42/);
    const search = s.seen.find((x) => x.body.query.includes('issues('));
    assert.equal(search.body.variables.fp, 'PROTOTYPE_POLLUTION@src/merge1.js:1');
    assert.equal(search.body.variables.teamId, 'team-1');
    assert.match(search.body.query, /nin: \["completed", "canceled"\]/);
  });

  it('skips a finding already in an open issue', async () => {
    const s = await make((req, res) =>
      req.body.query.includes('issueCreate')
        ? ok(req, res)
        : json(res, 200, { data: { issues: { nodes: req.body.variables.fp.includes('merge2') ? [{ id: 'x', identifier: 'ENG-9' }] : [] } } }),
    );
    const r = await deliverLinear(linear(s));
    assert.equal(r.created, 2);
    assert.equal(r.skipped, 1);
    const titles = s.seen.filter((x) => x.body.query.includes('issueCreate')).map((x) => x.body.variables.input.title);
    assert.ok(!titles.some((t) => t.includes('merge2')));
  });

  it('caps issues created per run', async () => {
    const s = await make(ok);
    const r = await deliverLinear(linear(s, { findings: readFindings(securityJson(6)).proven, max: 2 }));
    assert.equal(r.created, 2);
    assert.equal(s.seen.filter((x) => x.body.query.includes('issueCreate')).length, 2);
    assert.match(r.line, /4 not filed \(max-issues 2\)/);
  });

  it('files nothing when only unproven patterns exist', async () => {
    const s = await make(ok);
    const { proven, unproven } = readFindings(securityJson(0, 3));
    assert.equal(unproven, 3);
    const r = await deliverLinear(linear(s, { findings: proven }));
    assert.equal(r.created, 0);
    assert.equal(s.seen.length, 0);
  });

  it('a GraphQL error body on a 200 is a failure, one line, no secret', async () => {
    const s = await make((req, res) => json(res, 200, { errors: [{ message: `bad key ${SECRET}` }] }));
    const r = await deliverLinear(linear(s));
    assert.equal(r.created, 0);
    assert.equal(r.line.split('\n').length, 1);
    assert.ok(!r.line.includes(SECRET));
  });

  it('500, refusal and timeout all return one line without throwing', async () => {
    const five = await make((req, res) => json(res, 500, {}));
    const r1 = await deliverLinear(linear(five));
    assert.match(r1.line, /answered 500/);
    const dead = await stub(() => {});
    const deadUrl = dead.url;
    await dead.close();
    const r2 = await deliverLinear(linear({ url: deadUrl }));
    assert.match(r2.line, /Linear was not delivered/);
    const hang = await make(() => {});
    const r3 = await deliverLinear(linear(hang, { timeoutMs: 150 }));
    assert.match(r3.line, /Linear was not delivered/);
    for (const r of [r1, r2, r3]) {
      assert.equal(r.line.split('\n').length, 1);
      assert.ok(!r.line.includes(SECRET));
    }
    assert.equal(five.seen.length, 1, 'one attempt, no retry');
  });
});

describe('Jira', () => {
  const TOKEN = 'jira_TOKEN_SECRET_99';
  const jira = (s, over = {}) => ({
    baseUrl: `${s.url}/`,
    email: 'bot@acme.test',
    apiToken: TOKEN,
    projectKey: 'SEC',
    issueType: 'Bug',
    findings: readFindings(securityJson(3)).proven,
    runUrl: RUN,
    max: 10,
    fetch,
    ...over,
  });
  const ok = (req, res) =>
    req.url.includes('/search/jql') ? json(res, 200, { issues: [] }) : json(res, 201, { id: '1', key: 'SEC-1' });

  it('searches by fingerprint then creates Bug issues with ADF and basic auth', async () => {
    const s = await make(ok);
    const r = await deliverJira(jira(s));
    assert.equal(r.created, 3);
    const search = s.seen.find((x) => x.url === '/rest/api/3/search/jql');
    assert.equal(search.method, 'POST');
    const fp = jiraFingerprint('PROTOTYPE_POLLUTION@src/merge1.js:1');
    assert.match(fp, /^creddafp[0-9a-f]{20}$/);
    assert.equal(search.body.jql, `project = "SEC" AND statusCategory != Done AND labels = "${fp}"`);
    const create = s.seen.find((x) => x.url === '/rest/api/3/issue');
    assert.equal(create.method, 'POST');
    assert.equal(create.headers.authorization, `Basic ${Buffer.from(`bot@acme.test:${TOKEN}`).toString('base64')}`);
    const f = create.body.fields;
    assert.deepEqual(f.project, { key: 'SEC' });
    assert.deepEqual(f.issuetype, { name: 'Bug' });
    assert.equal(f.summary, 'Credda: PROTOTYPE_POLLUTION in src/merge1.js:1');
    assert.deepEqual(f.labels, ['credda', fp]);
    assert.equal(f.description.type, 'doc');
    assert.equal(f.description.version, 1);
    const code = f.description.content.find((n) => n.type === 'codeBlock');
    assert.equal(code.content[0].text, "console.log('exploit 1');");
    const text = JSON.stringify(f.description);
    assert.match(text, /CWE: CWE-1321/);
    assert.match(text, /Credda finding id: PROTOTYPE_POLLUTION@src\/merge1\.js:1/);
    assert.match(text, /"type":"link"/);
  });

  it('uses the overridden issue type', async () => {
    const s = await make(ok);
    await deliverJira(jira(s, { issueType: 'Task', findings: readFindings(securityJson(1)).proven }));
    assert.equal(s.seen.find((x) => x.url === '/rest/api/3/issue').body.fields.issuetype.name, 'Task');
  });

  it('skips a finding whose fingerprint is already open', async () => {
    const dup = jiraFingerprint('PROTOTYPE_POLLUTION@src/merge2.js:2');
    const s = await make((req, res) =>
      req.url.includes('/search/jql')
        ? json(res, 200, { issues: req.body.jql.includes(dup) ? [{ key: 'SEC-5' }] : [] })
        : json(res, 201, { key: 'SEC-1' }),
    );
    const r = await deliverJira(jira(s));
    assert.equal(r.created, 2);
    assert.equal(r.skipped, 1);
  });

  it('caps issues and never files unproven patterns', async () => {
    const s = await make(ok);
    const r = await deliverJira(jira(s, { findings: readFindings(securityJson(6)).proven, max: 2 }));
    assert.equal(r.created, 2);
    assert.match(r.line, /4 not filed \(max-issues 2\)/);
    const none = await make(ok);
    await deliverJira(jira(none, { findings: readFindings(securityJson(0, 5)).proven }));
    assert.equal(none.seen.length, 0);
  });

  it('500, refusal and timeout return one line, exit-0 shaped, without the token', async () => {
    const five = await make((req, res) => json(res, 500, {}));
    const r1 = await deliverJira(jira(five));
    const dead = await stub(() => {});
    const deadUrl = dead.url;
    await dead.close();
    const r2 = await deliverJira(jira({ url: deadUrl }));
    const hang = await make(() => {});
    const r3 = await deliverJira(jira(hang, { timeoutMs: 150 }));
    for (const r of [r1, r2, r3]) {
      assert.match(r.line, /Jira was not delivered/);
      assert.equal(r.line.split('\n').length, 1);
      assert.ok(!r.line.includes(TOKEN));
      assert.ok(!r.line.includes(Buffer.from(`bot@acme.test:${TOKEN}`).toString('base64')));
    }
    assert.equal(five.seen.length, 1);
  });
});

describe('allowedUrl', () => {
  it('accepts https and loopback http only', () => {
    assert.equal(allowedUrl('https://acme.atlassian.net'), true);
    assert.equal(allowedUrl('http://127.0.0.1:9'), true);
    assert.equal(allowedUrl('http://acme.atlassian.net'), false);
    assert.equal(allowedUrl('ftp://x'), false);
    assert.equal(allowedUrl('not a url'), false);
  });
});

describe('integrate.mjs, run as the action runs it', () => {
  const run = (destination, env) =>
    spawnSync(process.execPath, [join(root, 'integrate.mjs'), destination], {
      env: { PATH: process.env.PATH, GITHUB_REPOSITORY: 'acme/widgets', GITHUB_RUN_ID: '42', ...env },
      encoding: 'utf8',
      timeout: 30_000,
    });

  it('masks each secret first, exits 0, and sends the Slack body', async () => {
    const s = await make((req, res) => json(res, 200, {}));
    const hook = `${s.url}/services/T/B/SLACKSECRET`;
    const out = await new Promise((resolve) => {
      const c = spawn(process.execPath, [join(root, 'integrate.mjs'), 'slack'], {
        env: { PATH: process.env.PATH, GITHUB_REPOSITORY: 'acme/widgets', GITHUB_RUN_ID: '42', CREDDA_SLACK_WEBHOOK_URL: hook, CREDDA_NOTIFY_ON: 'always', CREDDA_MODE: 'security', CREDDA_SECURITY_JSON: securityJson(2, 1) },
      });
      let stdout = '';
      c.stdout.on('data', (d) => (stdout += d));
      c.on('close', (code) => resolve({ code, stdout }));
    });
    assert.equal(out.code, 0);
    assert.equal(out.stdout.split('\n')[0], `::add-mask::${hook}`);
    assert.equal(s.seen.length, 1);
    const printed = out.stdout.split('\n').slice(1).join('\n');
    assert.ok(!printed.includes('SLACKSECRET'));
  });

  it('a failing destination exits 0, prints one line, and never prints the secrets', () => {
    // Port 9 (discard) on loopback: nothing listens, so the connection is refused.
    const r = run('jira', {
      CREDDA_JIRA_BASE_URL: 'http://127.0.0.1:9',
      CREDDA_JIRA_EMAIL: 'bot@acme.test',
      CREDDA_JIRA_API_TOKEN: 'JIRATOKENXYZ',
      CREDDA_JIRA_PROJECT_KEY: 'SEC',
      CREDDA_MODE: 'security',
      CREDDA_SECURITY_JSON: securityJson(1),
    });
    assert.equal(r.status, 0);
    const lines = r.stdout.split('\n').filter((l) => l !== '' && !l.startsWith('::add-mask::'));
    assert.equal(lines.length, 1);
    assert.match(lines[0], /Jira was not delivered/);
    const afterMasks = lines.join('\n') + r.stderr;
    assert.ok(!afterMasks.includes('JIRATOKENXYZ'));
    assert.ok(!afterMasks.includes(Buffer.from('bot@acme.test:JIRATOKENXYZ').toString('base64')));
  });

  it('refuses a non-https Jira base URL without sending', () => {
    const r = run('jira', {
      CREDDA_JIRA_BASE_URL: 'http://acme.atlassian.net',
      CREDDA_JIRA_EMAIL: 'b@a.test',
      CREDDA_JIRA_API_TOKEN: 'TOKEN1234',
      CREDDA_JIRA_PROJECT_KEY: 'SEC',
      CREDDA_MODE: 'security',
      CREDDA_SECURITY_JSON: securityJson(1),
    });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /must be an https URL/);
  });

  it('a clean run with notify-on findings says so and sends nothing', async () => {
    const s = await make((req, res) => json(res, 200, {}));
    const r = run('slack', { CREDDA_SLACK_WEBHOOK_URL: `${s.url}/hook`, CREDDA_MODE: 'security', CREDDA_SECURITY_JSON: securityJson(0, 2) });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /No Slack message/);
    assert.equal(s.seen.length, 0);
  });
});

describe('off by default (action.yml)', () => {
  const yml = readFileSync(join(root, 'action.yml'), 'utf8');
  const stepFor = (name) => {
    const start = yml.indexOf(`- name: ${name}`);
    assert.ok(start > 0, `step ${name} exists`);
    const next = yml.indexOf('\n    - name:', start + 1);
    return yml.slice(start, next === -1 ? undefined : next);
  };
  it('every integration input defaults empty (or a harmless default) and each step is gated on its inputs', () => {
    for (const name of ['slack-webhook-url', 'linear-api-key', 'linear-team-id', 'jira-base-url', 'jira-email', 'jira-api-token', 'jira-project-key']) {
      assert.match(yml, new RegExp(`\\n  ${name}:\\n[\\s\\S]*?\\n    default: ''\\n`), `${name} defaults to ''`);
    }
    assert.match(stepFor('Post to Slack'), /if: inputs\.slack-webhook-url != ''/);
    const linear = stepFor('File proven findings in Linear');
    assert.match(linear, /inputs\.linear-api-key != ''/);
    assert.match(linear, /inputs\.linear-team-id != ''/);
    assert.match(linear, /inputs\.mode == 'security'/);
    const jiraStep = stepFor('File proven findings in Jira');
    for (const k of ['jira-base-url', 'jira-email', 'jira-api-token', 'jira-project-key']) assert.match(jiraStep, new RegExp(`inputs\\.${k} != ''`));
    assert.match(yml, /\n  notify-on:\n[\s\S]*?default: 'findings'/);
    assert.match(yml, /\n  max-issues:\n[\s\S]*?default: '10'/);
  });
  it('secrets reach the scripts only as step env, never inside a run: line', () => {
    for (const name of ['Post to Slack', 'File proven findings in Linear', 'File proven findings in Jira']) {
      const run = stepFor(name).split('\n').find((l) => l.trim().startsWith('run:'));
      assert.ok(!run.includes('inputs.'), `${name}: run line has no input expression`);
    }
  });
});
