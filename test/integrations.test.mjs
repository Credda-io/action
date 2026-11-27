/*
 * Slack, Linear and Jira delivery, against a local HTTP server standing in for
 * each API. No real Slack, Linear or Jira account was used: the request shapes
 * are written from the vendors' public documentation as known, and this file
 * proves what this action sends, not that a vendor accepts it.
 *
 * The findings below copy the shape of a real engine v0.1.17 security.json: a
 * package-level probe finding, fuzz findings with ids `CLASS@fuzz:fn`, and exploit
 * programs of about 20 KB.
 *
 * Run with `node --test test/integrations.test.mjs`. Nothing is installed.
 */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  cap,
  checkUrl,
  decideSlack,
  DESCRIPTION_LIMIT,
  deliverJira,
  deliverLinear,
  fingerprint,
  jiraDescription,
  linearDescription,
  readFindings,
  sendSlack,
  SLACK_TEXT_LIMIT,
  slackMessage,
} from '../integrations.mjs';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const RUN = 'https://github.com/acme/widgets/actions/runs/42';
const REPO = 'acme/widgets';

const finding = (n, extra = {}) => ({
  id: `PROTOTYPE_POLLUTION@src/merge${n}.js:${n}`,
  language: 'javascript',
  class: 'PROTOTYPE_POLLUTION',
  cwe: 'CWE-1321',
  site: { kind: 'source', file: `src/merge${n}.js`, line: n },
  sentence: `merge${n} lets __proto__ be set. Second line.`,
  program: `console.log('exploit ${n}');`,
  programFile: `probe${n}.js`,
  ...extra,
});

/** A program of about `size` characters with backtick runs and quotes in it, like the real reproducers. */
const bigProgram = (size) => {
  const line = "const s = `x${1}`; JSON.parse('{\"a\":1}'); // ```\n";
  return `#!/usr/bin/env node\n${line.repeat(Math.ceil(size / line.length))}`.slice(0, size);
};

/** Three findings shaped like the real vulnerable run. */
const realShaped = (seed = 1) => [
  { id: 'PROTOTYPE_POLLUTION', language: 'javascript', class: 'PROTOTYPE_POLLUTION', cwe: 'CWE-1321', site: { kind: 'package', file: 'package.json' }, sentence: `Error: Calling this package's own exports leaves a property on Object.prototype. ${'x '.repeat(130)}end`, program: bigProgram(17_428) },
  { id: 'PROTOTYPE_POLLUTION@fuzz:unflatten', language: 'javascript', class: 'PROTOTYPE_POLLUTION', cwe: 'CWE-1321', site: { kind: 'package', file: 'package.json' }, sentence: 'Credda fuzz finding (PROTOTYPE_POLLUTION): calling unflatten(...) leaves a property on Object.prototype.', program: bigProgram(21_594), fuzz: { function: 'unflatten', fuzzer: 'credda-seeded-fuzzer 1', seed, iteration: 21 * seed, input: '({})' } },
  { id: 'MEMORY_EXHAUSTION@fuzz:unflatten', language: 'javascript', class: 'MEMORY_EXHAUSTION', cwe: 'CWE-770', site: { kind: 'package', file: 'package.json' }, sentence: 'Credda fuzz finding (MEMORY_EXHAUSTION): a 90-byte input exhausts a 256 MB heap.', program: bigProgram(21_672), fuzz: { function: 'unflatten', fuzzer: 'credda-seeded-fuzzer 1', seed, iteration: 1190 * seed, input: '({})' } },
];

function writeJson(findings, unproven = 0) {
  const dir = mkdtempSync(join(tmpdir(), 'credda-int-'));
  const path = join(dir, 'security.json');
  const probes = [{ id: 'PATH_TRAVERSAL' }, { id: 'PROTOTYPE_POLLUTION' }, ...findings.filter((f) => f.id.includes('@fuzz:')).map((f) => ({ id: f.id }))];
  writeFileSync(path, JSON.stringify({
    schemaVersion: 1,
    probes,
    findings,
    fuzz: { functions: 2 },
    unproven: Array.from({ length: unproven }, (_, i) => ({ id: `u${i}`, rule: 'R', reason: 'x' })),
  }));
  return path;
}
const securityJson = (count, unproven = 0) => writeJson(Array.from({ length: count }, (_, i) => finding(i + 1)), unproven);

/** A local server that records requests and answers through `handler`. */
async function stub(handler) {
  const seen = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const entry = { method: req.method, url: req.url, headers: req.headers, raw: body, body: body === '' ? null : JSON.parse(body) };
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

/** A fake Linear that keeps the issues it was given and searches their descriptions. */
const statefulLinear = () => {
  const issues = [];
  return {
    issues,
    handler: (req, res) => {
      const { query, variables } = req.body;
      if (query.includes('issueCreate')) {
        issues.push(variables.input);
        return json(res, 200, { data: { issueCreate: { success: true, issue: { id: `i${issues.length}`, identifier: `ENG-${issues.length}`, url: 'u' } } } });
      }
      const nodes = issues.filter((i) => i.teamId === variables.teamId && i.description.includes(variables.fp)).map((i) => ({ id: 'x', identifier: 'ENG' }));
      return json(res, 200, { data: { issues: { nodes: nodes.slice(0, 1) } } });
    },
  };
};

/** A fake Jira that keeps the issues it was given and answers `labels = "..."` searches. */
const statefulJira = () => {
  const issues = [];
  return {
    issues,
    handler: (req, res) => {
      if (req.url === '/rest/api/3/issue') {
        issues.push(req.body.fields);
        return json(res, 201, { id: String(issues.length), key: `SEC-${issues.length}` });
      }
      const label = /labels = "([^"]+)"/.exec(req.body.jql)[1];
      return json(res, 200, { issues: issues.filter((i) => i.labels.includes(label)).map((i) => ({ key: 'SEC' })) });
    },
  };
};

const SECRET = 'lin_api_SECRETVALUE1234';

describe('readFindings, through the same reader as the job summary', () => {
  it('reads proven findings with site text, and counts unproven without listing them', () => {
    const got = readFindings(securityJson(2, 3));
    assert.equal(got.proven.length, 2);
    assert.equal(got.proven[0].site, 'at src/merge1.js:1');
    assert.equal(got.proven[0].sentence, 'merge1 lets __proto__ be set. Second line.');
    assert.equal(got.unproven, 3);
  });
  it('reads the v0.1.17 shapes: package site by its manifest, fuzz function, language, probes without fuzz proofs', () => {
    const python = { ...finding(1), id: 'CMD@py:x', language: 'python', site: { kind: 'package', file: 'pyproject.toml' } };
    const got = readFindings(writeJson([...realShaped(), python]));
    assert.equal(got.proven[0].site, 'in the package (through package.json)');
    assert.equal(got.proven[1].fuzzFunction, 'unflatten');
    assert.equal(got.proven[3].site, 'in the package (through pyproject.toml)');
    assert.equal(got.proven[3].language, 'python');
    assert.equal(got.probes, 2);
    assert.equal(got.fuzzed, 2);
    assert.ok(got.proven[0].sentence.endsWith('end'), 'the sentence is not cut at 300 characters');
  });
  it('returns null for a missing file', () => {
    assert.equal(readFindings('/nonexistent/security.json'), null);
  });
});

describe('cap', () => {
  it('leaves short text alone and states every cut, at a space when one is near', () => {
    assert.equal(cap('short', 10), 'short');
    const out = cap('alpha beta gamma delta epsilon', 22, ' [cut]');
    assert.equal(out, 'alpha beta gamma [cut]');
    assert.ok(out.length <= 22);
  });
});

describe('Slack', () => {
  it('sends a Block Kit body with repo, outcome, count, at most 5 findings, and the run link', async () => {
    const s = await make((req, res) => json(res, 200, {}));
    const { proven, unproven } = readFindings(securityJson(7, 2));
    const message = slackMessage({ repository: REPO, mode: 'security', outcome: '', runUrl: RUN, findings: proven, unprovenCount: unproven, statedFindings: 7 });
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
    assert.match(findingBlocks[0].text.text, /at src\/merge1\.js:1/);
    const all = JSON.stringify(blocks);
    assert.match(all, /2 more proven finding/);
    assert.match(all, /2 unproven pattern\(s\), not findings/);
    assert.match(all, new RegExp(RUN.replace(/\//g, '\\/')));
    assert.ok(!all.includes('exploit 1'), 'the exploit program is not sent to Slack');
  });

  it('names a fuzz finding by the function fuzzed', () => {
    const { proven } = readFindings(writeJson(realShaped()));
    const m = slackMessage({ repository: REPO, mode: 'security', outcome: '', runUrl: RUN, findings: proven, unprovenCount: 0, statedFindings: 3 });
    assert.match(JSON.stringify(m.blocks), /through unflatten \(fuzzing\)/);
  });

  it('stays inside Slack limits however long the repository text is, and says where it cut', () => {
    const long = { ...finding(1), sentence: `${'<!channel> & '.repeat(900)}tail`, site: { kind: 'source', file: `${'a/'.repeat(3000)}x.js`, line: 1 } };
    const { proven } = readFindings(writeJson(Array.from({ length: 60 }, () => long)));
    const m = slackMessage({ repository: REPO, mode: 'security', outcome: '', runUrl: RUN, findings: proven, unprovenCount: 0, statedFindings: 60 });
    assert.ok(m.blocks.length <= 50);
    assert.ok(m.blocks[0].text.text.length <= 150);
    for (const b of m.blocks) {
      if (b.text) assert.ok(b.text.text.length <= SLACK_TEXT_LIMIT, `section text ${b.text.text.length}`);
      for (const f of b.fields ?? []) assert.ok(f.text.length <= 2000);
      for (const e of b.elements ?? []) assert.ok(e.text.length <= SLACK_TEXT_LIMIT);
    }
    const section = m.blocks.find((b) => /PROTOTYPE_POLLUTION/.test(b.text?.text ?? ''));
    assert.match(section.text.text, /\[cut; the full text is on the run page\]$/);
    assert.doesNotMatch(section.text.text, /&(a|am|l|lt|g|gt)?\s*\[cut/, 'no entity is cut in half');
  });

  it('a hostile sentence or file name cannot forge a mention or a link', () => {
    const hostile = { ...finding(1), sentence: 'Hi <!channel> <!here> @everyone @here [docs](https://evil.test) <https://evil.test|click>', site: { kind: 'source', file: '<https://evil.test|x>.js', line: 2 } };
    const { proven } = readFindings(writeJson([hostile]));
    const text = JSON.stringify(slackMessage({ repository: REPO, mode: 'security', outcome: '', runUrl: RUN, findings: proven, unprovenCount: 0, statedFindings: 1 }).blocks);
    assert.ok(!text.includes('<!channel>') && !text.includes('<!here>'));
    assert.ok(!text.includes('<https://evil'));
    assert.ok(!/@(everyone|here)\b/.test(text), 'bare mentions are broken with a zero-width space');
    assert.match(text, /&lt;!channel&gt;/);
    // The one link is the run.
    assert.deepEqual(text.match(/<http[^>]*>/g), [`<${RUN}|View the run>`]);
  });

  it('a clean run with always says no exploit succeeded and that this is not an audit', () => {
    const { proven, probes, fuzzed } = readFindings(writeJson([]));
    const m = slackMessage({ repository: REPO, mode: 'security', outcome: '', runUrl: RUN, findings: proven, unprovenCount: 0, statedFindings: 0, probes, fuzzed });
    assert.match(m.blocks[0].text.text, /No exploit succeeded in acme\/widgets/);
    const all = JSON.stringify(m.blocks);
    assert.match(all, /Ran 2 exploit probes and fuzzed 2 exported functions\. No exploit succeeded\. That is not an audit/);
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

  it('a redirect is not followed', async () => {
    const elsewhere = await make((req, res) => json(res, 200, {}));
    const s = await make((req, res) => {
      res.writeHead(307, { location: `${elsewhere.url}/stolen` });
      res.end();
    });
    const r = await sendSlack({ webhookUrl: `${s.url}/services/T/SECRETPATH`, message: { text: 'x' }, fetch });
    assert.equal(r.sent, false);
    assert.equal(elsewhere.seen.length, 0);
    assert.ok(!r.line.includes('SECRETPATH'));
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

describe('issue descriptions', () => {
  const [probe, fuzz] = readFindings(writeJson(realShaped())).proven;

  it('a 20 KB exploit goes in whole, fenced so its own backticks cannot close the fence', () => {
    const fp = fingerprint(REPO, fuzz);
    const md = linearDescription(fuzz, RUN, fp);
    assert.ok(md.length <= DESCRIPTION_LIMIT);
    assert.ok(md.includes(fuzz.program), 'the program is whole');
    assert.match(md, /\n````js\n/);
    const adf = jiraDescription(fuzz, RUN, fp);
    assert.ok(JSON.stringify(adf).length <= DESCRIPTION_LIMIT, `ADF is ${JSON.stringify(adf).length}`);
    assert.equal(adf.content.find((n) => n.type === 'codeBlock').content[0].text, fuzz.program);
    assert.ok(linearDescription(probe, RUN, fp).includes(probe.program));
  });

  it('an exploit too long for the cap is left out whole with a note and the run link, never cut', () => {
    const huge = { ...fuzz, program: bigProgram(40_000) };
    const md = linearDescription(huge, RUN, 'fp');
    assert.ok(md.length <= DESCRIPTION_LIMIT);
    assert.ok(!md.includes('#!/usr/bin/env node'), 'no part of the program');
    assert.match(md, /The exploit program \\\(40000 characters\\\) is too long/);
    assert.match(md, /Run: https:\/\/github\.com\/acme\/widgets\/actions\/runs\/42$/);
    const adf = jiraDescription(huge, RUN, 'fp');
    assert.ok(JSON.stringify(adf).length <= DESCRIPTION_LIMIT);
    assert.equal(adf.content.find((n) => n.type === 'codeBlock'), undefined);
    assert.match(JSON.stringify(adf), /The exploit program \(40000 characters\) is too long for this description\. It is on the run's job summary/);
    assert.match(JSON.stringify(adf), /"href":"https:\/\/github\.com\/acme\/widgets\/actions\/runs\/42"/);
  });

  it('repository text cannot forge a link or a mention in Linear markdown or Jira ADF', () => {
    const hostile = readFindings(writeJson([{ ...finding(1), sentence: 'See [docs](https://evil.test) @everyone <b>x</b> ![i](https://evil.test/p.png)', site: { kind: 'source', file: '[a](https://evil.test).js', line: 1 } }])).proven[0];
    const md = linearDescription(hostile, RUN, 'fp');
    assert.ok(!/(^|[^\\])\[[^\]]*\]\(/.test(md), 'no unescaped [text](url)');
    assert.ok(!/(^|[^\\])@everyone/.test(md));
    assert.ok(!/(^|[^\\])</.test(md.split('The exploit')[0]));
    assert.match(md, /See \\\[docs\\\]\\\(https\\:\\\/\\\/evil\\\.test\\\)/);
    const adf = JSON.stringify(jiraDescription(hostile, RUN, 'fp'));
    assert.equal((adf.match(/"type":"link"/g) ?? []).length, 1, 'the only link is the run');
    assert.ok(!adf.includes('"mention"'));
  });
});

describe('de-duplication', () => {
  it('the fingerprint is the same across runs with another seed, and differs by repository and by finding', () => {
    const one = readFindings(writeJson(realShaped(1))).proven;
    const two = readFindings(writeJson(realShaped(7))).proven;
    assert.deepEqual(one.map((f) => fingerprint(REPO, f)), two.map((f) => fingerprint(REPO, f)));
    assert.equal(new Set(one.map((f) => fingerprint(REPO, f))).size, 3);
    assert.notEqual(fingerprint(REPO, one[0]), fingerprint('acme/other', one[0]));
    assert.match(fingerprint(REPO, one[0]), /^creddafp[0-9a-f]{20}$/);
  });

  it('a second run with the same findings files nothing new in Linear or Jira', async () => {
    const lin = statefulLinear();
    const jira = statefulJira();
    const ls = await make(lin.handler);
    const js = await make(jira.handler);
    const run = async (seed) => {
      const findings = readFindings(writeJson(realShaped(seed))).proven;
      const l = await deliverLinear({ apiKey: SECRET, teamId: 't', repository: REPO, findings, runUrl: RUN, max: 10, fetch, apiUrl: `${ls.url}/graphql` });
      const j = await deliverJira({ baseUrl: js.url, email: 'b@a.test', apiToken: 'T0KEN', projectKey: 'SEC', issueType: 'Bug', repository: REPO, findings, runUrl: RUN, max: 10, fetch });
      return [l, j];
    };
    const [l1, j1] = await run(1);
    assert.equal(l1.created, 3);
    assert.equal(j1.created, 3);
    const [l2, j2] = await run(7);
    assert.equal(l2.created, 0);
    assert.equal(l2.skipped, 3);
    assert.equal(j2.created, 0);
    assert.equal(j2.skipped, 3);
    assert.equal(lin.issues.length, 3);
    assert.equal(jira.issues.length, 3);
    assert.match(l2.line, /0 issue\(s\) created, 3 already open/);
  });

  it('a probe id that is a prefix of a fuzz id is still its own issue', async () => {
    const lin = statefulLinear();
    const ls = await make(lin.handler);
    const [probe, fuzz] = readFindings(writeJson(realShaped())).proven;
    await deliverLinear({ apiKey: SECRET, teamId: 't', repository: REPO, findings: [fuzz], runUrl: RUN, max: 10, fetch, apiUrl: `${ls.url}/graphql` });
    const r = await deliverLinear({ apiKey: SECRET, teamId: 't', repository: REPO, findings: [probe], runUrl: RUN, max: 10, fetch, apiUrl: `${ls.url}/graphql` });
    assert.equal(r.created, 1);
  });

  it('the same finding in another repository is its own issue', async () => {
    const jira = statefulJira();
    const js = await make(jira.handler);
    const findings = readFindings(writeJson(realShaped())).proven.slice(0, 1);
    const go = (repository) => deliverJira({ baseUrl: js.url, email: 'b@a.test', apiToken: 'T0KEN', projectKey: 'SEC', issueType: 'Bug', repository, findings, runUrl: RUN, max: 10, fetch });
    assert.equal((await go('acme/one')).created, 1);
    assert.equal((await go('acme/two')).created, 1);
    assert.equal((await go('acme/one')).created, 0);
  });
});

describe('Linear', () => {
  const linear = (s, over = {}) => ({
    apiKey: SECRET,
    teamId: 'team-1',
    repository: REPO,
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

  it('searches by fingerprint then creates one issue per finding with the documented fields', async () => {
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
    const fp = fingerprint(REPO, readFindings(securityJson(1)).proven[0]);
    assert.equal(input.teamId, 'team-1');
    assert.equal(input.title, 'Credda: PROTOTYPE_POLLUTION at src/merge1.js:1');
    assert.match(input.description, /merge1 lets \\_\\_proto\\_\\_ be set\\\./);
    assert.match(input.description, /CWE: CWE\\-1321/);
    assert.ok(input.description.includes(`Credda fingerprint: ${fp}`));
    assert.match(input.description, /```js\nconsole\.log\('exploit 1'\);\n```/);
    assert.match(input.description, /Run: https:\/\/github\.com\/acme\/widgets\/actions\/runs\/42/);
    const search = s.seen.find((x) => x.body.query.includes('issues('));
    assert.equal(search.body.variables.fp, fp);
    assert.equal(search.body.variables.teamId, 'team-1');
    assert.match(search.body.query, /nin: \["completed", "canceled"\]/);
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
    const s = await make((req, res) => json(res, 200, { errors: [{ message: `bad key ${SECRET}\nsecond line` }] }));
    const r = await deliverLinear(linear(s));
    assert.equal(r.created, 0);
    assert.equal(r.line.split('\n').length, 1);
    assert.ok(!r.line.includes(SECRET));
  });

  it('a GraphQL error message cannot carry a line break, a link or markup into the log or the job summary', async () => {
    const s = await make((req, res) => json(res, 200, { errors: [{ message: 'nope\r::add-mask::x [click](https://evil.test) <img src=https://evil.test/p.png> www.evil.test' }] }));
    const r = await deliverLinear(linear(s));
    assert.ok(!/[\r\n]/.test(r.line));
    assert.ok(!/[[\]<>]|https:|www\.evil/.test(r.line.replace('Linear was not delivered: Error: Linear returned errors: ', '').replace(/\. This run is unaffected\.$/, '')), r.line);
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
    repository: REPO,
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
    const fp = fingerprint(REPO, readFindings(securityJson(1)).proven[0]);
    assert.equal(search.body.jql, `project = "SEC" AND statusCategory != Done AND labels = "${fp}"`);
    const create = s.seen.find((x) => x.url === '/rest/api/3/issue');
    assert.equal(create.method, 'POST');
    assert.equal(create.headers.authorization, `Basic ${Buffer.from(`bot@acme.test:${TOKEN}`).toString('base64')}`);
    const f = create.body.fields;
    assert.deepEqual(f.project, { key: 'SEC' });
    assert.deepEqual(f.issuetype, { name: 'Bug' });
    assert.equal(f.summary, 'Credda: PROTOTYPE_POLLUTION at src/merge1.js:1');
    assert.deepEqual(f.labels, ['credda', fp]);
    assert.equal(f.description.type, 'doc');
    assert.equal(f.description.version, 1);
    const code = f.description.content.find((n) => n.type === 'codeBlock');
    assert.equal(code.content[0].text, "console.log('exploit 1');");
    assert.equal(code.attrs.language, 'javascript');
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

describe('checkUrl', () => {
  it('accepts https on a public host only', () => {
    assert.equal(checkUrl('https://acme.atlassian.net', 'x'), null);
    assert.equal(checkUrl('https://hooks.slack.com/services/T/B/C', 'x'), null);
    assert.equal(checkUrl('https://jira.acme.example', 'x'), null);
    for (const bad of [
      'http://acme.atlassian.net',
      'ftp://x.test',
      'not a url',
      'https://127.0.0.1',
      'https://localhost:8443',
      'https://app.localhost',
      'https://10.0.0.5',
      'https://172.20.1.1',
      'https://192.168.1.10',
      'https://169.254.169.254/latest',
      'https://100.64.0.1',
      'https://0.0.0.0',
      'https://[::1]',
      'https://[fd00::1]',
      'https://[fe80::1]',
      'https://[::ffff:127.0.0.1]',
      'https://jira',
      'https://jira.corp.internal',
      'https://nas.local',
      'https://user:pass@acme.atlassian.net',
    ]) {
      assert.notEqual(checkUrl(bad, 'x'), null, bad);
    }
    assert.equal(checkUrl('https://203.0.113.9', 'x'), null);
  });
  it('refuses the encodings and ranges that also reach a private address', () => {
    for (const bad of [
      'https://2130706433', // 127.0.0.1 as one number; URL normalises it
      'https://0x7f.1',
      'https://127.1',
      'https://[64:ff9b::7f00:1]', // NAT64 of 127.0.0.1
      'https://[64:ff9b::a9fe:a9fe]', // NAT64 of 169.254.169.254
      'https://224.0.0.1',
      'https://255.255.255.255',
      'https://198.18.0.1',
      'https://192.0.0.8',
      'https://[ff02::1]',
      'https://localhost.',
    ]) {
      assert.notEqual(checkUrl(bad, 'x'), null, bad);
    }
  });
});

describe('fix outcomes, from engine-written security.json with a fixes key', () => {
  const FIX = join(root, '.github/fixtures/security-fix');
  const PR = 'https://github.com/acme/widgets/pull/7';
  const record = (entries) => {
    const path = join(mkdtempSync(join(tmpdir(), 'credda-fixrec-')), 'fix-delivery.json');
    writeFileSync(path, JSON.stringify(entries));
    return path;
  };
  const opened = (url = PR) => record([{ class: 'PROTOTYPE_POLLUTION', language: 'javascript', outcome: 'opened', url }]);
  const byId = (got) => Object.fromEntries(got.proven.map((f) => [f.id, f.fix]));

  it('a proven fix with an opened pull request carries the URL; a declined class says rejected', () => {
    const fix = byId(readFindings(join(FIX, 'model/security.json'), opened()));
    assert.deepEqual(fix.PROTOTYPE_POLLUTION, { text: 'Fix proven by the check-fix gates. Pull request opened:', url: PR });
    assert.deepEqual(fix['PROTOTYPE_POLLUTION@fuzz:unflatten'], fix.PROTOTYPE_POLLUTION, 'both findings of the class share the attempt');
    assert.deepEqual(fix['MEMORY_EXHAUSTION@fuzz:unflatten'], { text: 'Fix rejected (stopped at declined).', url: '' });
  });

  it('a proven fix with no pull request says so, and one this action refused says nothing was proposed', () => {
    const only = byId(readFindings(join(FIX, 'model/security.json'), record([{ class: 'PROTOTYPE_POLLUTION', language: 'javascript', outcome: 'patch-only', url: '' }])));
    assert.equal(only.PROTOTYPE_POLLUTION.text, 'Fix proven by the check-fix gates. No pull request was opened. The job summary says why.');
    const off = byId(readFindings(join(FIX, 'model/security.json'), record([{ class: 'PROTOTYPE_POLLUTION', language: 'javascript', outcome: 'not-offered', url: '' }])));
    assert.match(off.PROTOTYPE_POLLUTION.text, /^The engine reported a proven fix, but the patch failed this action's checks, so nothing was proposed\.$/);
    const unknown = byId(readFindings(join(FIX, 'model/security.json')));
    assert.deepEqual(unknown.PROTOTYPE_POLLUTION, { text: 'Fix proven by the check-fix gates.', url: '' }, 'no delivery record: no claim about a pull request');
  });

  it('a patch the gates rejected names the verdict, and a run with no model says not attempted', () => {
    const broke = byId(readFindings(join(FIX, 'broke/security.json')));
    assert.equal(broke.PROTOTYPE_POLLUTION.text, 'Fix rejected by the check-fix gates (BROKE_FEATURE).');
    const heuristic = byId(readFindings(join(FIX, 'heuristic/security.json')));
    assert.equal(heuristic.PROTOTYPE_POLLUTION.text, 'Fix not attempted. The provider is not model-backed.');
    assert.equal(heuristic['MEMORY_EXHAUSTION@fuzz:unflatten'].text, 'Fix not attempted. The provider is not model-backed.');
  });

  it('with fix off there is no fix line anywhere', () => {
    const got = readFindings(writeJson(realShaped()));
    assert.ok(got.proven.every((f) => f.fix === null));
    const m = slackMessage({ repository: REPO, mode: 'security', outcome: '', runUrl: RUN, findings: got.proven, unprovenCount: 0, statedFindings: 3 });
    assert.doesNotMatch(JSON.stringify(m), /Fix /);
    assert.doesNotMatch(linearDescription(got.proven[0], RUN, 'fp'), /Fix /);
  });

  it('a URL not shaped like a pull request is dropped, so it cannot become a link', () => {
    for (const bad of ['https://evil.test/x|click>', 'javascript:alert(1)', 'http://github.com/a/b/pull/1', `${PR}\n::add-mask::x`, 'https://github.com/a/b/pull/1?x=<b>']) {
      const fix = byId(readFindings(join(FIX, 'model/security.json'), opened(bad)));
      assert.deepEqual(fix.PROTOTYPE_POLLUTION, { text: 'Fix proven by the check-fix gates. A pull request was opened.', url: '' }, bad);
    }
  });

  it('Slack, Linear and Jira each say the outcome per finding and link the pull request', () => {
    const got = readFindings(join(FIX, 'model/security.json'), opened());
    const slack = JSON.stringify(slackMessage({ repository: REPO, mode: 'security', outcome: '', runUrl: RUN, findings: got.proven, unprovenCount: 0, statedFindings: 3 }).blocks);
    assert.ok(slack.includes(`Fix proven by the check-fix gates. Pull request opened: <${PR}|${PR}>`));
    assert.match(slack, /Fix rejected \(stopped at declined\)\./);
    const [pp, , me] = got.proven;
    const md = linearDescription(pp, RUN, 'fp');
    assert.ok(md.includes(`Fix proven by the check\\-fix gates\\. Pull request opened\\: ${PR}`), md.slice(0, 600));
    assert.match(linearDescription(me, RUN, 'fp'), /Fix rejected \\\(stopped at declined\\\)\\\./);
    const adf = JSON.stringify(jiraDescription(pp, RUN, 'fp'));
    assert.ok(adf.includes(`"href":"${PR}"`));
    assert.match(adf, /Fix proven by the check-fix gates\. Pull request opened: /);
    assert.match(JSON.stringify(jiraDescription(me, RUN, 'fp')), /Fix rejected \(stopped at declined\)\./);
  });

  it('integrate.mjs reads the delivery record the run step wrote', async () => {
    const s = await make((req, res) => json(res, 200, {}));
    const env = {
      CREDDA_SLACK_WEBHOOK_URL: 'https://hooks.slack.com/services/T000/B000/FIXRUN1234',
      CREDDA_NOTIFY_ON: 'findings',
      CREDDA_MODE: 'security',
      CREDDA_SECURITY_JSON: join(FIX, 'model/security.json'),
      CREDDA_FIX_DELIVERY: opened(),
    };
    const summary = join(mkdtempSync(join(tmpdir(), 'credda-sum-')), 'summary.md');
    writeFileSync(summary, '');
    const code = await new Promise((resolve) => {
      const c = spawn(process.execPath, ['--import', join(root, 'test/fake-fetch.mjs'), join(root, 'integrate.mjs'), 'slack'], {
        env: { PATH: process.env.PATH, GITHUB_REPOSITORY: REPO, GITHUB_RUN_ID: '42', GITHUB_STEP_SUMMARY: summary, CREDDA_TEST_ORIGIN: s.url, ...env },
      });
      c.on('close', resolve);
    });
    assert.equal(code, 0);
    assert.equal(s.seen.length, 1);
    assert.ok(JSON.stringify(s.seen[0].body).includes(`<${PR}|${PR}>`));
  });
});

describe('integrate.mjs, run as the action runs it', () => {
  const SLACK_HOOK = 'https://hooks.slack.com/services/T000/B000/SLACKSECRETXYZ';
  const LINEAR_KEY = 'lin_api_FAKESECRET777';
  const JIRA_EMAIL = 'bot-secret@acme.test';
  const JIRA_TOKEN = 'JIRATOKENXYZ123';
  const BASIC = Buffer.from(`${JIRA_EMAIL}:${JIRA_TOKEN}`).toString('base64');
  const ALL_SECRETS = [SLACK_HOOK, '/services/T000/B000/SLACKSECRETXYZ', 'SLACKSECRETXYZ', LINEAR_KEY, JIRA_EMAIL, JIRA_TOKEN, BASIC];

  /** Runs one destination with every request sent to `origin`, and returns what it printed and wrote. */
  const run = (destination, env, origin) => {
    const summary = join(mkdtempSync(join(tmpdir(), 'credda-sum-')), 'summary.md');
    writeFileSync(summary, '');
    return new Promise((resolve) => {
      const c = spawn(process.execPath, ['--import', join(root, 'test/fake-fetch.mjs'), join(root, 'integrate.mjs'), destination], {
        env: { PATH: process.env.PATH, GITHUB_REPOSITORY: REPO, GITHUB_RUN_ID: '42', GITHUB_STEP_SUMMARY: summary, CREDDA_TEST_ORIGIN: origin ?? 'http://127.0.0.1:9', ...env },
      });
      let stdout = '';
      let stderr = '';
      c.stdout.on('data', (d) => (stdout += d));
      c.stderr.on('data', (d) => (stderr += d));
      c.on('close', (code) => resolve({ code, stdout, stderr, summary: readFileSync(summary, 'utf8') }));
    });
  };
  const slackEnv = (file, notifyOn = 'findings') => ({ CREDDA_SLACK_WEBHOOK_URL: SLACK_HOOK, CREDDA_NOTIFY_ON: notifyOn, CREDDA_MODE: 'security', CREDDA_SECURITY_JSON: file });
  const linearEnv = (file) => ({ CREDDA_LINEAR_API_KEY: LINEAR_KEY, CREDDA_LINEAR_TEAM_ID: 'team-1', CREDDA_MODE: 'security', CREDDA_SECURITY_JSON: file });
  const jiraEnv = (file, base = 'https://acme.atlassian.net') => ({ CREDDA_JIRA_BASE_URL: base, CREDDA_JIRA_EMAIL: JIRA_EMAIL, CREDDA_JIRA_API_TOKEN: JIRA_TOKEN, CREDDA_JIRA_PROJECT_KEY: 'SEC', CREDDA_MODE: 'security', CREDDA_SECURITY_JSON: file });
  /** Everything a person could read afterwards, except the mask commands, which the runner consumes. */
  const readable = (r) => [...r.stdout.split('\n').filter((l) => !l.startsWith('::add-mask::')), r.stderr, r.summary].join('\n');

  it('masks each secret first, exits 0, and sends the Slack body to the host the input named', async () => {
    const s = await make((req, res) => json(res, 200, {}));
    const out = await run('slack', slackEnv(writeJson(realShaped()), 'always'), s.url);
    assert.equal(out.code, 0);
    assert.equal(out.stdout.split('\n')[0], `::add-mask::${SLACK_HOOK}`);
    assert.equal(s.seen.length, 1);
    assert.equal(s.seen[0].headers['x-meant-host'], 'hooks.slack.com');
    assert.equal(s.seen[0].url, '/services/T000/B000/SLACKSECRETXYZ');
    assert.match(out.summary, /\*\*Credda to Slack:\*\* Slack message sent\./);
    for (const secret of ALL_SECRETS) assert.ok(!readable(out).includes(secret), secret);
  });

  it('each failing destination exits 0, says its status code in the log and the summary, and prints no secret', async () => {
    const file = writeJson(realShaped());
    const five = await make((req, res) => json(res, 503, { error: `upstream ${LINEAR_KEY}` }));
    const four = await make((req, res) => json(res, 401, { message: `bad token for ${JIRA_EMAIL}` }));
    const reset = await make((req, res) => res.socket.destroy());
    const results = {
      slack: await run('slack', slackEnv(file), five.url),
      linear: await run('linear', linearEnv(file), four.url),
      jira: await run('jira', jiraEnv(file), reset.url),
    };
    assert.match(results.slack.summary, /Slack was not delivered: the webhook answered 503\. This run is unaffected\./);
    assert.match(results.linear.summary, /Linear was not delivered: Error: Linear answered 401\. This run is unaffected\./);
    assert.match(results.jira.summary, /Jira was not delivered: TypeError .*: fetch failed\. This run is unaffected\./);
    for (const [name, r] of Object.entries(results)) {
      assert.equal(r.code, 0, name);
      const lines = r.stdout.split('\n').filter((l) => l !== '' && !l.startsWith('::add-mask::'));
      assert.equal(lines.length, 1, name);
      for (const secret of ALL_SECRETS) assert.ok(!readable(r).includes(secret), `${name} printed ${secret}`);
      assert.ok(!/authorization/i.test(readable(r)), `${name} printed a header`);
    }
  });

  it('a secret with a line break is masked and scrubbed line by line', async () => {
    const s = await make((req, res) => json(res, 401, { message: 'TOKENPARTTWO denied' }));
    const token = 'TOKENPARTONE\nTOKENPARTTWO';
    const r = await run('jira', { ...jiraEnv(writeJson(realShaped())), CREDDA_JIRA_API_TOKEN: token }, s.url);
    assert.equal(r.code, 0);
    const masks = r.stdout.split('\n').filter((l) => l.startsWith('::add-mask::'));
    assert.ok(masks.includes('::add-mask::TOKENPARTONE') && masks.includes('::add-mask::TOKENPARTTWO'), masks.join('|'));
    assert.ok(!masks.some((l) => l.includes('\n')));
    assert.ok(!readable(r).includes('TOKENPART'), readable(r));
  });

  it('refuses a non-https, loopback or private destination without sending', async () => {
    const s = await make((req, res) => json(res, 200, {}));
    const file = writeJson(realShaped());
    const http = await run('jira', jiraEnv(file, 'http://acme.atlassian.net'), s.url);
    assert.match(http.stdout, /jira-base-url must be an https URL/);
    const loop = await run('jira', jiraEnv(file, 'https://127.0.0.1:8443'), s.url);
    assert.match(loop.stdout, /jira-base-url must name a public host/);
    const meta = await run('slack', { ...slackEnv(file, 'always'), CREDDA_SLACK_WEBHOOK_URL: 'https://169.254.169.254/services/x' }, s.url);
    assert.match(meta.summary, /slack-webhook-url must name a public host/);
    for (const r of [http, loop, meta]) assert.equal(r.code, 0);
    assert.equal(s.seen.length, 0);
  });

  it('a clean run with notify-on findings sends nothing; with always it sends one message saying nothing was proven', async () => {
    const s = await make((req, res) => json(res, 200, {}));
    const file = writeJson([]);
    const quiet = await run('slack', slackEnv(file), s.url);
    assert.equal(quiet.code, 0);
    assert.match(quiet.stdout, /No Slack message/);
    assert.equal(s.seen.length, 0);
    const always = await run('slack', slackEnv(file, 'always'), s.url);
    assert.equal(always.code, 0);
    assert.equal(s.seen.length, 1);
    assert.match(JSON.stringify(s.seen[0].body), /No exploit succeeded\. That is not an audit/);
    const linear = await run('linear', linearEnv(file), s.url);
    assert.match(linear.stdout, /No linear issues: no finding was proven/);
    assert.equal(s.seen.length, 1);
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
  it('secrets reach the scripts only as step env, never inside a run: line, and no step can fail the job', () => {
    for (const name of ['Post to Slack', 'File proven findings in Linear', 'File proven findings in Jira']) {
      const step = stepFor(name);
      const runLine = step.split('\n').find((l) => l.trim().startsWith('run:'));
      assert.ok(!runLine.includes('inputs.'), `${name}: run line has no input expression`);
      assert.match(step, /\n      continue-on-error: true\n/, `${name}: continue-on-error`);
    }
  });
});
