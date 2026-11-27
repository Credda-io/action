/*
 * Security mode on a workspace (monorepo) report: the limited and partial
 * rules, the job summary's lead and "What this run reached", findings labelled
 * by package, Slack, Linear and Jira, the de-duplication fingerprint, the Fixes
 * section, and hostile package paths and reasons. The workspace fixtures are
 * security.json files the engine wrote on three public monorepos (see
 * fixtures/security-workspace/PROVENANCE.md). It also holds every
 * single-package fixture to the job summary it rendered before workspace
 * reports existed, byte for byte. The end-to-end cases run run.mjs with a
 * stand-in engine that writes a fixture, so no engine, Docker or network is used.
 *
 * Run with `node --test .github/security-workspace.test.mjs`. Nothing is installed.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { findingPackage, limitedReach, partialReach, reachRecord, reachSection, reachWarning, workspaceReach } from '../findings.mjs';
import { deliverJira, deliverLinear, fingerprint, jiraDescription, linearDescription, readFindings, slackMessage } from '../integrations.mjs';
import { fixesSummary } from '../security-fix.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const FIXTURES = join(ROOT, '.github', 'fixtures');
const workspace = (name) => JSON.parse(readFileSync(join(FIXTURES, 'security-workspace', `${name}.json`), 'utf8'));
const single = (path) => JSON.parse(readFileSync(join(FIXTURES, path), 'utf8'));
const roots = [];
after(() => {
  for (const dir of roots) rmSync(dir, { recursive: true, force: true });
});
const temp = () => {
  const dir = mkdtempSync(join(tmpdir(), 'credda-ws-'));
  roots.push(dir);
  return dir;
};
const writeJson = (report) => {
  const file = join(temp(), 'security.json');
  writeFileSync(file, JSON.stringify(report));
  return file;
};

/** run.mjs in security mode against a stand-in engine that writes `report`. */
function runSecurity(report) {
  const root = temp();
  const engine = join(root, 'engine');
  mkdirSync(join(engine, 'bundle'), { recursive: true });
  writeFileSync(join(engine, 'bundle', 'reef.mjs'), [
    "import { writeFileSync } from 'node:fs';",
    "import { join } from 'node:path';",
    "const out = process.argv[process.argv.indexOf('--out') + 1];",
    `writeFileSync(join(out, 'security.json'), ${JSON.stringify(JSON.stringify(report))});`,
    '',
  ].join('\n'));
  const ws = join(root, 'ws');
  mkdirSync(ws);
  const summary = join(root, 'summary.md');
  const output = join(root, 'output');
  writeFileSync(summary, '');
  writeFileSync(output, '');
  const r = spawnSync(process.execPath, [join(ROOT, 'run.mjs')], {
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH,
      CREDDA_MODE: 'security',
      CREDDA_ACTION_ROOT: ROOT,
      CREDDA_ENGINE_ROOT: engine,
      GITHUB_WORKSPACE: ws,
      RUNNER_TEMP: join(root, 'tmp'),
      GITHUB_OUTPUT: output,
      GITHUB_STEP_SUMMARY: summary,
      GITHUB_REPOSITORY: 'acme/widgets',
      GITHUB_SERVER_URL: 'https://github.com',
      GITHUB_RUN_ID: '1',
    },
  });
  const outputs = Object.fromEntries(readFileSync(output, 'utf8').split('\n').filter((l) => l !== '').map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
  return { ...r, summary: readFileSync(summary, 'utf8'), outputs };
}

/** A workspace report where every scanned package was exercised. */
function allExercised() {
  const r = workspace('zod');
  for (const p of r.packages) if (p.scope === 'full') p.exercised = true;
  r.workspaceScan = { ...r.workspaceScan, exercised: 8, notTested: [] };
  return r;
}

/** A workspace report where no package was exercised and nothing was proven. */
function noneExercised() {
  const r = workspace('zod');
  const zod = r.packages.find((p) => p.path === 'packages/zod');
  zod.exercised = false;
  zod.untested = [{ language: 'javascript', reason: 'it did not install: npm ERR! code E404' }];
  r.workspaceScan = { ...r.workspaceScan, exercised: 0, notTested: ['packages/zod', ...r.workspaceScan.notTested] };
  return r;
}

describe('the limited and partial rules on a workspace report', () => {
  it('the three real workspaces: some packages exercised, so partial and never limited', () => {
    assert.equal(JSON.stringify(reachRecord(workspace('zod'))),
      '{"limited":false,"functions":64,"probes":{"proven":0,"clean":106,"abstained":48,"timedOut":0,"crashed":0,"notRun":0},"sourceFiles":null,"partial":true,' +
      '"packages":{"found":8,"scanned":8,"exercised":1,"notTested":7,"overCap":0}}');
    assert.equal(JSON.stringify(reachRecord(workspace('changesets'))),
      '{"limited":false,"functions":14,"probes":{"proven":0,"clean":50,"abstained":55,"timedOut":0,"crashed":0,"notRun":0},"sourceFiles":null,"partial":true,' +
      '"packages":{"found":24,"scanned":10,"exercised":5,"notTested":5,"overCap":14}}');
    assert.equal(JSON.stringify(reachRecord(workspace('material-ui'))),
      '{"limited":false,"functions":21,"probes":{"proven":2,"clean":505,"abstained":57,"timedOut":0,"crashed":0,"notRun":0},"sourceFiles":null,"partial":true,' +
      '"packages":{"found":30,"scanned":10,"exercised":3,"notTested":7,"overCap":20}}');
  });

  it('installed false on a workspace (one package failed) is not "could not exercise" while another package was exercised', () => {
    const r = workspace('changesets');
    r.installed = false;
    assert.deepEqual(limitedReach(r), { reasons: [], said: '' });
    assert.equal(reachWarning(r), null);
    assert.equal(partialReach(r), true);
  });

  it('no package exercised and nothing proven is limited, and says so about the workspace', () => {
    const r = noneExercised();
    assert.deepEqual(limitedReach(r), { reasons: ['none of the 8 packages in scope was exercised'], said: '' });
    assert.deepEqual(reachWarning(r), {
      lead: "Credda could not exercise this repository's code.",
      why: 'None of the 8 packages in scope was exercised. So this run says nothing about whether the code is safe.',
      said: '',
    });
    assert.equal(reachRecord(r).limited, true);
    assert.equal(reachRecord(r).partial, true);
  });

  it('a proven finding is never limited, even in a package that was not exercised', () => {
    const r = noneExercised();
    r.findings = [{ id: 'packages/mini/REGEX_BLOWUP@src/a.ts:1', class: 'REGEX_BLOWUP', package: 'packages/mini' }];
    assert.equal(reachRecord(r).limited, false);
    assert.equal(reachRecord(r).partial, true);
  });

  it('every package exercised is neither limited nor partial', () => {
    const rec = reachRecord(allExercised());
    assert.deepEqual([rec.limited, rec.partial, rec.packages.notTested], [false, false, 0]);
  });

  it('a count the engine did not write is null, never 0', () => {
    const r = workspace('zod');
    delete r.workspaceScan.overCap;
    delete r.workspaceScan.total;
    assert.deepEqual(reachRecord(r).packages, { found: null, scanned: 8, exercised: 1, notTested: 7, overCap: null });
  });
});

describe('partial on a report of one package', () => {
  it('false on every existing fixture, which lists nothing as not tested', () => {
    for (const f of ['security-reach/flat-clean.json', 'security-reach/flat-vulnerable.json', 'security-reach/ts-loaded.json', 'security-reach/ts-not-loaded.json',
      'security-reach/ts-xss.json', 'security-fix/model/security.json']) {
      const rec = reachRecord(single(f));
      assert.deepEqual([rec.partial, rec.packages], [false, null], f);
    }
  });
  it('true with an `untested` language, `unsupported`, or a v0.1.19 root-only scan of a workspace', () => {
    // The `untested`, `unsupported` and `workspace` shapes are engine v0.1.19's (core apps/cli/src/security.ts at #212).
    const base = single('security-reach/ts-loaded.json');
    assert.equal(partialReach({ ...base, untested: [{ language: 'javascript', reason: 'x' }] }), true);
    assert.equal(partialReach({ ...base, unsupported: { reason: 'there is no package.json', manifests: ['go.mod'] } }), true);
    assert.equal(partialReach({ ...base, workspace: { declaredBy: 'package.json', patterns: ['packages/*'], packages: [{ path: 'packages/a' }], total: 1 } }), true);
    assert.equal(partialReach({ ...base, workspace: { declaredBy: 'package.json', patterns: [], packages: [], total: 0 } }), false);
  });
});

describe('the job summary of a workspace report', () => {
  it('zod: leads with "1 of 8 packages", names the ones it did not exercise, and never warns that the repository could not be exercised', () => {
    const r = runSecurity(workspace('zod'));
    assert.equal(r.status, 0, r.stderr);
    assert.doesNotMatch(r.summary, /could not exercise/);
    const lead = r.summary.split('\n')[2];
    assert.ok(lead.startsWith('**Credda exercised 1 of 8 packages.** It did not exercise `packages/mini` (the package could not be loaded for fuzzing\\: no source module'), lead);
    assert.ok(lead.endsWith('; and 2 more. This run says nothing about the code of those packages.'), lead);
    assert.ok(r.summary.indexOf(lead) < r.summary.indexOf('No exploit succeeded'));
    assert.equal(JSON.parse(r.outputs['security-reach']).partial, true);
  });

  it('material-ui: findings labelled by package, and the reach section per package, capped', () => {
    const r = runSecurity(workspace('material-ui'));
    assert.equal(r.status, 0, r.stderr);
    assert.ok(r.summary.includes('- **REGEX_BLOWUP** (CWE-1333) at `packages-internal/markdown/prepareMarkdown.mjs:264` in package `packages-internal/markdown`'));
    assert.ok(r.summary.includes('- **REGEX_BLOWUP** (CWE-1333) at `packages-internal/core-docs/src/Demo/Demo.tsx:45` in package `packages-internal/core-docs`'));
    assert.ok(r.summary.includes('**Credda exercised 3 of 30 packages.** It did not exercise `packages/mui-material`'));
    assert.ok(r.summary.includes('; and 22 more. This run says nothing about the code of those packages.'));
    const section = reachSection(workspace('material-ui'));
    assert.equal(section[2], '- Packages: 30 found, 10 scanned, 3 exercised, 7 not tested, 20 over the cap of 10.');
    for (const line of [
      'Exercised packages:',
      '- `packages-internal/markdown`: 55 probes (1 proven, 49 clean, 5 abstained); 4 functions fuzzed.',
      '- `packages/mui-material-pigment-css`: 6 probes (1 clean, 5 abstained); 10 functions fuzzed.',
      'Not tested: scanned, but no probe or fuzz call reached the code. This run says nothing about them.',
      "- `packages/mui-lab`: the package could not be loaded for fuzzing\\: Directory import \\'\\/w\\/src\\/CalendarPicker\\' is not supported resolving ES modules imported from \\/w\\/src\\/index\\.ts",
      'Over the cap of 10: only their regular expressions were read. They were not installed, loaded or fuzzed.',
    ]) assert.ok(section.includes(line), line);
    const over = section.find((l) => l.startsWith('- `packages/mui-private-theming`'));
    assert.ok(over.endsWith('`packages/mui-envinfo`, and 10 more.'), over);
    assert.equal(section.filter((l) => l.startsWith('- `')).length, 3 + 7 + 1);
  });

  it('more than ten not tested packages: ten lines, then how many are not shown and where the full list is', () => {
    const r = workspace('material-ui');
    const extra = Array.from({ length: 6 }, (_, i) => `packages/extra-${i}`);
    r.workspaceScan.notTested.push(...extra);
    r.packages.push(...extra.map((path) => ({ path, scope: 'full', exercised: false, untested: [{ language: 'javascript', reason: 'why' }], summary: {} })));
    const section = reachSection(r);
    assert.ok(section.includes("- 3 more not tested packages not shown. security.json lists every package: set `keep-report: 'true'` to keep it."), section.join('\n'));
  });

  it('changesets: the lead lists five and counts the rest, over-the-cap ones included', () => {
    const r = runSecurity(workspace('changesets'));
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.summary, /\*\*Credda exercised 5 of 24 packages\.\*\* It did not exercise `packages\/types` \(.*; and 14 more\. This run says nothing/);
    assert.ok(r.summary.includes('- Packages: 24 found, 10 scanned, 5 exercised, 5 not tested, 14 over the cap of 10.'));
  });

  it('no package exercised: the warning first, then the packages, then "No exploit succeeded"', () => {
    const r = runSecurity(noneExercised());
    assert.equal(r.status, 0, r.stderr);
    const warn = r.summary.indexOf("**Credda could not exercise this repository's code.** None of the 8 packages in scope was exercised.");
    const list = r.summary.indexOf('Credda exercised 0 of 8 packages. It did not exercise `packages/zod` (it did not install\\: npm ERR\\! code E404)');
    assert.ok(warn > 0 && list > warn && r.summary.indexOf('No exploit succeeded') > list, r.summary);
    assert.equal(JSON.parse(r.outputs['security-reach']).limited, true);
  });

  it('every package exercised: the count, no list, and no warning', () => {
    const r = runSecurity(allExercised());
    assert.ok(r.summary.includes('**Credda exercised 8 of 8 packages.**\n'), r.summary);
    assert.doesNotMatch(r.summary, /did not exercise|could not exercise/);
  });

  it('a v0.1.19 scan of a workspace root says only the root was scanned, and names the packages', () => {
    const report = { ...single('security-reach/ts-loaded.json'), workspace: { declaredBy: 'pnpm-workspace.yaml', patterns: ['packages/*'], total: 7, packages: ['a', 'b', 'c', 'd', 'e', 'f', 'g'].map((x) => ({ path: `packages/${x}` })) } };
    const r = runSecurity(report);
    assert.ok(r.summary.includes('**Credda scanned only the root of this workspace.** Its packages were not scanned'), r.summary);
    assert.ok(r.summary.includes('- Not tested: this is a workspace of 7 packages, and only the root was scanned. Not scanned: `packages/a`, `packages/b`, `packages/c`, `packages/d`, `packages/e`, and 2 more.'));
    assert.equal(JSON.parse(r.outputs['security-reach']).partial, true);
  });
});

describe('a report of one package', () => {
  // SHA-256 of the job summary run.mjs wrote for each fixture at df7d377, before
  // workspace reports existed, with this file's runSecurity. A change to any of
  // them is a change to what every client running @v1 sees today.
  const BEFORE = {
    'security-reach/flat-clean.json': 'a8b3c1fc176a098d67be8a1a694f1fc8c28c0e3ad857c9b19de14c74c4a7ddf8',
    'security-reach/flat-vulnerable.json': '021b1ecf5620d8dea0ec4634c2743f32212185d883f2c7c39df092171a220bc5',
    'security-reach/ts-loaded.json': 'b54b739d370d748f4e3518e65c02a15728271294a3a7b2b1d20325fe6a57a453',
    'security-reach/ts-not-loaded.json': 'aedf645545a1e23449656fd13666cd70f4304dd0961068e4ae733c4e04c304b2',
    'security-reach/ts-xss.json': 'ee53d29e40ea886afe73041d0b8291e0e5c9baccd1394a276e09073635b64032',
    'security-fix/broke/security.json': '8b2ff5833e0e976aeb233caa856b107222b4dd2442061d04c2a838f6f6ef994c',
    'security-fix/heuristic/security.json': 'f89544ef936edb0a898219bd7d351993afee29d215cd8330a0556e25f895ef21',
    'security-fix/model/security.json': 'e4e2cb5fe81800da48d1e1f0083acf9fe16f458d2a8962a6254786d04d674191',
  };
  for (const [path, hash] of Object.entries(BEFORE)) {
    it(`${path}: the job summary is byte-identical to before`, () => {
      const r = runSecurity(single(path));
      assert.equal(r.status, 0, r.stderr);
      assert.equal(createHash('sha256').update(r.summary).digest('hex'), hash);
    });
  }

  it('the engine\'s NOT TESTED entries are shown, with the reason, escaped', () => {
    // ts-not-loaded with the `untested` entry engine v0.1.19 writes for that run (its shape: core apps/cli/src/security.ts).
    const report = { ...single('security-reach/ts-not-loaded.json'), untested: [{ language: 'javascript', reason: "the package could not be loaded for fuzzing: Cannot find module '/w'\n::error::x" }] };
    const section = reachSection(report);
    assert.equal(section[2], "- Not tested: the JavaScript package was never loaded, so no probe or fuzz call reached its code. Why: the package could not be loaded for fuzzing\\: Cannot find module \\'\\/w\\'");
    assert.equal(section[3], "- Probes: 23 attempted (6 through the package's exports, 17 at a line of source). 0 proven, 17 clean, 6 abstained, 0 timed out, 0 crashed, 0 not run.");
    const unsupported = reachSection({ findings: [], probes: [], unsupported: { reason: 'there is no package.json', manifests: ['go.mod'] } });
    assert.equal(unsupported[2], '- Not tested: nothing was scanned, because there is no package\\.json.');
  });

  it('a finding of one package has no package label, and its fingerprint is the one it always had', () => {
    const file = writeJson(single('security-reach/flat-vulnerable.json'));
    const { proven, workspace: ws } = readFindings(file);
    assert.equal(ws, null);
    assert.deepEqual(proven.map((f) => f.package), ['', '', '']);
    // Recorded at df7d377 for repository acme/widgets.
    assert.deepEqual(proven.map((f) => fingerprint('acme/widgets', f)), ['creddafp1ea981c65e6c58c39647', 'creddafp09647f6c7a6c426ae1bb', 'creddafpccc2f151c7aa1583556b']);
    assert.ok(!linearDescription(proven[0], null, 'fp').includes('Package:'));
  });
});

describe('findings by package', () => {
  it('the id prefix decides the package: the longest path that prefixes it, `.` for the root, and the field cannot override it', () => {
    const r = workspace('material-ui');
    assert.equal(findingPackage(r.findings[0], r), 'packages-internal/markdown');
    assert.equal(findingPackage({ id: 'packages/mui-envinfo/test/X@a.js:1', package: 'packages/mui-envinfo' }, r), 'packages/mui-envinfo/test');
    assert.equal(findingPackage({ id: 'REGEX_BLOWUP@scripts/a.js:1', package: 'packages/mui-lab' }, r), '.');
    assert.equal(findingPackage({ id: 'packages/mui-lab-extra/X' }, r), '.', 'a path is a prefix only up to a slash');
    assert.equal(findingPackage({ id: 'packages/a/X' }, single('security-reach/flat-clean.json')), '');
  });

  it('two packages with the same finding get two fingerprints, and the root keeps the unprefixed one', () => {
    const r = workspace('material-ui');
    const base = r.findings[0];
    r.findings = [
      { ...base, id: 'packages/mui-lab/REGEX_BLOWUP@src/a.js:1', package: 'packages/mui-lab' },
      { ...base, id: 'packages/mui-utils/REGEX_BLOWUP@src/a.js:1', package: 'packages/mui-utils' },
      { ...base, id: 'REGEX_BLOWUP@src/a.js:1', package: '.' },
    ];
    const { proven } = readFindings(writeJson(r));
    const fps = proven.map((f) => fingerprint('acme/widgets', f));
    assert.equal(new Set(fps).size, 3);
    assert.equal(fps[2], fingerprint('acme/widgets', { language: 'js', id: 'REGEX_BLOWUP@src/a.js:1' }), 'the root finding keys as a scan of the root alone does');
    assert.deepEqual(proven.map((f) => f.package), ['packages/mui-lab', 'packages/mui-utils', '.']);
  });

  it('Linear and Jira titles and descriptions name the package', async () => {
    const { proven } = readFindings(writeJson(workspace('material-ui')));
    const titles = [];
    const fetch = async (url, init) => {
      const body = JSON.parse(init.body);
      const title = body.variables?.input?.title ?? body.fields?.summary;
      if (title) titles.push(title);
      const search = String(body.query ?? '').startsWith('query') || new URL(url).pathname === '/rest/api/3/search/jql';
      return new Response(JSON.stringify(search ? { data: { issues: { nodes: [] } }, issues: [] } : { data: { issueCreate: { success: true } } }), { status: 200 });
    };
    await deliverLinear({ apiKey: 'k', teamId: 't', repository: 'acme/widgets', findings: proven, runUrl: null, max: 10, fetch });
    await deliverJira({ baseUrl: 'https://acme.atlassian.net', email: 'e@acme.test', apiToken: 'tok1', projectKey: 'P', issueType: 'Bug', repository: 'acme/widgets', findings: proven, runUrl: null, max: 10, fetch });
    const want = [
      'Credda: REGEX_BLOWUP at packages-internal/markdown/prepareMarkdown.mjs:264 in package packages-internal/markdown',
      'Credda: REGEX_BLOWUP at packages-internal/core-docs/src/Demo/Demo.tsx:45 in package packages-internal/core-docs',
    ];
    assert.deepEqual(titles, [...want, ...want]);
    assert.ok(linearDescription(proven[0], null, 'fp').includes('\nPackage: packages\\-internal\\/markdown\n'));
    assert.ok(JSON.stringify(jiraDescription(proven[0], null, 'fp')).includes('"text":"Package: packages-internal/markdown"'));
  });
});

describe('Slack on a workspace report', () => {
  const message = (report) => {
    const loaded = readFindings(writeJson(report));
    return slackMessage({ repository: 'acme/widgets', mode: 'security', outcome: '', runUrl: null, findings: loaded.proven, unprovenCount: 0, statedFindings: 0, ...loaded });
  };
  it('a partly exercised workspace with nothing proven never posts as "No exploit succeeded"', () => {
    const m = message(workspace('zod'));
    assert.equal(m.blocks[0].text.text, 'Credda exercised 1 of 8 packages in acme/widgets');
    assert.equal(m.blocks[1].fields[1].text, '*Outcome*\nnothing proven in the packages exercised');
    assert.ok(m.blocks[2].text.text.startsWith('Credda exercised 1 of 8 packages. It did not exercise packages/mini (the package could not be loaded'), m.blocks[2].text.text);
    assert.ok(m.blocks[2].text.text.endsWith('; and 2 more.'));
  });
  it('findings are labelled by package, and the exercised line is there too', () => {
    const m = message(workspace('material-ui'));
    const texts = m.blocks.map((b) => b.text?.text ?? '');
    assert.ok(texts.some((t) => t.startsWith('Credda exercised 3 of 30 packages.')));
    assert.ok(texts.some((t) => t.startsWith('*REGEX_BLOWUP* (CWE-1333) at packages-internal/markdown/prepareMarkdown.mjs:264 in package packages-internal/markdown\n')), JSON.stringify(texts));
  });
  it('no package exercised posts the warning', () => {
    assert.equal(message(noneExercised()).blocks[0].text.text, 'Credda could not exercise the code in acme/widgets');
  });
});

describe('Fixes on a workspace report', () => {
  // The shape the engine writes for --fix on a workspace (core apps/cli/src/security.ts, workspaceFixesNotAttempted).
  const r = workspace('material-ui');
  const fixes = {
    provider: 'anthropic',
    modelBacked: true,
    counts: { proven: 0, rejected: 0, notAttempted: 2 },
    attempts: r.findings.map((f) => ({
      class: f.class, language: f.language, findings: [f.id], status: 'NOT_ATTEMPTED',
      reason: `No fix was attempted: --fix runs on one package, and this is a workspace report. Run credda security --fix /home/runner/work/_temp/material-ui/${f.package}. A package whose dependencies are workspace siblings may not install there on its own; its report then says NOT TESTED.`,
    })),
  };
  const args = { fixes, usable: [], broken: [], delivery: new Map(), openPullRequest: false, patchDir: '', baseRefusal: '' };
  it('says it once, not once per package and class', () => {
    assert.equal(fixesSummary({ ...args, workspace: true }), [
      '### Fixes',
      '',
      'No fix was attempted for the 2 proven findings above. This is a workspace (monorepo) report, and Credda attempts fixes on one package at a time. ' +
        'To have one attempted, scan that package on its own: see *Monorepos* in the Credda action README. The findings above are unchanged.',
      '',
    ].join('\n'));
  });
  it('nothing proven on a workspace: nothing to fix', () => {
    assert.match(fixesSummary({ ...args, fixes: { ...fixes, attempts: [] }, workspace: true }), /No finding was proven, so there was nothing to fix\./);
  });
  it('a report of one package lists each attempt as before', () => {
    const out = fixesSummary(args);
    assert.equal(out.split('\n').filter((l) => l.startsWith('- **NOT_ATTEMPTED** REGEX_BLOWUP')).length, 2);
  });
});

describe('hostile package paths, names and reasons', () => {
  const EVIL = 'https://evil.test';
  // Every character a regular expression reads specially is escaped, so a URL or path is matched only as itself.
  const literal = (text) => new RegExp(text.replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&'));
  const path = `packages/\`<img src=${EVIL}/p.png>\`\n::error::pwned`;
  const reason = `[click](${EVIL}) <!channel> <b>x</b> @everyone\n::error::pwned`;
  const hostile = () => {
    const r = workspace('changesets');
    r.workspaceScan.notTested = [path, ...r.workspaceScan.notTested.slice(1)];
    r.workspaceScan.overCap = [`docs](${EVIL})`, ...r.workspaceScan.overCap.slice(1)];
    r.packages[0] = { ...r.packages[0], path, name: `<script>${EVIL}</script>`, untested: [{ language: 'javascript', reason }] };
    r.findings = [{ id: `${path}/PROTOTYPE_POLLUTION`, class: 'PROTOTYPE_POLLUTION', cwe: 'CWE-1321', language: 'javascript', site: { kind: 'package', file: `${path}/package.json` }, sentence: 's', package: path }];
    return r;
  };

  it('the job summary: each path is one code span, each reason escaped, and nothing starts a second line', () => {
    const r = runSecurity(hostile());
    assert.equal(r.status, 0, r.stderr);
    assert.doesNotMatch(r.summary, /^::/m);
    assert.ok(!r.summary.toLowerCase().includes('<script'), 'the package name is never shown');
    // The path is cut at its first line, and it ends in a backtick, so the span is padded.
    const span = `\`\` packages/\`<img src=${EVIL}/p.png>\` \`\``;
    assert.match(r.summary, literal(`${span} (\\[click\\]\\(https\\:\\/\\/evil\\.test\\) \\<\\!channel\\> \\<b\\>x\\<\\/b\\> \\@everyone)`));
    assert.match(r.summary, literal(`in package ${span}`));
    assert.match(r.summary, literal(`\`docs](${EVIL})\``));
    // Outside code spans, nothing unescaped is left to form a tag, a link or an image.
    const siteSpan = `\`\`packages/\`<img src=${EVIL}/p.png>\` ::error::pwned/package.json\`\``;
    assert.match(r.summary, literal(siteSpan));
    const outside = [span, siteSpan, `\`docs](${EVIL})\``].reduce((t, cut) => t.split(cut).join(''), r.summary).replace(/`[^`\n]*`/g, '').replace(/^\[Action run\]\(.*\)$/m, '').replace(/^\s*<\/?details>|<summary>[^<]*<\/summary>/gm, '');
    assert.ok(!/(^|[^\\])[<[]/m.test(outside.replace(/^- /gm, '')), outside);
    // A finding's site has always been one code span with its line endings made spaces; every other path and reason is cut at its first line.
    assert.doesNotMatch(outside, /pwned/);
    assert.equal(r.summary.split('pwned').length - 1, 1, 'only inside the site code span');
  });

  it('Slack escapes the paths and reasons', () => {
    const loaded = readFindings(writeJson(hostile()));
    const m = slackMessage({ repository: 'a/b', mode: 'security', outcome: '', runUrl: null, findings: loaded.proven, unprovenCount: 0, statedFindings: 0, ...loaded });
    const text = JSON.stringify(m.blocks);
    assert.doesNotMatch(text, /<!channel>|<b>|<img|pwned/);
    assert.match(text, /&lt;!channel&gt;/);
    assert.match(text, /@​everyone/);
  });

  it('Linear escapes the package line', () => {
    const { proven } = readFindings(writeJson(hostile()));
    const md = linearDescription(proven[0], null, 'fp');
    const line = md.split('\n').find((l) => l.startsWith('Package: '));
    assert.equal(line, 'Package: packages\\/\\`\\<img src\\=https\\:\\/\\/evil\\.test\\/p\\.png\\>\\`');
  });

  it('workspaceReach keeps the engine words raw for each format to escape', () => {
    const w = workspaceReach(hostile());
    assert.equal(w.missed[0].reason, `[click](${EVIL}) <!channel> <b>x</b> @everyone`);
  });
});
