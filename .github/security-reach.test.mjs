/*
 * What a security run reached: the job summary's "What this run reached"
 * section, the limited-reach rule, the `security-reach` output, `keep-report`
 * and the Slack line. The fixtures are security.json files the engine wrote
 * (see fixtures/security-reach/PROVENANCE.md). The end-to-end cases run run.mjs
 * with a stand-in engine that writes a fixture, so no engine, Docker or network
 * is used.
 *
 * Run with `node --test .github/security-reach.test.mjs`. Nothing is installed.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { limitedReach, reachRecord, reachSection, reachSummaryText, reachWarning } from '../findings.mjs';
import { readFindings, slackMessage } from '../integrations.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const FIXTURES = join(ROOT, '.github', 'fixtures', 'security-reach');
const fixture = (name) => JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), 'utf8'));
const roots = [];
after(() => {
  for (const dir of roots) rmSync(dir, { recursive: true, force: true });
});

describe('the limited-reach rule on real engine output', () => {
  it('the TypeScript repository the engine could not load warns, and says why', () => {
    const r = fixture('ts-not-loaded');
    assert.deepEqual(limitedReach(r), {
      reasons: ['no exported function could be fuzzed', "none of the 6 probes that call the package's exports found code they could drive"],
      said: "the package could not be loaded for fuzzing: Cannot find module '/w'",
    });
    assert.equal(reachRecord(r).limited, true);
  });
  it('the same repository loaded from source, 36 functions fuzzed, does not warn', () => {
    assert.equal(reachWarning(fixture('ts-loaded')), null);
    assert.equal(reachWarning(fixture('ts-xss')), null);
  });
  it('flat with 2 functions fuzzed and one probe clean does not warn; flat with findings does not either', () => {
    assert.equal(reachWarning(fixture('flat-clean')), null);
    assert.equal(reachWarning(fixture('flat-vulnerable')), null);
  });
  it('a package that did not install, a source load that imported nothing, or a run that ran nothing, warns', () => {
    assert.match(limitedReach({ installed: false, findings: [], probes: [{ id: 'X', verdict: 'CLEAN', site: { kind: 'source' } }] }).reasons[0], /did not install/);
    const r = fixture('ts-loaded');
    r.fuzz.reach.imported = [];
    assert.ok(limitedReach(r).reasons.includes('no source module could be imported'));
    assert.deepEqual(limitedReach({ findings: [], probes: [] }).reasons, ['no probe ran and no function was fuzzed']);
  });
  it('a probe that timed out or crashed is not clean, so it does not count as reach', () => {
    const probes = [{ id: 'A', verdict: 'TIMED_OUT', site: { kind: 'package' } }, { id: 'B', verdict: 'CRASHED', site: { kind: 'package' } }];
    assert.equal(limitedReach({ findings: [], probes, fuzz: { functions: 3 } }).reasons.length, 1);
  });
});

describe('What this run reached', () => {
  it('the could-not-load run', () => {
    assert.deepEqual(reachSection(fixture('ts-not-loaded')), [
      '### What this run reached',
      '',
      "- Probes: 23 attempted (6 through the package's exports, 17 at a line of source). 0 proven, 17 clean, 6 abstained, 0 timed out, 0 crashed, 0 not run.",
      '- Fuzzing: 0 exported functions, 0 calls. 0 oracle hits, 0 proven, 0 dropped.',
      "- Engine note on fuzzing: the package could not be loaded for fuzzing\\: Cannot find module \\'\\/w\\'",
      '',
      'What each result means:',
      '',
      '- Clean: the probe ran against code it could drive and no exploit succeeded.',
      '- Abstained: the probe had nothing it could drive or measure, so it says nothing about that class.',
      '',
    ]);
  });
  it('the source-loaded run has the load line', () => {
    assert.ok(reachSection(fixture('ts-loaded')).includes(
      '- Loaded from source: no build output, so Node v22.23.5 type stripping loaded the entry `src/index.ts`. 12 source files loaded, 0 modules failed.',
    ));
  });
  it('an engine without fuzz.reach (v0.1.17) gets no load line, and no field reads undefined or 0 of 0', () => {
    const lines = reachSection(fixture('flat-clean')).join('\n');
    assert.doesNotMatch(lines, /Loaded from source|undefined|NaN|null|0 of 0/);
    assert.match(lines, /- Fuzzing: 2 exported functions, 638010 calls\./);
  });
  it('a record with no fuzz stage and no probes list says only that', () => {
    assert.deepEqual(reachSection({ findings: [] }).slice(2, 3), ['- security.json records nothing about what this run reached.']);
    const r = reachRecord({ findings: [] });
    assert.deepEqual({ functions: r.functions, probes: r.probes, sourceFiles: r.sourceFiles }, { functions: null, probes: null, sourceFiles: null });
  });
  it('modules sources, the cap, and more than five failures', () => {
    const failed = Array.from({ length: 7 }, (_, i) => ({ module: `src/m${i}.ts`, error: 'SyntaxError' }));
    const line = reachSection({ findings: [], fuzz: { functions: 1, reach: { from: 'modules', imported: ['a', 'b'], failed, overCap: 4, cap: 32, filesLoaded: 9, node: 'v22.1.0' } } })
      .find((l) => l.startsWith('- Loaded'));
    assert.equal(line, '- Loaded from source: no build output, so Node v22.1.0 type stripping loaded the modules under src/. 2 imported, 9 source files loaded, cap 32, ' +
      '4 over the cap not imported, 7 modules failed: `src/m0.ts` (SyntaxError); `src/m1.ts` (SyntaxError); `src/m2.ts` (SyntaxError); `src/m3.ts` (SyntaxError); `src/m4.ts` (SyntaxError); and 2 more.');
  });
});

describe('security-reach and the Slack line', () => {
  it('numbers and one boolean, on one line', () => {
    const value = JSON.stringify(reachRecord(fixture('ts-loaded')));
    assert.equal(value, '{"limited":false,"functions":36,"probes":{"proven":0,"clean":18,"abstained":5,"timedOut":0,"crashed":0,"notRun":0},"sourceFiles":{"loaded":12,"failed":0}}');
  });
  it('the Slack line counts what ran', () => {
    assert.equal(reachSummaryText(fixture('flat-clean')), 'Reached: 6 probes (1 clean, 5 abstained); 2 exported functions fuzzed, 638010 calls.');
  });
  it('a limited run never posts as "No exploit succeeded", and the warning comes first', () => {
    const file = join(mkdtempSync(join(tmpdir(), 'credda-reach-')), 'security.json');
    roots.push(join(file, '..'));
    writeFileSync(file, JSON.stringify(fixture('ts-not-loaded')));
    const loaded = readFindings(file);
    const m = slackMessage({ repository: 'acme/widgets', mode: 'security', outcome: '', runUrl: null, findings: [], unprovenCount: 0, statedFindings: 0, ...loaded });
    assert.equal(m.blocks[0].text.text, 'Credda could not exercise the code in acme/widgets');
    const texts = m.blocks.map((b) => b.text?.text ?? b.elements?.[0]?.text ?? '');
    const warn = texts.findIndex((t) => t.startsWith("Credda could not exercise this repository's code. No exported function"));
    const nothing = texts.findIndex((t) => t.includes('No exploit succeeded'));
    assert.ok(warn > 0 && nothing > warn, JSON.stringify(texts));
    assert.ok(texts[warn].endsWith("The engine said: the package could not be loaded for fuzzing: Cannot find module '/w'"));
    assert.ok(texts.includes('Reached: 23 probes (17 clean, 6 abstained); 0 exported functions fuzzed, 0 calls.'));
  });
});

describe('hostile text in the reach record', () => {
  const EVIL = 'https://evil.test';
  const hostile = {
    findings: [],
    probes: [{ id: 'PATH_TRAVERSAL', verdict: 'ABSTAINED', site: { kind: 'package' }, said: `<!channel> <${EVIL}|click> [x](${EVIL})` }],
    note: `top\n::warning::pwned`,
    leftBehind: [`/tmp/a\`<img src=${EVIL}/l.png>\``],
    fuzz: {
      functions: 0,
      calls: 0,
      note: `![i](${EVIL}/n.png) <b>bold</b>\r# heading`,
      reach: {
        from: 'entry',
        imported: [],
        failed: [{ module: `src/\`<img src=${EVIL}/m.png>\`.ts`, error: `<script>x</script> [y](${EVIL})\n::error::pwned` }],
        overCap: 0,
        cap: 32,
        filesLoaded: 1,
        node: `v22<img src=${EVIL}/v.png>`,
      },
    },
  };

  it('a module name, an error, a note and a temp directory cannot form markup or a second line', () => {
    const [heading, ...lines] = reachSection(hostile);
    assert.equal(heading, '### What this run reached');
    for (const l of lines) {
      assert.ok(!/[\r\n]/.test(l), JSON.stringify(l));
      assert.ok(!l.startsWith('#') && !l.startsWith('::'), l);
    }
    const text = lines.join('\n');
    // Each name sits in one code span whose fence is longer than any backtick run in it.
    const moduleSpan = `\`\`src/\`<img src=${EVIL}/m.png>\`.ts\`\``;
    const dirSpan = `\`\` /tmp/a\`<img src=${EVIL}/l.png>\` \`\``;
    assert.ok(text.includes(`${moduleSpan} (\\<script\\>x\\<\\/script\\> \\[y\\]\\(https\\:\\/\\/evil\\.test\\))`), text);
    assert.ok(text.includes(dirSpan), text);
    // Outside those spans, nothing unescaped is left to form a tag, a link or an image.
    const outside = text.replace(moduleSpan, '').replace(dirSpan, '');
    assert.ok(!/(^|[^\\])[<[!]/m.test(outside.replace(/^- /gm, '')), outside);
    assert.doesNotMatch(outside, /pwned|heading/, 'only the first line of any engine text');
    assert.match(text, /Node type stripping loaded its entry\./, 'an engine Node version with markup is not printed');
  });

  it('the warning on the job summary escapes the engine words', () => {
    const w = reachWarning(hostile);
    assert.equal(w.said, `![i](${EVIL}/n.png) <b>bold</b>`, 'first line only');
  });

  it('Slack escapes the engine words in the warning', () => {
    const m = slackMessage({ repository: 'a/b', mode: 'security', outcome: '', runUrl: null, findings: [], unprovenCount: 0, statedFindings: 0, warning: reachWarning(hostile), reach: reachSummaryText(hostile) });
    const text = JSON.stringify(m.blocks);
    assert.doesNotMatch(text, /<b>|<!channel>/);
    assert.match(text, /&lt;b&gt;bold&lt;\/b&gt;/);
  });
});

/** run.mjs in security mode against a stand-in engine that writes `report` and the two other report files. */
function runSecurity(report, keep) {
  const root = mkdtempSync(join(tmpdir(), 'credda-reach-'));
  roots.push(root);
  const engine = join(root, 'engine');
  mkdirSync(join(engine, 'bundle'), { recursive: true });
  writeFileSync(join(engine, 'bundle', 'reef.mjs'), [
    "import { writeFileSync } from 'node:fs';",
    "import { join } from 'node:path';",
    "const out = process.argv[process.argv.indexOf('--out') + 1];",
    `writeFileSync(join(out, 'security.json'), ${JSON.stringify(JSON.stringify(report))});`,
    "writeFileSync(join(out, 'security.md'), '# Credda security report\\n');",
    "writeFileSync(join(out, 'security.sarif'), '{}');",
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
      CREDDA_KEEP_REPORT: keep ? 'true' : 'false',
      CREDDA_ACTION_ROOT: ROOT,
      CREDDA_ENGINE_ROOT: engine,
      GITHUB_WORKSPACE: ws,
      RUNNER_TEMP: join(root, 'tmp'),
      GITHUB_OUTPUT: output,
      GITHUB_STEP_SUMMARY: summary,
      GITHUB_REPOSITORY: 'acme/widgets',
    },
  });
  const outputs = Object.fromEntries(readFileSync(output, 'utf8').split('\n').filter((l) => l !== '').map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
  return { ...r, summary: readFileSync(summary, 'utf8'), outputs };
}

describe('run.mjs', () => {
  it('a run that could not load the package leads with the warning, before "No exploit succeeded"', () => {
    const r = runSecurity(fixture('ts-not-loaded'), false);
    assert.equal(r.status, 0, r.stderr);
    const warn = r.summary.indexOf("**Credda could not exercise this repository's code.** No exported function could be fuzzed");
    assert.ok(warn > 0 && warn < r.summary.indexOf('Ran 23 exploit probes'), r.summary);
    assert.ok(r.summary.indexOf('No exploit succeeded') > warn);
    assert.ok(r.summary.includes("The engine said: the package could not be loaded for fuzzing\\: Cannot find module \\'\\/w\\'"));
    assert.ok(r.summary.indexOf('### What this run reached') > r.summary.indexOf('No exploit succeeded'));
    assert.equal(JSON.parse(r.outputs['security-reach']).limited, true);
    assert.equal(r.outputs['security-report-path'], '');
  });

  it('a run that reached the code has no warning', () => {
    const r = runSecurity(fixture('ts-loaded'), false);
    assert.equal(r.status, 0, r.stderr);
    assert.doesNotMatch(r.summary, /could not exercise/);
    assert.match(r.summary, /### What this run reached\n\n- Probes: 23 attempted/);
  });

  it('keep-report copies the engine files to the directory it names', () => {
    const r = runSecurity(fixture('flat-clean'), true);
    assert.equal(r.status, 0, r.stderr);
    const dir = r.outputs['security-report-path'];
    assert.ok(dir !== '' && existsSync(dir));
    assert.deepEqual(readdirSync(dir).sort(), ['security.json', 'security.md', 'security.sarif']);
    assert.deepEqual(JSON.parse(readFileSync(join(dir, 'security.json'), 'utf8')), fixture('flat-clean'));
  });
});
