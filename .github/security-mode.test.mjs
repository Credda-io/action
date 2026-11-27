/*
 * Security mode in run.mjs. `extra-probes`: the names it takes, the engine
 * flags it sets for the `credda security` run, and the summary line per class.
 * And what the job summary and the log do with hostile text in security.json:
 * a file name, a sentence or an exploit program from the scanned repository,
 * or an engine field shaped like a workflow command. The end-to-end cases
 * run run.mjs with a stand-in engine (a script in a temp directory that records
 * its environment and writes a security.json), so no engine, Docker or network
 * is used. The class names, env vars and the `probes[].class` field are the
 * engine's own (core apps/cli/src/security.ts and
 * packages/repository/src/security-probes.ts).
 *
 * Run with `node --test .github/security-mode.test.mjs`. Nothing is installed.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { extraProbeEnv, extraProbesLines, parseExtraProbes } from '../findings.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const roots = [];
after(() => {
  for (const dir of roots) rmSync(dir, { recursive: true, force: true });
});

describe('parseExtraProbes', () => {
  it('reads a comma-separated list, trimmed, once each', () => {
    assert.deepEqual(parseExtraProbes(''), { names: [], error: null });
    assert.deepEqual(parseExtraProbes(' injection , ssrf,,xss,ssrf '), { names: ['injection', 'ssrf', 'xss'], error: null });
  });
  it('an unknown name is an error that names it and the three it takes', () => {
    for (const bad of ['sqli', 'XSS', 'injection,rce', '__proto__', 'toString']) {
      const r = parseExtraProbes(bad);
      assert.deepEqual(r.names, []);
      assert.match(r.error, /is not a probe class this action knows\. Use a comma-separated list of injection, ssrf, xss, or leave it empty\./, bad);
    }
  });
  it('a name with a newline stays on one line, so it cannot write a workflow command', () => {
    const r = parseExtraProbes('x\n::add-mask::y');
    assert.equal(r.error.split('\n').length, 1);
  });
});

describe('extraProbeEnv', () => {
  it('sets 1 for each named class and unsets the rest', () => {
    assert.deepEqual(extraProbeEnv(['ssrf']), { CREDDA_INJECTION_PROBE: undefined, CREDDA_SSRF_PROBE: '1', CREDDA_XSS_PROBE: undefined });
  });
});

describe('extraProbesLines', () => {
  const probes = [{ id: 'SSRF', class: 'SSRF' }, { id: 'SSRF@a.js:1', class: 'SSRF' }, { id: 'PROTOTYPE_POLLUTION', class: 'PROTOTYPE_POLLUTION' }];
  it('counts the probes of a class that ran', () => {
    assert.deepEqual(extraProbesLines(['ssrf'], { engineVersion: '0.1.18', probes }), ['- `ssrf` (SSRF): 2 probes ran. Only a finding an exploit proved is listed above.']);
  });
  it('an engine older than the class says not available in this engine, never clean', () => {
    const [line] = extraProbesLines(['xss'], { engineVersion: '0.1.18', probes });
    assert.equal(line, '- `xss` (REFLECTED_XSS): not available in this engine (Credda 0.1.18). It needs v0.1.19 or later. Nothing was probed for it.');
    assert.match(extraProbesLines(['injection'], { engineVersion: '0.1.17', probes })[0], /not available in this engine \(Credda 0\.1\.17\)\. It needs v0\.1\.18 or later/);
  });
  it('an engine that has the class but probed nothing says no probe applied', () => {
    assert.match(extraProbesLines(['xss'], { engineVersion: '0.1.19', probes })[0], /no probe of this class applied to this repository, so none ran\./);
  });
  it('an engine version it cannot read says both possibilities', () => {
    assert.match(extraProbesLines(['xss'], { engineVersion: 'dev', probes })[0], /This engine may not have it \(it needs v0\.1\.19 or later\), or nothing in this repository matched it\./);
  });
});

/** run.mjs in security mode against a stand-in engine. */
function runSecurity({ extra = '', engineVersion = '0.1.18', probes = [], inherited = {}, report = {}, fix = false }) {
  const root = mkdtempSync(join(tmpdir(), 'credda-extra-'));
  roots.push(root);
  const engine = join(root, 'engine');
  mkdirSync(join(engine, 'bundle'), { recursive: true });
  const seen = join(root, 'seen.json');
  writeFileSync(join(engine, 'bundle', 'reef.mjs'), [
    "import { writeFileSync } from 'node:fs';",
    "import { join } from 'node:path';",
    'const args = process.argv.slice(2);',
    `writeFileSync(${JSON.stringify(seen)}, JSON.stringify({ args, env: Object.fromEntries(Object.entries(process.env).filter(([k]) => /_PROBE$/.test(k))) }));`,
    "const out = args[args.indexOf('--out') + 1];",
    `writeFileSync(join(out, 'security.json'), JSON.stringify(${JSON.stringify({ schemaVersion: 1, engineVersion, probes, findings: [], ...report })}));`,
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
      ...inherited,
      CREDDA_MODE: 'security',
      CREDDA_EXTRA_PROBES: extra,
      CREDDA_FIX: fix ? 'true' : 'false',
      CREDDA_ACTION_ROOT: ROOT,
      CREDDA_ENGINE_ROOT: engine,
      GITHUB_WORKSPACE: ws,
      RUNNER_TEMP: join(root, 'tmp'),
      GITHUB_OUTPUT: output,
      GITHUB_STEP_SUMMARY: summary,
      GITHUB_REPOSITORY: 'acme/widgets',
    },
  });
  let engineSaw = null;
  try {
    engineSaw = JSON.parse(readFileSync(seen, 'utf8'));
  } catch {
    engineSaw = null;
  }
  return { ...r, summary: readFileSync(summary, 'utf8'), engineSaw };
}

describe('run.mjs with extra-probes', () => {
  it('maps the names to the engine flags for the security run, and unsets one the job environment set', () => {
    const r = runSecurity({ extra: 'injection,ssrf', probes: [{ id: 'SSRF', class: 'SSRF' }], inherited: { CREDDA_XSS_PROBE: '1' } });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.engineSaw.args[0], 'security');
    assert.deepEqual(r.engineSaw.env, { CREDDA_INJECTION_PROBE: '1', CREDDA_SSRF_PROBE: '1' });
    assert.match(r.summary, /### Extra probe classes/);
    assert.match(r.summary, /- `ssrf` \(SSRF\): 1 probe ran\./);
    assert.match(r.summary, /- `injection` \(INJECTION_TO_EXECUTION\): no probe of this class applied to this repository/);
  });

  it('says xss is not available in an engine older than v0.1.19', () => {
    const r = runSecurity({ extra: 'xss', engineVersion: '0.1.18' });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(r.engineSaw.env, { CREDDA_XSS_PROBE: '1' });
    assert.match(r.summary, /- `xss` \(REFLECTED_XSS\): not available in this engine \(Credda 0\.1\.18\)\. It needs v0\.1\.19 or later\./);
  });

  it('empty sets no flag and writes no section', () => {
    const r = runSecurity({ extra: '' });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(r.engineSaw.env, {});
    assert.doesNotMatch(r.summary, /Extra probe classes/);
  });

  it('an unknown name fails the job before the engine runs', () => {
    const r = runSecurity({ extra: 'injection, sqli' });
    assert.equal(r.status, 1);
    assert.equal(r.engineSaw, null, 'the engine never started');
    assert.match(r.stdout, /^::error::extra-probes names "sqli", which is not a probe class this action knows\./m);
    assert.match(r.summary, /Credda did not finish/);
  });
});

describe('run.mjs with hostile text in security.json', () => {
  const EVIL = 'https://evil.test';
  const hostile = {
    id: 'PROTOTYPE_POLLUTION@x',
    language: 'javascript',
    class: 'PROTOTYPE_POLLUTION',
    cwe: 'CWE-1321',
    site: { kind: 'source', file: `a\`<img src=${EVIL}/p.png>\`](${EVIL}).js`, line: 3 },
    sentence: `<img src=${EVIL}/x.png> [click](${EVIL}) ${EVIL}/autolink`,
    program: `console.log(1);\r# Injected heading\r<img src=${EVIL}/y.png>\rconsole.log(2);`,
  };

  it('a file name, a sentence and an exploit program cannot form markup in the job summary', () => {
    const r = runSecurity({ report: { findings: [hostile], probes: [{ id: 'PROTOTYPE_POLLUTION@x', class: 'PROTOTYPE_POLLUTION' }] } });
    assert.equal(r.status, 0, r.stderr);
    const lines = r.summary.split(/\r\n|\r|\n/);
    const item = lines.find((l) => l.startsWith('- **PROTOTYPE_POLLUTION**'));
    // The path is one code span whose fence is longer than any backtick run in it.
    assert.ok(item.endsWith(`at \`\`a\`<img src=${EVIL}/p.png>\`](${EVIL}).js:3\`\``), item);
    const sentence = lines[lines.indexOf(item) + 1];
    assert.ok(!/(^|[^\\])[<[]/.test(sentence), sentence);
    assert.ok(!sentence.includes('https://'), 'no bare URL left to autolink');
    // Every line of the program stays inside the list item.
    const open = lines.findIndex((l) => /^  ```+js$/.test(l));
    const close = lines.findIndex((l, i) => i > open && /^  ```+$/.test(l));
    assert.ok(open > 0 && close > open);
    for (const l of lines.slice(open, close + 1)) assert.ok(l.startsWith('  '), JSON.stringify(l));
    assert.ok(lines.slice(open, close).includes('  # Injected heading'));
  });

  it('a class shaped like a workflow command never reaches the log as one', () => {
    const report = {
      fixes: {
        provider: 'openai-compatible',
        modelBacked: true,
        counts: { proven: 1, rejected: 0, notAttempted: 0 },
        attempts: [{ class: 'PP\n::warning::pwned', language: 'javascript', findings: [], status: 'FIX_PROVEN', verdict: 'FIX_PROVEN', gates: [] }],
      },
    };
    const r = runSecurity({ report, fix: true });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /^::error::The engine said FIX_PROVEN for an unnamed class but it records no passing exploit gate\./m);
    assert.doesNotMatch(r.stdout, /^::warning::pwned/m);
  });

  it('an engine version with markup in it is not printed', () => {
    const r = runSecurity({ extra: 'xss', engineVersion: `0.1.19<img src=${EVIL}/v.png>` });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.summary, /This engine may not have it/);
    assert.doesNotMatch(r.summary, /<img/);
  });
});
