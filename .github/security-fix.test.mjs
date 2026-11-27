/*
 * Security mode's `fix` input: what reaches the summary, what reaches a pull
 * request, and what is refused before git runs.
 *
 * The security.json files under fixtures/security-fix/ were written by the
 * engine (`credda security --fix`, v0.1.18 dev build) through this Action's own
 * run step; PROVENANCE.md there says how. Delivery runs against a real git
 * repository: a bare repository stands in for `origin`, a clone for the
 * `actions/checkout` workspace, and `gh` is a shell script on PATH that records
 * its argv. Nothing here uses the network.
 *
 * What is NOT established here: that GitHub accepts the push or the
 * `gh pr create` call, or that a real model writes a patch the gates prove.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { branchNameForSecurityFix, patchRefusal, pullRequestTitleForSecurityFix } from '../delivery.mjs';
import { deliverSecurityFixes, fixesSummary, provenFixes, securityFixBody } from '../security-fix.mjs';

const FIXTURES = fileURLToPath(new URL('./fixtures/security-fix/', import.meta.url));
const SOURCE = fileURLToPath(new URL('../security-fix.mjs', import.meta.url));
const roots = [];
after(() => {
  for (const dir of roots) rmSync(dir, { recursive: true, force: true });
});
function temp() {
  const dir = mkdtempSync(join(tmpdir(), 'credda-secfix-'));
  roots.push(dir);
  return dir;
}

/** A fixture's security.json, with its patch files moved into a fresh output directory. */
function fixture(name) {
  const out = temp();
  const result = JSON.parse(readFileSync(join(FIXTURES, name, 'security.json'), 'utf8'));
  for (const a of result.fixes?.attempts ?? []) {
    if (typeof a.patchFile === 'string') {
      const base = a.patchFile.split('/').pop();
      cpSync(join(FIXTURES, name, base), join(out, base));
      a.patchFile = join(out, base);
    }
  }
  return { result, out };
}

const runUrl = () => 'https://github.com/example/flat/actions/runs/1';

function git(cwd, ...args) {
  const r = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.test', ...args], { cwd, encoding: 'utf8' });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

/** origin.git, a clone of it holding the pre-image, and a gh stub on PATH. */
function scenario({ openPr = '' } = {}) {
  const root = temp();
  const origin = join(root, 'origin.git');
  const seed = join(root, 'seed');
  const ws = join(root, 'ws');
  git(root, 'init', '-q', '--bare', '-b', 'main', origin);
  mkdirSync(seed);
  cpSync(join(FIXTURES, 'pre-image'), seed, { recursive: true });
  git(seed, 'init', '-q', '-b', 'main');
  git(seed, 'add', '-A');
  git(seed, 'commit', '-q', '-m', 'seed');
  git(seed, 'push', '-q', origin, 'main');
  git(root, 'clone', '-q', origin, ws);
  const bin = join(root, 'bin');
  mkdirSync(bin);
  const log = join(root, 'gh.log');
  writeFileSync(join(root, 'open-pr'), openPr);
  writeFileSync(
    join(bin, 'gh'),
    [
      '#!/bin/sh',
      `printf '%s\\n' "$*" >> '${log}'`,
      'case "$1 $2" in',
      `  "pr list") cat '${join(root, 'open-pr')}'; exit 0 ;;`,
      '  "repo view") echo main; exit 0 ;;',
      '  "pr create") echo https://github.example/example/flat/pull/7; exit 0 ;;',
      'esac',
      'exit 1',
      '',
    ].join('\n'),
  );
  chmodSync(join(bin, 'gh'), 0o755);
  return { root, origin, ws, log, bin, gh: () => (existsSync(log) ? readFileSync(log, 'utf8') : '') };
}

function withPath(bin, fn) {
  const previous = process.env.PATH;
  process.env.PATH = `${bin}:${previous}`;
  try {
    return fn();
  } finally {
    process.env.PATH = previous;
  }
}

const quiet = (fn) => {
  const log = console.log;
  console.log = () => {};
  try {
    return fn();
  } finally {
    console.log = log;
  }
};

const diffFor = (path, body = ['@@ -1 +1 @@', '-a', '+b']) =>
  [`diff --git a/${path} b/${path}`, 'index 1111111..2222222 100644', `--- a/${path}`, `+++ b/${path}`, ...body, ''].join('\n');

describe('patchRefusal', () => {
  it('accepts the patch the engine proved', () => {
    const { result } = fixture('model');
    const a = result.fixes.attempts.find((x) => x.status === 'FIX_PROVEN');
    assert.equal(patchRefusal(readFileSync(a.patchFile, 'utf8')), null);
  });

  for (const [what, diff, said] of [
    ['a workflow', diffFor('.github/workflows/ci.yml'), /CI or workflow/],
    ['other CI configuration', diffFor('.gitlab-ci.yml'), /CI or workflow/],
    ['a registry file', diffFor('.npmrc'), /where packages come from/],
    ['a parent path', diffFor('../outside.js'), /outside the repository/],
    ['an absolute path', ['--- /etc/passwd', '+++ /etc/passwd', '@@ -1 +1 @@', '-a', '+b', ''].join('\n'), /outside the repository/],
    ['a URL added to a lockfile', diffFor('package-lock.json', ['@@ -1 +1 @@', '-"x": 1', '+"resolved": "https://evil.example/x.tgz"']), /lockfile/],
    ['a symbolic link', ['diff --git a/link b/link', 'new file mode 120000', '--- /dev/null', '+++ b/link', '@@ -0,0 +1 @@', '+/etc', ''].join('\n'), /symbolic link/],
    ['a quoted path', 'diff --git "a/x\\ty" "b/x\\ty"\n', /quote/],
    ['an empty diff', '', /names no file/],
  ]) {
    it(`refuses ${what}`, () => assert.match(patchRefusal(diff) ?? '', said));
  }

  it('allows a lockfile change that adds no URL', () => {
    assert.equal(patchRefusal(diffFor('package-lock.json', ['@@ -1 +1 @@', '-"version": "1"', '+"version": "2"'])), null);
  });

  it('reads a header-shaped line inside a hunk as content', () => {
    assert.equal(patchRefusal(diffFor('index.js', ['@@ -1 +1,2 @@', ' a', '++++ b/.github/workflows/x.yml'])), null);
  });

  it('reads a header after a finished hunk as a header', () => {
    const smuggled = `${diffFor('index.js')}--- a/.github/workflows/x.yml\n+++ b/.github/workflows/x.yml\n@@ -1 +1 @@\n-a\n+b\n`;
    assert.match(patchRefusal(smuggled) ?? '', /CI or workflow/);
  });
});

describe('names', () => {
  it('names one deterministic branch per class and language', () => {
    assert.equal(branchNameForSecurityFix('PROTOTYPE_POLLUTION', 'javascript'), 'credda/security-fix-prototype-pollution');
    assert.equal(branchNameForSecurityFix('ARCHIVE_TRAVERSAL', 'python'), 'credda/security-fix-archive-traversal-python');
    assert.throws(() => branchNameForSecurityFix('x; rm -rf /', 'javascript'), /Nothing was pushed/);
  });

  it('titles a proposal from engine tokens only, with no closing keyword', () => {
    assert.equal(pullRequestTitleForSecurityFix('PROTOTYPE_POLLUTION', 'CWE-1321'), 'Credda: a proven fix for PROTOTYPE_POLLUTION (CWE-1321)');
    assert.equal(pullRequestTitleForSecurityFix('`x`', 'Fixes #1'), 'Credda: a proven fix for a proven finding');
  });
});

describe('the Fixes summary', () => {
  it('says no fix was attempted without a model-backed provider, and how to get one', () => {
    const { result, out } = fixture('heuristic');
    const { usable, broken } = provenFixes(result.fixes, out);
    const text = fixesSummary({ fixes: result.fixes, usable, broken, delivery: new Map(), openPullRequest: true, patchDir: '', baseRefusal: '' });
    assert.match(text, /No fix was attempted: the provider \(heuristic\) is not model-backed/);
    assert.match(text, /anthropic-api-key/);
    assert.doesNotMatch(text, /FIX_PROVEN/);
    assert.equal(usable.length, 0);
  });

  it('lists a proven fix with its gates and how to enable pull requests, and a rejection with its step', () => {
    const { result, out } = fixture('model');
    const { usable, broken } = provenFixes(result.fixes, out);
    assert.equal(usable.length, 1);
    assert.equal(broken.length, 0);
    const text = fixesSummary({ fixes: result.fixes, usable, broken, delivery: new Map(), openPullRequest: false, patchDir: '/runner/fixes', baseRefusal: '' });
    assert.match(text, /\*\*FIX_PROVEN\*\* PROTOTYPE_POLLUTION/);
    assert.match(text, /Gates: exploit PASS, variants PASS/);
    assert.match(text, /`open-pull-request` is off/);
    assert.match(text, /contents: write/);
    assert.match(text, /\*\*FIX_REJECTED\*\* MEMORY_EXHAUSTION.*Stopped at declined/);
  });

  it('names the gate that stopped a rejected patch', () => {
    const { result, out } = fixture('broke');
    const { usable } = provenFixes(result.fixes, out);
    const text = fixesSummary({ fixes: result.fixes, usable, broken: [], delivery: new Map(), openPullRequest: true, patchDir: '', baseRefusal: '' });
    assert.equal(usable.length, 0);
    assert.match(text, /Stopped at the check-fix gates, verdict BROKE_FEATURE\. Failed: functional:/);
  });

  it('calls nothing proven when the engine wrote no fix record', () => {
    const text = fixesSummary({ fixes: undefined, usable: [], broken: [], delivery: new Map(), openPullRequest: true, patchDir: '', baseRefusal: '' });
    assert.match(text, /no fix record, so no fix was attempted/);
  });
});

describe('provenFixes', () => {
  it('refuses a FIX_PROVEN whose patch file is outside the output directory', () => {
    const { result } = fixture('model');
    const { usable, broken } = provenFixes(result.fixes, temp());
    assert.equal(usable.length, 0);
    assert.match(broken[0].why, /outside the output directory/);
  });

  it('refuses a FIX_PROVEN whose file differs from the patch in security.json', () => {
    const { result, out } = fixture('model');
    const a = result.fixes.attempts.find((x) => x.status === 'FIX_PROVEN');
    writeFileSync(a.patchFile, `${readFileSync(a.patchFile, 'utf8')}\n`);
    assert.match(provenFixes(result.fixes, out).broken[0].why, /differs/);
  });

  it('never treats FIX_REJECTED or NOT_ATTEMPTED as deliverable', () => {
    for (const name of ['heuristic', 'broke']) {
      const { result, out } = fixture(name);
      assert.equal(provenFixes(result.fixes, out).usable.length, 0);
    }
  });
});

describe('the pull request body', () => {
  it('states the finding, the CWE, the exploit before and after, the gates, the engine and a review line', () => {
    const { result } = fixture('model');
    const attempt = result.fixes.attempts.find((x) => x.status === 'FIX_PROVEN');
    const body = securityFixBody({ attempt, findings: result.findings, engineVersion: result.engineVersion, baseBranch: 'main', baseSha: 'abcdef1234567890', runUrl });
    const finding = result.findings.find((f) => attempt.findings.includes(f.id));
    assert.ok(body.includes(String(finding.sentence)));
    assert.match(body, /CWE-1321/);
    assert.match(body, /exploit fired on the code before this patch/);
    assert.match(body, /did not fire/);
    for (const gate of attempt.gates) assert.ok(body.includes(`${gate.gate}: ${gate.status}. ${gate.reason}`), gate.gate);
    assert.ok(body.includes(`Engine: Credda ${result.engineVersion}.`));
    assert.match(body, /A person should review it before merging\. Credda does not merge\./);
    assert.doesNotMatch(body, /\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?) #\d/i);
    assert.doesNotMatch(body, /—/);
  });
});

describe('delivery through deliver-core.mjs', () => {
  const ctx = (s, extra = {}) => {
    const { result, out } = fixture('model');
    return {
      result, outDir: out, patchDir: join(temp(), 'fixes'), workspace: s.ws, repository: 'example/flat',
      baseBranch: 'main', baseRefusal: '', openPullRequest: true, runUrl, ...extra,
    };
  };

  it('opens one pull request against the scanned branch with the proven patch committed', () => {
    const s = scenario();
    const done = withPath(s.bin, () => quiet(() => deliverSecurityFixes(ctx(s))));
    const [decision] = [...done.delivery.values()];
    assert.equal(decision.outcome, 'opened', decision.message + decision.detail);
    assert.equal(decision.url, 'https://github.example/example/flat/pull/7');
    const branch = 'credda/security-fix-prototype-pollution';
    const pushed = git(s.origin, 'show', `${branch}:index.js`);
    assert.match(pushed, /key1 === 'constructor'/);
    assert.equal(git(s.origin, 'log', '-1', '--format=%an %s', branch), 'Credda Credda: a proven fix for PROTOTYPE_POLLUTION (CWE-1321)');
    const create = s.gh().split('\n').find((l) => l.startsWith('pr create'));
    assert.match(create, /--head credda\/security-fix-prototype-pollution/);
    assert.match(create, /--base main/);
    assert.doesNotMatch(s.gh(), /repo view/);
    assert.doesNotMatch(s.gh(), /pr merge|--auto|--approve|pr review/);
    assert.ok(existsSync(join(done.patchDir, 'fix-PROTOTYPE_POLLUTION.patch')));
    // The workspace is back on the scanned commit.
    assert.equal(git(s.ws, 'rev-parse', 'HEAD'), git(s.origin, 'rev-parse', 'main'));
  });

  it('says "already proposed" and pushes nothing when the branch has an open pull request', () => {
    const s = scenario({ openPr: 'https://github.example/example/flat/pull/7' });
    withPath(s.bin, () => quiet(() => deliverSecurityFixes(ctx(s))));
    const again = withPath(s.bin, () => quiet(() => deliverSecurityFixes(ctx(s))));
    const [decision] = [...again.delivery.values()];
    assert.equal(decision.outcome, 'already-proposed');
    assert.equal(s.gh().split('\n').filter((l) => l.startsWith('pr create')).length, 1);
  });

  it('refuses, and never force-pushes, when the branch exists with no open pull request', () => {
    const s = scenario();
    withPath(s.bin, () => quiet(() => deliverSecurityFixes(ctx(s))));
    const before = git(s.origin, 'rev-parse', 'credda/security-fix-prototype-pollution');
    const again = withPath(s.bin, () => quiet(() => deliverSecurityFixes(ctx(s))));
    const [decision] = [...again.delivery.values()];
    assert.equal(decision.outcome, 'refused');
    assert.match(decision.message, /already exists and has no open pull request/);
    assert.equal(git(s.origin, 'rev-parse', 'credda/security-fix-prototype-pollution'), before);
  });

  it('with open-pull-request off writes the patch and body and calls neither git push nor gh', () => {
    const s = scenario();
    const done = withPath(s.bin, () => deliverSecurityFixes(ctx(s, { openPullRequest: false })));
    assert.equal(done.delivery.size, 0);
    assert.equal(s.gh(), '');
    assert.ok(readFileSync(join(done.patchDir, 'fix-PROTOTYPE_POLLUTION.md'), 'utf8').includes('A person should review it'));
    assert.equal(spawnSync('git', ['ls-remote', '--heads', s.origin, 'credda/*'], { encoding: 'utf8' }).stdout, '');
  });

  it('proposes nothing when the run scanned a pull request merge commit', () => {
    const s = scenario();
    const done = withPath(s.bin, () => deliverSecurityFixes(ctx(s, { baseBranch: '', baseRefusal: 'merge commit' })));
    assert.equal(done.delivery.size, 0);
    assert.equal(s.gh(), '');
  });

  it('refuses a proven patch that touches .github/ before git runs', () => {
    const s = scenario();
    const c = ctx(s);
    const a = c.result.fixes.attempts.find((x) => x.status === 'FIX_PROVEN');
    const evil = diffFor('.github/workflows/ci.yml');
    writeFileSync(a.patchFile, evil);
    a.patch = evil;
    const done = withPath(s.bin, () => quiet(() => deliverSecurityFixes(c)));
    const [decision] = [...done.delivery.values()];
    assert.equal(decision.outcome, 'refused');
    assert.match(decision.detail, /CI or workflow/);
    assert.equal(s.gh(), '');
    assert.equal(spawnSync('git', ['ls-remote', '--heads', s.origin, 'credda/*'], { encoding: 'utf8' }).stdout, '');
  });
});

describe('security-fix.mjs', () => {
  it('has no merge verb and reads no environment', () => {
    const code = readFileSync(SOURCE, 'utf8').split('\n').filter((l) => !/^\s*(?:\/\/|\*|\/\*)/.test(l)).join('\n');
    for (const verb of ['pr merge', '--auto', 'pr review', '--approve', 'enablePullRequestAutoMerge', 'process.env']) {
      assert.ok(!code.includes(verb), verb);
    }
  });
});
