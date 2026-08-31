#!/usr/bin/env node
/*
 * The action ships as a git tree. This proves the tree is complete.
 *
 * WHY THIS EXISTS. Nothing in the public repository ran on a pull request. The
 * tests that hold `run.mjs`, `delivery.mjs` and `action.yml` to their meanings
 * live in the private engine checkout and read this repository as a sibling, so
 * a contributor here -- or a maintainer editing on the web -- got no signal at
 * all, and `smoke.yml` only runs after a push to `main` has already happened.
 *
 * WHAT IT CHECKS, AND WHY THESE. Not semantics: those are core's and belong
 * there, and a second opinion about them here is how two surfaces come to
 * disagree. This checks the one thing core cannot, because core reads a
 * developer's working tree rather than the tree a customer fetches: that every
 * file the action reaches for at run time is actually IN the tree, and that the
 * version it names is the version the lockfile pins.
 *
 * `a65ab94` is why. A launcher file the shipped tree did not carry is a defect
 * that has already happened here, and nothing red would have said so.
 *
 * It runs on plain Node with no dependencies, no network, and no engine,
 * because this repository installs nothing -- see the `//` note in package.json.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, normalize, relative } from 'node:path';

const problems = [];
const note = (line) => problems.push(line);

/* The tree a customer fetches is the tracked tree, not the working directory.
 * An untracked file passes every check you can run on a laptop and is absent
 * from every checkout of the tag. */
const tracked = new Set(
  execFileSync('git', ['ls-files'], { encoding: 'utf8' }).split('\n').filter((l) => l !== ''),
);

const shipped = [...tracked].filter((f) => f.endsWith('.mjs') && !f.startsWith('.github/'));

if (shipped.length === 0) {
  note('No shipped .mjs files were found. Either the layout moved or this checker is looking in');
  note('  the wrong place; a green line covering nothing is worse than a red one.');
}

/* 1. Every shipped module parses. A syntax error in `run.mjs` is discovered by
 * the first customer to label an issue, and there is no build step here to
 * catch it earlier. */
for (const file of shipped) {
  try {
    execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' });
  } catch (error) {
    const said = String(error.stderr ?? '').trim().split('\n').slice(0, 3).join(' / ');
    note(`${file} does not parse: ${said}`);
  }
}

/* 2. Every relative import resolves to a TRACKED file. This is a65ab94's
 * defect, stated as an assertion.
 *
 * THREE FORMS, AND THE THIRD WAS MISSING. `import x from './y.mjs'` and
 * `import('./y.mjs')` were matched; a bare side-effect `import './y.mjs';` has
 * no `from` and no parenthesis, so it matched nothing -- and this checker still
 * printed "every relative import ... is tracked". An untracked module imported
 * that way passed here and is absent from every checkout of the tag, which is
 * precisely the defect this assertion exists for.
 *
 * BOTH QUOTE STYLES, for the same reason. Every module here is single-quoted
 * today and the pattern was written to that, so a double-quoted specifier --
 * which a maintainer editing on github.com is one autoformat away from -- was
 * invisible in all three forms. The quote is captured and back-referenced
 * rather than alternated, so `'x"` cannot match.
 *
 * Each of the three forms was verified by adding one to a shipped module and
 * watching this go from green to red. */
const importFrom =
  /(?:^|[\s(])(?:import|export)[^'"]*?from\s*(['"])(\.[^'"]*)\1|(?:^|[\s(])import\s*\(\s*(['"])(\.[^'"]*)\3|^\s*import\s*(['"])(\.[^'"]*)\5/gm;
for (const file of shipped) {
  const source = readFileSync(file, 'utf8');
  for (const match of source.matchAll(importFrom)) {
    const specifier = match[2] ?? match[4] ?? match[6];
    const target = normalize(join(dirname(file), specifier));
    if (!tracked.has(target)) {
      note(`${file} imports '${specifier}', which is not a tracked file (${target}).`);
      note('  It resolves in this working copy and is absent from every checkout of the tag.');
    }
  }
}

/* 3. Every file `action.yml` executes is tracked. The launcher, the runner and
 * the delivery script are named there as paths, not as imports, so nothing
 * above would notice one going missing. */
const actionYml = readFileSync('action.yml', 'utf8');
for (const match of actionYml.matchAll(/(?:\$GITHUB_ACTION_PATH|\$\{\{\s*github\.action_path\s*\}\})\/([A-Za-z0-9_./-]+)/g)) {
  const target = normalize(match[1]);
  if (target === '..' || target.startsWith('../')) continue;
  if (!tracked.has(target)) {
    note(`action.yml runs \`${target}\`, which is not a tracked file.`);
  }
}

/* 4. package.json is shipped. `launcher/fetch-engine.mjs` COPIES it out of the
 * action root so the engine can answer `credda --version`; without it every
 * receipt in the fleet reports "unknown" and nothing fails. */
if (!tracked.has('package.json')) {
  note('package.json is not tracked, and the launcher copies it beside the unpacked engine.');
  note('  Its absence fails nothing at run time and makes every metering receipt say "unknown".');
}

/* 5. The version names the same release in both files. package.json's `//`
 * note states this rule; nothing enforced it. */
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const lock = JSON.parse(readFileSync('engine.lock.json', 'utf8'));
const version = pkg.version;

if (typeof version !== 'string' || !/^[A-Za-z0-9._-]{1,32}$/.test(version)) {
  note(`package.json version '${String(version)}' is not matchable by /^[A-Za-z0-9._-]{1,32}$/.`);
  note('  The metering protocol rejects it, at the client and again at the server.');
}
if (/^[0-9a-f]{7,40}$/i.test(String(version))) {
  note(`package.json version '${String(version)}' looks like a commit SHA, which metering rejects.`);
}
if (lock.version !== `v${String(version)}`) {
  note(`package.json says '${String(version)}' and engine.lock.json pins '${String(lock.version)}'.`);
  note('  The launcher asks the engine endpoint for the lockfile version and the copied');
  note('  package.json reports the other, so a run fetches one release and names another.');
}

/* 6. The README's inventory of this repository is the repository.
 *
 * "That is the whole repository" is a sentence about a list, and a list is the
 * one kind of documentation that rots without reading wrong: every line in it
 * stayed true while `delivery.mjs`, `deliver-pr.mjs`, both CI checks and this
 * file were added around it, and the paragraph under it still said `whole`.
 * A reader deciding whether to trust an action reads that block to find out
 * what runs on their runner, and it was missing the two files that push a
 * branch and open a pull request.
 *
 * BOTH DIRECTIONS, because only one of them is the defect that already
 * happened and the other is the one that happens next: a tracked file with no
 * line describing it, and a line naming a path that has since moved.
 *
 * A trailing `/` means a directory and matches everything under it; a `*`
 * matches within one path segment. Anything else is a literal path. */
const readme = readFileSync('README.md', 'utf8');
const inventory = /## What is in this repository\s*\n+```\n([\s\S]*?)\n```/.exec(readme);

if (inventory === null) {
  note('README.md has no fenced inventory under "## What is in this repository".');
  note('  That block is checked against the tracked tree; without it this assertion covers nothing.');
} else {
  /* Continuation lines are indented; an entry starts at column zero. */
  const entries = inventory[1]
    .split('\n')
    .filter((line) => /^\S/.test(line))
    .map((line) => line.split(/\s+/)[0]);

  if (entries.length === 0) {
    note('README.md\'s inventory block lists no paths at all, so it describes nothing.');
  }

  const matcher = (entry) => {
    if (entry.endsWith('/')) return (f) => f.startsWith(entry);
    if (entry.includes('*')) {
      const pattern = new RegExp(
        `^${entry.split('*').map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[^/]*')}$`,
      );
      return (f) => pattern.test(f);
    }
    return (f) => f === entry;
  };

  const files = [...tracked];
  const described = new Set();

  for (const entry of entries) {
    const hits = files.filter(matcher(entry));
    if (hits.length === 0) {
      note(`README.md's inventory lists '${entry}', which matches no tracked file.`);
      note('  The listing is what a reader uses to decide what runs on their runner.');
    }
    for (const hit of hits) described.add(hit);
  }

  for (const file of files) {
    if (described.has(file)) continue;
    note(`${file} is tracked and the README's inventory does not mention it.`);
    note('  That block ends "That is the whole repository", which is then not true.');
  }
}

if (problems.length > 0) {
  console.error('The shipped tree is not complete:\n');
  for (const line of problems) console.error(`  ${line}`);
  process.exit(1);
}

console.log(
  `Shipped tree is complete: ${String(shipped.length)} module(s) parse, every relative import and ` +
    `every path action.yml runs is tracked, both files name ${String(version)}, and the README's ` +
    `inventory and the ${String(tracked.size)} tracked files describe each other exactly.`,
);
