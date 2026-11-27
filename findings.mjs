// How security.json (engine v0.1.17) is read, in one place. run.mjs writes the job
// summary from these, integrations.mjs fills Slack, Linear and Jira from them and
// security-fix.mjs writes the fix pull request body from them, so the summary, a
// tracker issue and a pull request cannot describe one finding two ways.

/** Every line ending markdown and the runner's log reader honour. */
export const LINE_BREAK = /\r\n|\r|\n/;

/** The first line of a text, cut at any line ending, so it cannot start a second line or a workflow command. */
export const oneLine = (text) => String(text ?? '').split(LINE_BREAK)[0];

/** Markdown text from the scanned repository: every ASCII punctuation mark escaped, so no link, image, HTML or markup forms. */
export const markdownText = (text) => String(text).replace(/[!-/:-@[-`{-~]/g, '\\$&');

/** One line of untrusted text for a job summary or a pull request body: first line, cut to `max`, escaped. */
export function plain(text, max = 300) {
  const first = oneLine(text);
  return markdownText(first.length > max ? `${first.slice(0, max)}...` : first);
}

/** A code span that its text cannot close, on one line. */
export function codeSpan(text) {
  const body = String(text ?? '').replace(/[\r\n]+/g, ' ');
  const tick = '`'.repeat(Math.max(1, ...(body.match(/`+/g) ?? []).map((run) => run.length + 1)));
  const pad = body.startsWith('`') || body.endsWith('`') || body.startsWith(' ') ? ' ' : '';
  return `${tick}${pad}${body}${pad}${tick}`;
}

/** An engine version such as 0.1.18, or '' when the text is not one. */
export const engineVersionText = (v) => (/^v?\d{1,4}\.\d{1,4}\.\d{1,6}(?:-[A-Za-z0-9.]{1,40})?$/.test(String(v ?? '')) ? String(v) : '');

/** What a clean run says, on the job summary and in Slack. */
export const NOTHING_PROVEN =
  'No exploit succeeded. That is not an audit: it says the probes Credda has did not prove a ' +
  'finding in the code they reached.';

/**
 * The findings, the probes that are not fuzz proofs, and how many functions were
 * fuzzed. A fuzz finding is also listed as a probe (id `CLASS@fuzz:fn`), so it is
 * counted under fuzzing instead.
 */
export function securityCounts(result) {
  const findings = Array.isArray(result?.findings) ? result.findings : [];
  const probes = Array.isArray(result?.probes) ? result.probes.filter((p) => !String(p.id).includes('@fuzz:')) : [];
  const fuzzed = (result?.fuzz?.functions ?? 0) + (result?.pythonFuzz?.functions ?? 0);
  return { findings, probes: probes.length, fuzzed };
}

/** "Ran 6 exploit probes and fuzzed 2 exported functions". */
export function ranText(probes, fuzzed) {
  const fuzzText = fuzzed > 0 ? ` and fuzzed ${fuzzed} exported function${fuzzed === 1 ? '' : 's'}` : '';
  return `Ran ${probes} exploit probe${probes === 1 ? '' : 's'}${fuzzText}`;
}

/**
 * Where a finding is, as words: "in the package (through package.json)" or
 * "at src/a.js:3", or '' when the engine gave no site. `code` wraps the path for
 * a format that marks code.
 */
export function siteText(site, code = (s) => s) {
  if (site?.kind === 'package') return `in the package (through ${code(site.file)})`;
  if (site?.file) return `at ${code(`${site.file}${site.line ? `:${site.line}` : ''}`)}`;
  return '';
}

/** The fence language for a finding's exploit program. */
export const exploitLanguage = (finding) => (finding?.language === 'python' ? 'python' : 'js');

/** A backtick fence longer than any backtick run in the program, so the program cannot close it. */
export const fenceFor = (program) =>
  '`'.repeat(Math.max(3, ...(String(program).match(/`+/g) ?? []).map((run) => run.length + 1)));

/** An engine token (a status, verdict or step) as is, or null when it is not shaped like one. */
const engineToken = (text) => (/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(String(text ?? '')) ? String(text) : null);

/** A pull request URL as `gh pr create` prints it, or '' for anything else. */
export const pullRequestUrl = (url) =>
  /^https:\/\/[A-Za-z0-9.-]+(?::[0-9]{1,5})?\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+\/pull\/[0-9]{1,10}$/.test(String(url ?? '')) ? String(url) : '';

/**
 * What happened to the fix for one finding, as `{ text, url }`, or null when the
 * run made no fix record (`fix` off) or no attempt names the finding. The
 * verdict is the engine's `fixes` record in security.json; whether a pull
 * request was opened is the delivery record run.mjs wrote (`delivered`, one
 * entry per FIX_PROVEN attempt). Only engine tokens are used, never the
 * model's own words, and `url` is '' unless it is shaped like a pull request.
 */
export function fixFor(fixes, delivered, findingId) {
  const attempts = Array.isArray(fixes?.attempts) ? fixes.attempts : [];
  const a = attempts.find((x) => Array.isArray(x?.findings) && x.findings.includes(findingId));
  if (a === undefined) return null;
  if (a.status === 'FIX_PROVEN') {
    const list = Array.isArray(delivered) ? delivered : [];
    const d = list.find((x) => x?.class === a.class && x?.language === a.language);
    const proven = 'Fix proven by the check-fix gates.';
    if (d === undefined) return { text: proven, url: '' };
    if (d.outcome === 'not-offered') {
      return { text: 'The engine reported a proven fix, but the patch failed this action\'s checks, so nothing was proposed.', url: '' };
    }
    const url = pullRequestUrl(d.url);
    if (d.outcome === 'opened') return url ? { text: `${proven} Pull request opened:`, url } : { text: `${proven} A pull request was opened.`, url: '' };
    if (d.outcome === 'already-proposed') return { text: `${proven} A pull request for it was already open${url ? ':' : '.'}`, url };
    return { text: `${proven} No pull request was opened. The job summary says why.`, url: '' };
  }
  if (a.status === 'FIX_REJECTED') {
    const verdict = engineToken(a.verdict);
    const step = engineToken(a.stoppedAt);
    if (a.stoppedAt === 'check-fix' && verdict) return { text: `Fix rejected by the check-fix gates (${verdict}).`, url: '' };
    return { text: `Fix rejected${step ? ` (stopped at ${step})` : ''}.`, url: '' };
  }
  if (a.status === 'NOT_ATTEMPTED') {
    return { text: `Fix not attempted.${fixes?.modelBacked === false ? ' The provider is not model-backed.' : ''}`, url: '' };
  }
  const status = engineToken(a.status);
  return { text: `Fix status: ${status ?? 'not stated'}.`, url: '' };
}

/**
 * The probe classes the engine keeps behind a flag, by the name `extra-probes`
 * takes. Each env var is read by the engine and is off unless it is '1'. `since`
 * is the first engine release that has the class.
 */
export const EXTRA_PROBES = {
  injection: { cls: 'INJECTION_TO_EXECUTION', env: 'CREDDA_INJECTION_PROBE', since: '0.1.18' },
  ssrf: { cls: 'SSRF', env: 'CREDDA_SSRF_PROBE', since: '0.1.18' },
  xss: { cls: 'REFLECTED_XSS', env: 'CREDDA_XSS_PROBE', since: '0.1.19' },
};

/**
 * `extra-probes` as names, or an error for the first name this action does not
 * know. Empty means none. Items are trimmed; empty items are dropped.
 */
export function parseExtraProbes(raw) {
  const names = [];
  for (const item of String(raw ?? '').split(',').map((s) => s.trim()).filter((s) => s !== '')) {
    if (!Object.hasOwn(EXTRA_PROBES, item)) {
      return {
        names: [],
        error: `extra-probes names ${JSON.stringify(item.slice(0, 40))}, which is not a probe class this action knows. ` +
          `Use a comma-separated list of ${Object.keys(EXTRA_PROBES).join(', ')}, or leave it empty.`,
      };
    }
    if (!names.includes(item)) names.push(item);
  }
  return { names, error: null };
}

/** The environment for the `credda security` run: '1' for each named class, unset for the rest. */
export function extraProbeEnv(names) {
  return Object.fromEntries(Object.entries(EXTRA_PROBES).map(([name, p]) => [p.env, names.includes(name) ? '1' : undefined]));
}

/** -1, 0 or 1, or null when either is not a version. */
function compareVersions(a, b) {
  const pa = /^v?(\d+)\.(\d+)\.(\d+)/.exec(String(a ?? ''));
  const pb = /^v?(\d+)\.(\d+)\.(\d+)/.exec(String(b ?? ''));
  if (pa === null || pb === null) return null;
  for (let i = 1; i <= 3; i += 1) {
    if (Number(pa[i]) !== Number(pb[i])) return Number(pa[i]) < Number(pb[i]) ? -1 : 1;
  }
  return 0;
}

/**
 * One summary line per requested class. security.json says which classes ran
 * through `probes[].class`; it has no list of the classes an engine has, so a
 * class with no probe is "not available in this engine" only when the engine's
 * own version is older than the class.
 */
export function extraProbesLines(names, result) {
  const probes = Array.isArray(result?.probes) ? result.probes : [];
  const version = engineVersionText(result?.engineVersion);
  return names.map((name) => {
    const p = EXTRA_PROBES[name];
    const head = `- \`${name}\` (${p.cls}):`;
    const ran = probes.filter((x) => x?.class === p.cls).length;
    if (ran > 0) return `${head} ${ran} probe${ran === 1 ? '' : 's'} ran. Only a finding an exploit proved is listed above.`;
    const older = compareVersions(version, p.since);
    if (older === -1) return `${head} not available in this engine (Credda ${version}). It needs v${p.since} or later. Nothing was probed for it.`;
    if (older === null) {
      return `${head} security.json lists no probe of this class. This engine may not have it (it needs v${p.since} or later), or nothing in this repository matched it.`;
    }
    return `${head} no probe of this class applied to this repository, so none ran.`;
  });
}

/* ------------------------------ what a run reached ------------------------------ */

/** A count the engine wrote, or null when it is absent or not a whole number. */
const whole = (v) => (Number.isSafeInteger(v) && v >= 0 ? v : null);

/** The verdicts security.json uses, by the key `security-reach` gives them. */
const VERDICTS = [
  ['PROVEN', 'proven'],
  ['CLEAN', 'clean'],
  ['ABSTAINED', 'abstained'],
  ['TIMED_OUT', 'timedOut'],
  ['CRASHED', 'crashed'],
  ['NOT_RUN', 'notRun'],
];

/** What each verdict says, for the job summary. */
const VERDICT_MEANING = {
  proven: 'Proven: an exploit ran and printed its own finding. Only these are findings.',
  clean: 'Clean: the probe ran against code it could drive and no exploit succeeded.',
  abstained: 'Abstained: the probe had nothing it could drive or measure, so it says nothing about that class.',
  timedOut: 'Timed out: the probe hit its time limit before a verdict, so it says nothing about that class.',
  crashed: 'Crashed: the probe failed inside Credda. That is our failure, and it says nothing about that class.',
  notRun: 'Not run: the probe never started, so it says nothing about that class.',
};

const VERDICT_WORDS = { proven: 'proven', clean: 'clean', abstained: 'abstained', timedOut: 'timed out', crashed: 'crashed', notRun: 'not run' };

/** The probes that are not fuzz proofs, as securityCounts counts them, or null when security.json has no list. */
const plainProbes = (result) => (Array.isArray(result?.probes) ? result.probes.filter((p) => !String(p?.id).includes('@fuzz:')) : null);

/** Probes by verdict, counted off `probes[]`, or null when there is no list. `other` is a verdict this action does not know. */
function probeVerdicts(result) {
  const probes = plainProbes(result);
  if (probes === null) return null;
  const counts = { attempted: probes.length, proven: 0, clean: 0, abstained: 0, timedOut: 0, crashed: 0, notRun: 0, other: 0, package: 0, source: 0 };
  for (const p of probes) {
    if (p?.site?.kind === 'package' || p?.site?.kind === 'source') counts[p.site.kind] += 1;
    const hit = VERDICTS.find(([v]) => v === p?.verdict);
    counts[hit ? hit[1] : 'other'] += 1;
  }
  return counts;
}

/** The fuzz records security.json has (JavaScript, Python), each with its label. */
const fuzzRecords = (result) =>
  [['Fuzzing', result?.fuzz], ['Python fuzzing', result?.pythonFuzz]].filter(([, z]) => z !== null && typeof z === 'object');

/* ------------------------------ workspace reports ------------------------------ */

/** The most packages named on one line of the job summary or in Slack before "and K more". */
export const MAX_NAMED_PACKAGES = 5;

/** A list of strings the engine wrote, or [] when it wrote none. */
const strings = (v) => (Array.isArray(v) ? v.map((s) => String(s ?? '')) : []);

/** Why the engine did not exercise one scanned package: its own first reason, untrusted, or a sentence of ours. */
function notTestedReason(p) {
  const u = Array.isArray(p?.untested) ? p.untested.find((x) => typeof x?.reason === 'string' && x.reason !== '') : undefined;
  if (u !== undefined) return oneLine(u.reason);
  if (typeof p?.unsupported?.reason === 'string') return `nothing was scanned, because ${oneLine(p.unsupported.reason)}`;
  if (typeof p?.installError === 'string' && p.installError !== '') return `it did not install: ${oneLine(p.installError)}`;
  return 'the engine gave no reason';
}

/**
 * A workspace (monorepo) report's reach, or null for a report of one package.
 * Engines after v0.1.19 write `workspaceScan` and `packages` when the root
 * declares a workspace. Counts the engine did not write are null. `missed` is
 * every package in scope that was not exercised, the not tested ones first,
 * each with the engine's reason (untrusted text: escape it for the format).
 */
export function workspaceReach(result) {
  const ws = result?.workspaceScan;
  if (ws === null || typeof ws !== 'object' || Array.isArray(ws)) return null;
  const packages = Array.isArray(result?.packages) ? result.packages.filter((p) => p !== null && typeof p === 'object') : [];
  const byPath = new Map(packages.map((p) => [String(p.path), p]));
  const cap = whole(ws.cap);
  const notTested = strings(ws.notTested);
  const overCap = strings(ws.overCap);
  const missed = [
    ...notTested.map((path) => ({ path, reason: notTestedReason(byPath.get(path)) })),
    ...overCap.map((path) => {
      const said = byPath.get(path)?.scopeReason;
      return { path, reason: typeof said === 'string' && said !== '' ? oneLine(said) : `over the cap${cap === null ? '' : ` of ${cap}`} packages` };
    }),
  ];
  return {
    found: whole(ws.total),
    considered: whole(ws.considered),
    scanned: whole(ws.scanned),
    exercised: whole(ws.exercised),
    cap,
    notTested: Array.isArray(ws.notTested) ? notTested : null,
    overCap: Array.isArray(ws.overCap) ? overCap : null,
    missed,
    packages,
  };
}

/** "3 of 30 packages", with "?" for a count the engine did not write. */
const ofPackages = (w) => `${w.exercised ?? '?'} of ${w.considered ?? '?'} package${w.considered === 1 ? '' : 's'}`;

/** "Credda exercised 3 of 30 packages." */
export const exercisedSentence = (w) => `Credda exercised ${ofPackages(w)}.`;

/**
 * The packages in scope that were not exercised, as one line: "`a` (why); `b`
 * (why); and 4 more". `name` and `text` escape the path and the reason for the
 * format, so nothing the repository or the engine wrote forms markup.
 */
export function missedText(missed, name, text, max = MAX_NAMED_PACKAGES) {
  const shown = missed.slice(0, max).map((m) => `${name(oneLine(m.path).slice(0, 200))} (${text(m.reason, 160)})`);
  return `${shown.join('; ')}${missed.length > max ? `; and ${missed.length - max} more` : ''}`;
}

/**
 * The package a finding of a workspace report belongs to: the longest package
 * path its id starts with, or `.` (the root, whose ids the engine does not
 * prefix). '' on a report of one package. The id is the source of truth, not
 * the finding's `package` field.
 */
export function findingPackage(finding, result) {
  // Without the packages list there is nothing to read a prefix against, so no label rather than a wrong one.
  if (workspaceReach(result) === null || !Array.isArray(result?.packages)) return '';
  const id = String(finding?.id ?? '');
  const hits = result.packages
    .map((p) => String(p?.path ?? ''))
    .filter((path) => path !== '' && path !== '.' && id.startsWith(`${path}/`))
    .sort((a, b) => b.length - a.length);
  return hits[0] ?? '.';
}

/** How a finding's package reads in a sentence: "in package `a`" or "in the workspace root". `name` wraps the path for the format. */
export const packageWords = (pkg, name = (s) => s) => (pkg === '' ? '' : pkg === '.' ? 'in the workspace root' : `in package ${name(pkg)}`);

/**
 * Whether part of what was in scope was not exercised, as `security-reach`'s
 * `partial` gives it. On a workspace report: at least one package was not
 * tested or was over the cap. On a report of one package: the engine listed a
 * language as NOT TESTED (`untested`, v0.1.19 and later), found nothing it
 * could scan (`unsupported`), or scanned only the root of a workspace
 * (`workspace`, v0.1.19). On either: the engine named a directory with its
 * own manifest that no scan read (`notScanned`, v0.1.21). A field that is
 * absent is not evidence either way.
 */
export function partialReach(result) {
  if ((whole(result?.notScanned?.total) ?? 0) > 0) return true;
  const w = workspaceReach(result);
  if (w !== null) return (w.notTested?.length ?? 0) + (w.overCap?.length ?? 0) > 0;
  return (Array.isArray(result?.untested) && result.untested.length > 0) ||
    (result?.unsupported !== null && typeof result?.unsupported === 'object') ||
    (whole(result?.workspace?.total) ?? 0) > 0;
}

/**
 * Why a run that proved nothing reached too little to mean anything, as reasons
 * this action wrote, plus `said`, the engine's own words (untrusted) when it gave
 * any. Empty `reasons` means reach was not limited.
 *
 * ON A WORKSPACE REPORT the rule is about the workspace: reach is limited when
 * no finding was proven and no package was exercised (`workspaceScan.exercised`
 * is 0). The rules below are about one package, and a workspace's top-level
 * `installed` is false when any one package failed to install, so they do not
 * apply to it. A workspace where some packages were exercised is partial
 * (partialReach), never limited.
 *
 * THE RULE. Reach is limited when no finding was proven AND any of:
 *   1. `installed` is false: the package did not install.
 *   2. security.json has a fuzz record (`fuzz` or `pythonFuzz`) and their
 *      `functions` add up to 0: no exported function was fuzzed.
 *   3. at least one probe drives the package through its manifest
 *      (`site.kind` is `package`, fuzz proofs aside) and none of them ended
 *      CLEAN: every one abstained, timed out, crashed or did not run.
 *   4. a source-load record (`fuzz.reach` or `python.reach`) imported nothing.
 *   5. no probe ran and no function was fuzzed.
 * A field that is absent is not evidence either way, so an older engine is
 * judged on the fields it does write.
 */
export function limitedReach(result) {
  const findings = Array.isArray(result?.findings) ? result.findings : [];
  if (findings.length > 0) return { reasons: [], said: '' };
  const w = workspaceReach(result);
  if (w !== null) {
    if (w.exercised !== 0) return { reasons: [], said: '' };
    const n = w.considered;
    const why = n === null ? 'no package of the workspace was exercised' : n === 1 ? 'the one package in scope was not exercised' : `none of the ${n} packages in scope was exercised`;
    return { reasons: [why], said: '' };
  }
  const reasons = [];
  if (result?.installed === false) reasons.push('the package did not install');
  const records = fuzzRecords(result);
  const fuzzed = records.reduce((n, [, z]) => n + (whole(z.functions) ?? 0), 0);
  if (records.length > 0 && fuzzed === 0) reasons.push('no exported function could be fuzzed');
  const probes = plainProbes(result) ?? [];
  const driving = probes.filter((p) => p?.site?.kind === 'package');
  if (driving.length > 0 && !driving.some((p) => p?.verdict === 'CLEAN')) {
    reasons.push(`none of the ${driving.length} probe${driving.length === 1 ? '' : 's'} that call the package's exports found code ${driving.length === 1 ? 'it' : 'they'} could drive`);
  }
  for (const r of [result?.fuzz?.reach, result?.python?.reach]) {
    if (r && Array.isArray(r.imported) && r.imported.length === 0) {
      reasons.push('no source module could be imported');
      break;
    }
  }
  if (probes.length === 0 && fuzzed === 0) reasons.push('no probe ran and no function was fuzzed');
  if (reasons.length === 0) return { reasons, said: '' };
  const notes = [result?.fuzz?.note, result?.pythonFuzz?.note, result?.python?.note, result?.note].filter((n) => typeof n === 'string' && n !== '');
  const probeSaid = driving.find((p) => p?.verdict !== 'CLEAN' && typeof p?.said === 'string' && p.said !== '')?.said;
  return { reasons, said: oneLine(notes[0] ?? probeSaid ?? '') };
}

/** The warning, as plain sentences of this action's own plus the engine's words. `said` is untrusted: escape it for the format. */
export function reachWarning(result) {
  const { reasons, said } = limitedReach(result);
  if (reasons.length === 0) return null;
  const why = reasons.join(', and ');
  return {
    lead: "Credda could not exercise this repository's code.",
    why: `${why[0].toUpperCase()}${why.slice(1)}. So this run says nothing about whether the code is safe.`,
    said,
  };
}

/**
 * The `security-reach` output: numbers and two booleans, nothing from the
 * repository. A field the engine did not write is null, never 0. `packages` is
 * null on a report of one package.
 */
export function reachRecord(result) {
  const v = probeVerdicts(result);
  const records = fuzzRecords(result);
  const fns = records.map(([, z]) => whole(z.functions));
  const r = result?.fuzz?.reach;
  const w = workspaceReach(result);
  return {
    limited: limitedReach(result).reasons.length > 0,
    functions: fns.length > 0 && fns.every((n) => n !== null) ? fns.reduce((a, b) => a + b, 0) : null,
    probes: v === null ? null : { proven: v.proven, clean: v.clean, abstained: v.abstained, timedOut: v.timedOut, crashed: v.crashed, notRun: v.notRun },
    sourceFiles: r && typeof r === 'object' ? { loaded: whole(r.filesLoaded), failed: Array.isArray(r.failed) ? r.failed.length : null } : null,
    partial: partialReach(result),
    packages: w === null ? null : { found: w.found, scanned: w.scanned, exercised: w.exercised, notTested: w.notTested?.length ?? null, overCap: w.overCap?.length ?? null },
  };
}

/** The most failed modules named on one line. */
const MAX_FAILED = 5;

/** "2 modules failed: `a` (why); `b` (why); and 3 more", every name and reason escaped by `name` and `text`. */
function failedText(failed, name, text) {
  if (failed.length === 0) return '0 modules failed';
  const shown = failed.slice(0, MAX_FAILED).map((f) => `${name(oneLine(f?.module).slice(0, 200))} (${text(f?.error, 200)})`);
  const more = failed.length > MAX_FAILED ? `; and ${failed.length - MAX_FAILED} more` : '';
  return `${failed.length} module${failed.length === 1 ? '' : 's'} failed: ${shown.join('; ')}${more}`;
}

/** The Node version the engine names, or '' when it is not shaped like one. */
const nodeVersion = (v) => (/^v?\d{1,3}\.\d{1,4}\.\d{1,4}$/.test(String(v ?? '')) ? String(v) : '');

/** How the engine loaded an unbuilt package from source, or null without a record. */
function sourceLine(r, name, text) {
  if (!r || typeof r !== 'object') return null;
  const imported = Array.isArray(r.imported) ? r.imported : [];
  const failed = Array.isArray(r.failed) ? r.failed : [];
  const node = nodeVersion(r.node);
  const files = whole(r.filesLoaded);
  const counts = [];
  let what;
  if (r.from === 'entry') {
    what = imported.length > 0 ? `the entry ${name(oneLine(imported[0]).slice(0, 200))}` : 'its entry';
  } else {
    // The top-level directories the modules came from: src/, or lib/ and app/ in an app with no src/ (v0.1.21).
    const roots = [...new Set([...imported, ...failed.map((f) => f?.module)].filter((m) => typeof m === 'string' && m.includes('/')).map((m) => m.split('/')[0]))].slice(0, 4);
    what = `the modules under ${roots.length > 0 && roots.join() !== 'src' ? roots.map((d) => name(`${oneLine(d).slice(0, 60)}/`)).join(', ') : 'src/'}`;
    counts.push(`${imported.length} imported`);
  }
  if (files !== null) counts.push(`${files} source file${files === 1 ? '' : 's'} loaded`);
  const cap = whole(r.cap);
  const over = whole(r.overCap);
  if (r.from !== 'entry' && cap !== null) counts.push(`cap ${cap}`);
  if (over) counts.push(`${over} over the cap not imported`);
  const compiled = whole(r.compiled);
  if (compiled) counts.push(`${compiled} JSX or decorator file${compiled === 1 ? '' : 's'} compiled with TypeScript first`);
  const components = whole(r.components);
  if (components) counts.push(`${components} React component${components === 1 ? '' : 's'} set aside and not called`);
  counts.push(failedText(failed, name, text));
  return `Loaded from source: no build output, so ${node ? `Node ${node}` : 'Node'} type stripping loaded ${what}. ${counts.join(', ')}.`;
}

/** One fuzz record as a sentence, from its counts only. */
function fuzzSentence(label, z) {
  const fns = whole(z.functions);
  if (fns === null) return null;
  const calls = whole(z.calls);
  const hits = whole(z.hits);
  const proven = whole(z.proven);
  const dropped = Array.isArray(z.dropped) ? z.dropped.length : null;
  const tail = [hits !== null ? `${hits} oracle hit${hits === 1 ? '' : 's'}` : '', proven !== null ? `${proven} proven` : '', dropped !== null ? `${dropped} dropped` : '']
    .filter((s) => s !== '');
  return `${label}: ${fns} exported function${fns === 1 ? '' : 's'}${calls !== null ? `, ${calls} call${calls === 1 ? '' : 's'}` : ''}.${tail.length > 0 ? ` ${tail.join(', ')}.` : ''}`;
}

/** The probes as one sentence, or null when security.json has no list. */
function probesSentence(v) {
  if (v === null) return null;
  const parts = VERDICTS.map(([, k]) => `${v[k]} ${VERDICT_WORDS[k]}`);
  if (v.other > 0) parts.push(`${v.other} with a verdict this action does not know`);
  const where = [
    v.package > 0 ? `${v.package} through the package's exports` : '',
    v.source > 0 ? `${v.source} at a line of source` : '',
  ].filter((w) => w !== '');
  return `Probes: ${v.attempted} attempted${where.length > 0 ? ` (${where.join(', ')})` : ''}. ${parts.join(', ')}.`;
}

/** The most packages listed under each heading of a workspace's reach before "K more not shown". */
const MAX_PACKAGE_LINES = 10;

/** "Packages: 30 found, 10 scanned, 3 exercised, 7 not tested, 20 over the cap of 10." */
function packagesSentence(w) {
  const n = (v) => (v === null ? '?' : String(v));
  const listed = (a) => (a === null ? '?' : String(a.length));
  return `Packages: ${n(w.found)} found, ${n(w.scanned)} scanned, ${n(w.exercised)} exercised, ${listed(w.notTested)} not tested, ` +
    `${listed(w.overCap)} over the cap${w.cap === null ? '' : ` of ${w.cap}`}.`;
}

/** One exercised package's counts: "55 probes (1 proven, 49 clean, 5 abstained); 4 functions fuzzed". */
function packageCounts(p) {
  const s = p?.summary ?? {};
  const parts = [];
  const attempted = whole(s.attempted);
  if (attempted !== null) {
    const by = VERDICTS.map(([, k]) => [whole(s[k]), VERDICT_WORDS[k]]).filter(([c]) => c !== null && c > 0).map(([c, word]) => `${c} ${word}`);
    parts.push(`${attempted} probe${attempted === 1 ? '' : 's'}${by.length > 0 ? ` (${by.join(', ')})` : ''}`);
  }
  const fns = [p?.fuzz, p?.pythonFuzz].filter((z) => z !== null && typeof z === 'object').map((z) => whole(z.functions));
  if (fns.length > 0 && fns.every((f) => f !== null)) {
    const total = fns.reduce((a, b) => a + b, 0);
    parts.push(`${total} function${total === 1 ? '' : 's'} fuzzed`);
  }
  return parts.length > 0 ? parts.join('; ') : 'security.json records no counts for it';
}

/** How many more there were, and where the full list is. */
const notShown = (n, what) => `- ${n} more ${what} not shown. security.json lists every package: set \`keep-report: 'true'\` to keep it.`;

/** A workspace's packages: the exercised ones with their counts, then the not tested and over-the-cap ones with the engine's reasons. */
function workspaceLines(w, name, text) {
  const lines = [];
  const notTested = new Set(w.notTested ?? []);
  const exercised = w.packages.filter((p) => p.exercised === true && p.scope === 'full');
  if (exercised.length > 0) {
    lines.push('Exercised packages:', '');
    for (const p of exercised.slice(0, MAX_PACKAGE_LINES)) lines.push(`- ${name(oneLine(p.path).slice(0, 200))}: ${packageCounts(p)}.`);
    if (exercised.length > MAX_PACKAGE_LINES) lines.push(notShown(exercised.length - MAX_PACKAGE_LINES, 'exercised packages'));
    lines.push('');
  }
  const missedTested = w.missed.filter((m) => notTested.has(m.path));
  if (missedTested.length > 0) {
    lines.push('Not tested: scanned, but no probe or fuzz call reached the code. This run says nothing about them.', '');
    for (const m of missedTested.slice(0, MAX_PACKAGE_LINES)) lines.push(`- ${name(oneLine(m.path).slice(0, 200))}: ${text(m.reason, 300)}`);
    if (missedTested.length > MAX_PACKAGE_LINES) lines.push(notShown(missedTested.length - MAX_PACKAGE_LINES, 'not tested packages'));
    lines.push('');
  }
  const over = w.overCap ?? [];
  if (over.length > 0) {
    lines.push(
      `Over the cap${w.cap === null ? '' : ` of ${w.cap}`}: only their regular expressions were read. They were not installed, loaded or fuzzed.`,
      '',
      `- ${over.slice(0, MAX_PACKAGE_LINES).map((p) => name(oneLine(p).slice(0, 200))).join(', ')}${over.length > MAX_PACKAGE_LINES ? `, and ${over.length - MAX_PACKAGE_LINES} more` : ''}.`,
      '',
    );
  }
  return lines;
}

/**
 * What a report of one package says was not tested: each `untested` language
 * with the engine's reason, `unsupported`, and a v0.1.19 scan of a workspace
 * root that scanned only the root (`workspace`). Empty when it says none.
 */
function notTestedItems(result, name, text) {
  const items = [];
  if (result?.unsupported !== null && typeof result?.unsupported === 'object') {
    items.push(`Not tested: nothing was scanned, because ${text(result.unsupported.reason, 300)}.`);
  }
  for (const u of Array.isArray(result?.untested) ? result.untested : []) {
    const lang = u?.language === 'python' ? 'Python' : 'JavaScript';
    items.push(`Not tested: the ${lang} package was never loaded, so no probe or fuzz call reached its code. Why: ${text(u?.reason, 400)}`);
  }
  const ws = result?.workspace;
  const total = whole(ws?.total);
  if (total !== null && total > 0) {
    const listed = Array.isArray(ws.packages) ? ws.packages.map((p) => oneLine(p?.path).slice(0, 200)) : [];
    const shown = listed.slice(0, MAX_NAMED_PACKAGES).map(name);
    const more = total - shown.length;
    items.push(`Not tested: this is a workspace of ${total} package${total === 1 ? '' : 's'}, and only the root was scanned${shown.length > 0 ? `. Not scanned: ${shown.join(', ')}${more > 0 ? `, and ${more} more` : ''}` : ''}.`);
  }
  return items;
}

/** Directories with a manifest of their own that no scan read (`notScanned`, engine v0.1.21). Paths are the repository's: code spans. */
function notScannedSentence(n, name) {
  const total = whole(n?.total);
  if (!total) return null;
  const listed = (Array.isArray(n.listed) ? n.listed : []).filter((d) => typeof d?.path === 'string').slice(0, MAX_FAILED);
  const names = listed.map((d) => name(oneLine(d.path).slice(0, 200))).join(', ');
  const more = total - listed.length;
  return `**Not scanned:** ${total} director${total === 1 ? 'y has' : 'ies have'} a manifest of ${total === 1 ? 'its' : 'their'} own that this run did not read${names ? `: ${names}${more > 0 ? ` and ${more} more` : ''}` : ''}. This run says nothing about that code.`;
}

/**
 * The job summary's "What this run reached" section, built only from fields the
 * engine wrote. Every path, module name, error and note is the scanned
 * repository's or the engine's text, so each is a code span it cannot close or
 * escaped text on one line.
 */
export function reachSection(result) {
  const name = codeSpan;
  const text = (t, max) => plain(t, max);
  const v = probeVerdicts(result);
  const lines = ['### What this run reached', ''];
  const items = [];
  const w = workspaceReach(result);
  if (w !== null) items.push(packagesSentence(w));
  else items.push(...notTestedItems(result, name, text));
  const skipped = notScannedSentence(result?.notScanned, name);
  if (skipped) items.push(skipped);
  const probes = probesSentence(v);
  if (probes) items.push(probes);
  for (const [label, z] of fuzzRecords(result)) {
    const s = fuzzSentence(label, z);
    if (s) items.push(s);
  }
  const src = sourceLine(result?.fuzz?.reach, name, text);
  if (src) items.push(src);
  const py = result?.python?.reach;
  if (py && typeof py === 'object') {
    const imported = Array.isArray(py.imported) ? py.imported.length : 0;
    items.push(`Python modules: ${imported} imported. ${failedText(Array.isArray(py.failed) ? py.failed : [], name, text)}.`);
  }
  if (typeof result?.note === 'string' && result.note !== '') items.push(`Engine note: ${text(result.note, 300)}`);
  for (const [label, z] of fuzzRecords(result)) {
    if (typeof z.note === 'string' && z.note !== '') items.push(`Engine note on ${label.toLowerCase()}: ${text(z.note, 300)}`);
  }
  const left = Array.isArray(result?.leftBehind) ? result.leftBehind : [];
  for (const dir of left.slice(0, MAX_FAILED)) {
    items.push(`Credda could not delete its temp directory ${name(oneLine(dir).slice(0, 300))}. It holds only Credda's copy of the checkout. Delete it by hand.`);
  }
  if (left.length > MAX_FAILED) items.push(`${left.length - MAX_FAILED} more temp directories were left behind. security.json lists them.`);
  if (items.length === 0) items.push('security.json records nothing about what this run reached.');
  lines.push(...items.map((i) => `- ${i}`), '');
  if (w !== null) lines.push(...workspaceLines(w, name, text));
  const seen = v === null ? [] : VERDICTS.map(([, k]) => k).filter((k) => v[k] > 0);
  if (seen.length > 0) lines.push('What each result means:', '', ...seen.map((k) => `- ${VERDICT_MEANING[k]}`), '');
  return lines;
}

/** One plain line for Slack, from counts only: "Reached: 6 probes (1 clean, 5 abstained); 2 exported functions fuzzed, 638010 calls." */
export function reachSummaryText(result) {
  const v = probeVerdicts(result);
  const parts = [];
  if (v !== null) {
    const by = VERDICTS.map(([, k]) => k).filter((k) => v[k] > 0).map((k) => `${v[k]} ${VERDICT_WORDS[k]}`);
    if (v.other > 0) by.push(`${v.other} other`);
    parts.push(`${v.attempted} probe${v.attempted === 1 ? '' : 's'}${by.length > 0 ? ` (${by.join(', ')})` : ''}`);
  }
  for (const [label, z] of fuzzRecords(result)) {
    const fns = whole(z.functions);
    const calls = whole(z.calls);
    if (fns !== null) parts.push(`${fns} ${label === 'Fuzzing' ? '' : 'Python '}exported function${fns === 1 ? '' : 's'} fuzzed${calls !== null ? `, ${calls} call${calls === 1 ? '' : 's'}` : ''}`);
  }
  const r = result?.fuzz?.reach;
  const files = whole(r?.filesLoaded);
  if (files !== null) parts.push(`${files} source file${files === 1 ? '' : 's'} loaded, ${Array.isArray(r.failed) ? r.failed.length : 0} module${r.failed?.length === 1 ? '' : 's'} failed`);
  return parts.length > 0 ? `Reached: ${parts.join('; ')}.` : '';
}
