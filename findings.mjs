// How security.json (engine v0.1.17) is read, in one place. run.mjs writes the job
// summary from these, integrations.mjs fills Slack, Linear and Jira from them and
// security-fix.mjs writes the fix pull request body from them, so the summary, a
// tracker issue and a pull request cannot describe one finding two ways.

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
  const version = /^v?\d+\.\d+\.\d+/.test(String(result?.engineVersion ?? '')) ? String(result.engineVersion) : '';
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
