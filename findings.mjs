// How security.json (engine v0.1.17) is read, in one place. run.mjs writes the job
// summary from these and integrations.mjs fills Slack, Linear and Jira from them,
// so the summary and a tracker issue cannot describe one finding two ways.

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
