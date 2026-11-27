// `fix: true` in security mode: report what `credda security --fix` proved, and
// propose each proven fix through the shared delivery.
//
// WHAT THE ENGINE DOES AND WHAT THIS DOES. The engine asks the customer's own
// model for one patch per proven class, applies it to a temp copy, and runs the
// check-fix gates on it. It writes the verdict under `fixes` in security.json
// and, for FIX_PROVEN only, the patch to `fix-<CLASS>.patch` beside it. This
// file judges nothing. It reads that record, writes it to the job summary, and
// hands each FIX_PROVEN patch to `deliverPullRequest` in `deliver-core.mjs`, the
// same function investigate and sweep push through, with its refusals, its
// no-force-push rule and its "already proposed" check unchanged.
//
// READS NO ENVIRONMENT, for the reason `deliver-core.mjs` gives: `run.mjs` reads
// the inputs in its own step and passes them in.
//
// UNTRUSTED TEXT. A decline reason can be the model's own words and a finding
// sentence names repository code, so neither is written to the summary or the
// pull request body as markdown: sentences go in fenced blocks and short
// reasons are escaped. The patch reaches git as a file the engine wrote, inside
// the output directory this run chose, and nothing in it is executed here.

import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, sep } from 'node:path';

import { deliverPullRequest } from './deliver-core.mjs';
import { branchNameForSecurityFix, pullRequestTitleForSecurityFix } from './delivery.mjs';
import { codeSpan, engineVersionText, plain, pullRequestUrl, securityCounts, siteText } from './findings.mjs';

export { plain };

/** An engine token (a status, class, gate or verdict) as is, or '?' when it is not shaped like one. */
function token(text) {
  return /^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(String(text ?? '')) ? String(text) : '?';
}

/** A fenced block the text cannot close. */
function fenced(text) {
  const body = String(text ?? '');
  const fence = '`'.repeat(Math.max(3, ...(body.match(/`+/g) ?? []).map((run) => run.length + 1)));
  return [`${fence}text`, body, fence];
}

function inside(dir, file) {
  try {
    const rel = relative(realpathSync(dir), realpathSync(file));
    return rel !== '' && rel.split(sep)[0] !== '..' && !isAbsolute(rel);
  } catch {
    return false;
  }
}

/**
 * The FIX_PROVEN attempts this run can hand to delivery, and why any other
 * FIX_PROVEN attempt cannot be. Consistency only: the engine's status is the
 * verdict and is never re-derived. A patch file outside the output directory,
 * missing, empty, different from the patch in security.json, or not paired with
 * a passing exploit gate is a Credda inconsistency, and nothing is proposed.
 *
 * @param {unknown} fixes the `fixes` key of security.json
 * @param {string} outDir the directory `--out` named
 */
export function provenFixes(fixes, outDir) {
  const attempts = Array.isArray(fixes?.attempts) ? fixes.attempts : [];
  const usable = [];
  const broken = [];
  for (const a of attempts) {
    if (a?.status !== 'FIX_PROVEN') continue;
    const why = (() => {
      if (a.verdict !== 'FIX_PROVEN') return 'its check-fix verdict is not FIX_PROVEN';
      const exploit = Array.isArray(a.gates) ? a.gates.find((g) => g?.gate === 'exploit') : undefined;
      if (exploit?.status !== 'PASS') return 'it records no passing exploit gate';
      if (typeof a.patchFile !== 'string' || !existsSync(a.patchFile) || !statSync(a.patchFile).isFile()) return 'its patch file is missing';
      if (!inside(outDir, a.patchFile)) return 'its patch file is outside the output directory';
      const diff = readFileSync(a.patchFile, 'utf8');
      if (diff.trim() === '') return 'its patch file is empty';
      if (typeof a.patch === 'string' && a.patch !== diff) return 'its patch file differs from the patch in security.json';
      return null;
    })();
    if (why === null) usable.push(a);
    else broken.push({ attempt: a, why });
  }
  return { usable, broken };
}

/** The pull request body for one proven fix. */
export function securityFixBody({ attempt, findings, engineVersion, baseBranch, baseSha, runUrl }) {
  const own = findings.filter((f) => (attempt.findings ?? []).includes(f.id));
  const cwe = own.find((f) => /^CWE-[0-9]+$/.test(String(f.cwe)))?.cwe ?? '';
  const lines = [
    `## ${pullRequestTitleForSecurityFix(attempt.class, cwe)}`,
    '',
    `Credda security ran an exploit against ${codeSpan(baseBranch)} at ${plain(baseSha.slice(0, 12), 12)} and it proved ` +
      `${own.length === 1 ? 'this finding' : `these ${String(own.length)} findings`}` +
      `${/^CWE-[0-9]+$/.test(cwe) ? ` (${cwe})` : ''}:`,
    '',
  ];
  for (const f of own) {
    const site = siteText(f.site) || 'at a site the engine did not state';
    lines.push(`- ${plain(f.id, 120)} (${plain(f.cwe, 20)}) ${plain(site, 200)}`, '', ...fenced(String(f.sentence ?? '')), '');
  }
  lines.push(
    'The exploit fired on the code before this patch; that is how the finding was proven. On the patched ' +
      'code the check-fix exploit gate reran it and it did not fire.',
    '',
    'The check-fix gates, as the engine reported them for this patch:',
    '',
    ...fenced([
      `verdict: ${String(attempt.verdict)}. ${String(attempt.reason ?? '')}`,
      ...(attempt.gates ?? []).map((g) => `${String(g.gate)}: ${String(g.status)}. ${String(g.reason ?? '')}`),
      ...(attempt.targetVerdicts ?? []).map((t) => `${String(t.targetId)}: ${String(t.verdict)} (decided by ${(t.decidedBy ?? []).join(', ')})`),
    ].join('\n')),
    '',
  );
  if (Array.isArray(attempt.filesChanged) && attempt.filesChanged.length > 0) {
    lines.push('Files changed:', '', ...fenced(attempt.filesChanged.map(String).join('\n')), '');
  }
  lines.push(
    `Engine: Credda ${engineVersionText(engineVersion) || 'of an unstated version'}.`,
    '',
    'The patch was written by your own model and checked by the gates above. A person should review it before ' +
      'merging. Credda does not merge.',
    '',
    `[Action run](${runUrl()})`,
    '',
  );
  return lines.join('\n');
}

/** The "Fixes" section of the job summary. */
export function fixesSummary({ fixes, usable, broken, delivery, openPullRequest, patchDir, baseRefusal }) {
  const lines = ['### Fixes', ''];
  if (fixes === undefined || fixes === null || typeof fixes !== 'object') {
    lines.push('The engine wrote no fix record, so no fix was attempted. The findings above are unchanged.', '');
    return lines.join('\n');
  }
  if (fixes.modelBacked !== true) {
    lines.push(
      `No fix was attempted: the provider (${plain(fixes.provider, 60)}) is not model-backed and cannot write a patch. ` +
        'To have Credda attempt fixes, pass your own model key: `anthropic-api-key`, or `model-api-key` with ' +
        '`model-base-url`. The findings above are unchanged.',
      '',
    );
    return lines.join('\n');
  }
  const c = fixes.counts ?? {};
  const n = (v) => (Number.isInteger(v) && v >= 0 ? String(v) : '?');
  lines.push(
    `Provider ${plain(fixes.provider, 60)}. ${n(c.proven ?? 0)} proven by the check-fix gates, ` +
      `${n(c.rejected ?? 0)} rejected, ${n(c.notAttempted ?? 0)} not attempted. Only a fix the gates ` +
      'proved is offered as a patch.',
    '',
  );
  const attempts = Array.isArray(fixes.attempts) ? fixes.attempts : [];
  if (attempts.length === 0) lines.push('No finding was proven, so there was nothing to fix.', '');
  for (const a of attempts) {
    const head = `- **${token(a.status)}** ${token(a.class)}${a.language === 'python' ? ', Python' : ''} (${(a.findings ?? []).map((id) => plain(id, 80)).join(', ')})`;
    const gates = (a.gates ?? []).map((g) => `${token(g.gate)} ${token(g.status)}`).join(', ');
    if (a.status === 'FIX_PROVEN') {
      const bad = broken.find((b) => b.attempt === a);
      const d = delivery.get(a);
      let note;
      if (bad !== undefined) note = `Not offered: the engine said FIX_PROVEN but ${bad.why}. This is a Credda failure.`;
      else if (!openPullRequest) {
        note = `The patch is in \`fix-patches\` (${plain(patchDir, 300)}). No pull request was opened: \`open-pull-request\` ` +
          'is off. Set it to `true` and grant `contents: write` and `pull-requests: write` to have one opened.';
      } else if (baseRefusal !== '') note = `No pull request was opened: ${baseRefusal} The patch is in \`fix-patches\`.`;
      else if (d === undefined) note = 'No pull request was attempted.';
      else if (d.outcome === 'opened') note = `Pull request opened${pullRequestUrl(d.url) === '' ? '' : `: ${pullRequestUrl(d.url)}`}. A person should review it before merging.`;
      else if (d.outcome === 'already-proposed') note = `Credda already proposed this fix${pullRequestUrl(d.url) === '' ? '' : `: ${pullRequestUrl(d.url)}`}. This run pushed nothing over it.`;
      else if (d.outcome === 'not-attempted') note = d.message;
      else note = `No pull request was opened. ${d.message} ${plain(d.detail, 400)}`.trim();
      lines.push(`${head}. Gates: ${gates}.`, `  ${note}`, '');
    } else if (a.status === 'FIX_REJECTED') {
      const failed = (a.gates ?? []).filter((g) => g.status === 'FAIL').map((g) => `${token(g.gate)}: ${plain(g.reason, 200)}`);
      const where = a.stoppedAt === 'check-fix' && a.verdict !== undefined
        ? `Stopped at the check-fix gates, verdict ${token(a.verdict)}${failed.length > 0 ? `. Failed: ${failed.join('; ')}` : ''}.`
        : `Stopped at ${a.stoppedAt === undefined ? 'an unnamed step' : token(a.stoppedAt)}.`;
      lines.push(`${head}. ${where}`, `  ${plain(a.reason, 400)}`, '');
    } else {
      lines.push(`${head}. ${plain(a.reason, 400)}`, '');
    }
  }
  return lines.join('\n');
}

/**
 * What delivery did with each FIX_PROVEN attempt, for the Slack, Linear and Jira
 * steps, which run after this step and cannot see its result. Only outcomes the
 * delivery reported: `not-offered` (the attempt failed provenFixes), `patch-only`
 * (no pull request was asked for, or the scanned ref has no branch), or the
 * outcome and URL deliverPullRequest returned.
 */
export function deliveryRecord({ fixes, broken, delivery, openPullRequest, baseRefusal }) {
  const attempts = Array.isArray(fixes?.attempts) ? fixes.attempts : [];
  return attempts.filter((a) => a?.status === 'FIX_PROVEN').map((a) => {
    const d = delivery.get(a);
    const outcome = broken.some((b) => b.attempt === a)
      ? 'not-offered'
      : !openPullRequest || baseRefusal !== ''
        ? 'patch-only'
        : d === undefined ? 'not-attempted' : String(d.outcome);
    return { class: String(a.class), language: String(a.language), outcome, url: outcome === 'opened' || outcome === 'already-proposed' ? String(d?.url ?? '') : '' };
  });
}

/**
 * Writes the proven patches and their bodies to `patchDir`, and, when
 * `openPullRequest` is on and the run scanned a branch, opens one pull request
 * per proven fix through `deliverPullRequest`. Never exits the process.
 *
 * @returns {{ usable: object[], broken: object[], delivery: Map<object, object>, patchDir: string }}
 */
export function deliverSecurityFixes({ result, outDir, patchDir, workspace, repository, baseBranch, baseRefusal, openPullRequest, runUrl }) {
  const { usable, broken } = provenFixes(result.fixes, outDir);
  const delivery = new Map();
  if (usable.length === 0) return { usable, broken, delivery, patchDir: '' };

  const head = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: workspace, encoding: 'utf8' });
  const baseSha = head.status === 0 ? String(head.stdout).trim() : '';
  mkdirSync(patchDir, { recursive: true });
  const { findings } = securityCounts(result);
  const prepared = usable.map((attempt) => {
    const name = `fix-${String(attempt.class).replace(/[^A-Za-z0-9_]/g, '')}${attempt.language === 'python' ? '-python' : ''}`;
    const patchPath = join(patchDir, `${name}.patch`);
    const bodyPath = join(patchDir, `${name}.md`);
    copyFileSync(attempt.patchFile, patchPath);
    writeFileSync(bodyPath, securityFixBody({
      attempt, findings, engineVersion: String(result.engineVersion ?? 'unknown'),
      baseBranch: baseBranch || 'the scanned commit', baseSha: baseSha || 'unknown', runUrl,
    }), 'utf8');
    return { attempt, patchPath, bodyPath };
  });

  if (!openPullRequest || baseRefusal !== '') return { usable, broken, delivery, patchDir };
  if (baseSha === '') {
    for (const p of prepared) {
      delivery.set(p.attempt, { outcome: 'refused', message: 'The workspace is not a git checkout, so no branch could be cut.', detail: '', url: '', forgeRefusal: false });
    }
    return { usable, broken, delivery, patchDir };
  }

  let forgeBlocked = false;
  for (const p of prepared) {
    if (forgeBlocked) {
      delivery.set(p.attempt, {
        outcome: 'not-attempted',
        message: 'Not attempted: GitHub refused an earlier push for a reason that applies to every fix, so the rest were not tried.',
        detail: '', url: '', forgeRefusal: false,
      });
      continue;
    }
    // Each proposal is cut from the scanned commit, never from a previous fix's branch.
    spawnSync('git', ['checkout', '--force', baseSha], { cwd: workspace, encoding: 'utf8' });
    let branch;
    try {
      branch = branchNameForSecurityFix(p.attempt.class, p.attempt.language);
    } catch (error) {
      delivery.set(p.attempt, { outcome: 'refused', message: error.message, detail: '', url: '', forgeRefusal: false });
      continue;
    }
    const cwe = findings.find((f) => (p.attempt.findings ?? []).includes(f.id))?.cwe ?? '';
    // The shared delivery refuses a patch that touches CI, registry
    // configuration or anything outside the repository (`patchRefusal`).
    const decision = deliverPullRequest({
      workspace,
      repository,
      branch,
      patchPath: p.patchPath,
      bodyPath: p.bodyPath,
      commitSubject: pullRequestTitleForSecurityFix(p.attempt.class, cwe),
      commitBody:
        'Written by your own model through Credda and judged FIX_PROVEN by the check-fix gates. The ' +
        'pull request lists each gate as the engine reported it. Credda proposes; a human decides.',
      prTitle: pullRequestTitleForSecurityFix(p.attempt.class, cwe),
      baseBranch,
    });
    delivery.set(p.attempt, decision);
    if (decision.outcome === 'refused') {
      console.log(`::warning::Credda did not open a pull request for the ${String(p.attempt.class)} fix. ${decision.message.split('\n')[0]}`);
      if (decision.forgeRefusal) forgeBlocked = true;
    }
  }
  spawnSync('git', ['checkout', '--force', baseSha], { cwd: workspace, encoding: 'utf8' });
  return { usable, broken, delivery, patchDir };
}
