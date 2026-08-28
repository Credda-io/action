// SHA-256, and the comparison that decides whether downloaded code is allowed
// to run.
//
// WHY THIS IS ITS OWN FILE. Everything else in this launcher is plumbing --
// read an environment variable, make a request, write a directory. This file is
// the security boundary of the entire product: Credda downloads code over the
// network and executes it inside a customer's repository checkout, in a job
// that holds their GITHUB_TOKEN. If an attacker can substitute those bytes,
// they have arbitrary code execution in every repository that installed us,
// with a token that can read the code and write to the issue tracker. There is
// no worse thing that can happen to this company, so the check is isolated,
// short enough to read in one sitting, and tested directly.
//
// THE TRUST ANCHOR IS THE LOCKFILE, NOT THE SERVER. `engine.lock.json` is
// committed to the public launcher repository, so the digest a runner checks
// against arrived over the same channel as the launcher itself -- git, over a
// tag the customer pinned. The server's own reply is not consulted for the
// decision, and the response header that names a version is diagnostic only.
// That is what makes a compromise of the delivery path survivable: an attacker
// who owns the Worker, the bucket, or the network between them can stop a job,
// which is a nuisance, but cannot make one execute bytes the launcher's own
// repository did not already name.
//
// FAIL CLOSED, ALWAYS. Every function here either returns a verified value or
// throws. There is no flag that skips verification, no environment variable
// that turns it off and no branch where an unverified byte reaches the disk.
// A mirror is supported (see fetch-engine.mjs) precisely because it does not
// need one: a mirrored archive is checked against the same digest as a
// downloaded one.

import { createHash, timingSafeEqual } from 'node:crypto';

/** SHA-256 of a buffer, as lowercase hex. */
export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

const HEX_64 = /^[0-9a-f]{64}$/;

/**
 * Throws unless `bytes` hashes to `expected`.
 *
 * `what` names the thing being checked and appears verbatim in the error, so a
 * customer reading a red job sees which artifact failed rather than a digest
 * mismatch with no subject.
 *
 * The expected digest is itself validated for shape. A lockfile whose digest
 * field was empty, or truncated, or the string "TODO", would otherwise compare
 * equal to nothing and reject everything -- which is at least fail-closed -- or
 * worse, be silently coerced somewhere upstream. Refusing an unusable expected
 * value with its own message is how that stays diagnosable instead of looking
 * like a supply-chain attack.
 */
export function verifyDigest(what, bytes, expected) {
  if (typeof expected !== 'string' || !HEX_64.test(expected)) {
    throw new Error(
      `Credda cannot verify ${what}: engine.lock.json does not carry a SHA-256 digest for it. ` +
        'This is a broken Credda release, not a problem with your repository. Nothing was executed.',
    );
  }

  const actual = sha256(bytes);
  // The digests are public values and a timing attack on them buys nothing, so
  // this is not load-bearing. It costs one line and removes the need for the
  // next reader to work that out for themselves.
  const equal =
    actual.length === expected.length &&
    timingSafeEqual(Buffer.from(actual, 'utf8'), Buffer.from(expected, 'utf8'));

  if (!equal) {
    throw new Error(
      `Credda refused to run: ${what} does not match the digest pinned in this action's ` +
        `engine.lock.json.\n  expected sha256 ${expected}\n  received sha256 ${actual}\n` +
        'The download was discarded and NOTHING WAS EXECUTED. This means the bytes served did not ' +
        'match the bytes this release of the action was built against -- either a corrupted ' +
        'download, or a tampered one. Re-run the job; if it fails again, report it and do not ' +
        'work around it.',
    );
  }
  return actual;
}

/**
 * The lockfile, parsed and checked for the fields the launcher depends on.
 *
 * Validated rather than trusted, even though it ships in the same repository as
 * this file, because "the lockfile is committed" is a claim about a build
 * process and this is the one place that can turn a mistake in that process
 * into executed code. A release cut with a placeholder digest should fail on
 * the first job, loudly, naming the lockfile.
 */
export function parseLockfile(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`engine.lock.json is not valid JSON: ${error.message}`);
  }
  const version = parsed?.version;
  const archiveDigest = parsed?.archive?.sha256;
  const files = parsed?.files;

  if (typeof version !== 'string' || !/^v[0-9]+\.[0-9]+\.[0-9]+$/.test(version)) {
    throw new Error('engine.lock.json does not name an engine version of the form vX.Y.Z.');
  }
  if (typeof archiveDigest !== 'string' || !HEX_64.test(archiveDigest)) {
    throw new Error('engine.lock.json does not carry a SHA-256 digest for the engine archive.');
  }
  if (typeof files !== 'object' || files === null || Array.isArray(files)) {
    throw new Error('engine.lock.json does not carry a per-file digest map.');
  }
  const entries = Object.entries(files);
  if (entries.length === 0) {
    throw new Error('engine.lock.json lists no files, so there is nothing an archive could be checked against.');
  }
  for (const [name, digest] of entries) {
    if (typeof digest !== 'string' || !HEX_64.test(digest)) {
      throw new Error(`engine.lock.json has no valid SHA-256 digest for '${name}'.`);
    }
  }

  // The archive is only as trustworthy as the weakest thing the launcher will
  // execute out of it, so the entry point has to be one of the pinned files
  // rather than whatever happens to be in the tarball.
  const entry = typeof parsed.entry === 'string' ? parsed.entry : 'reef.mjs';
  if (!Object.hasOwn(files, entry)) {
    throw new Error(`engine.lock.json names '${entry}' as the engine entry point but does not pin its digest.`);
  }

  return {
    version,
    archiveDigest,
    archiveBytes: typeof parsed.archive?.bytes === 'number' ? parsed.archive.bytes : null,
    files: Object.fromEntries(entries),
    entry,
  };
}
