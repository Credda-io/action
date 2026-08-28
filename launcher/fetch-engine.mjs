// The launcher: prove which repository is asking, download the engine, verify
// it, put it on disk, and get out of the way.
//
// ## WHY THE ENGINE IS NOT IN THIS REPOSITORY
//
// A public action repository must contain whatever it runs, and this one used
// to: `bundle/reef.mjs` was the compiled engine, 27,957 lines, with every agent
// prompt in it as a plain string literal. Shipping that is shipping the engine
// in public, which is the decision `Credda-io/core` going private reversed.
// Minifying does not help -- the prompt strings survive any transform that
// keeps the program working.
//
// So the engine moved behind an authenticated endpoint and this repository kept
// only the launcher. That is what makes `uses: Credda-io/action@v1`
// work for an outsider again, and what makes a Marketplace listing possible,
// since a listing reads `action.yml` at the repository ROOT and nowhere else.
//
// ## HOW A JOB PROVES IT MAY HAVE THE ENGINE
//
// GitHub Actions OIDC. A job with `id-token: write` asks GitHub for a
// short-lived JWT whose claims GitHub signs: which repository is running, who
// owns it, whether it is public or private. Credda's Worker checks that
// signature against GitHub's published keys and reads the claims.
//
// The alternatives were considered and are worse. A shared download token
// distributed with the licence is a bearer secret that sits in a workflow file
// and leaks on the first gist. A private container image on GHCR needs a pull
// credential granted per user or org, which does not scale past a handful of
// customers and is the same leakable secret in a different wrapper. OIDC
// distributes nothing: there is no credential to leak because there is no
// credential.
//
// ## THE COST, WHICH IS REAL AND IS NOT BURIED
//
// The calling workflow now needs `id-token: write` on top of `contents: read`
// and `issues: write`. The site advertises the minimal permission set as a
// feature, and this is a regression in that story. It is stated in README.md
// under its own heading, in action.yml, and in the error message a job gets
// when the permission is missing -- because the first time most people will
// read about it is in a red job, and that message is where the fix has to be.
//
// `id-token: write` grants the job the ability to MINT a token that identifies
// it. It grants no access to anything of the customer's; it is not a write
// permission on any repository content, and a token minted for Credda's
// audience is useless anywhere else.
//
// ## WHAT BREAKS WHEN CREDDA IS DOWN
//
// The job does not start. Before this change nothing Credda operated could
// stop a customer's run; now our Worker, our bucket and GitHub's OIDC provider
// are all in front of every job. That was accepted deliberately as the price of
// making the engine private, and the only thing that makes it survivable in
// practice is that the failure says so: every message below names its own cause
// so that nobody spends an afternoon debugging their own repository over our
// outage.
//
// A customer who cannot tolerate that dependency has one supported way out --
// `engine-archive`, below -- which mirrors the artifact into their own storage
// and verifies it against the identical digest.
//
// ## THE ONE THING THIS FILE MUST NEVER GET WRONG
//
// It downloads code and the next step executes it inside the customer's
// checkout, in a job holding their GITHUB_TOKEN. Every byte is verified against
// a SHA-256 digest committed in THIS repository before anything is written to
// disk, and again per-file after unpacking. There is no flag that skips it. See
// integrity.mjs, which is deliberately a separate, short, directly tested file.

import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { appendFileSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseLockfile, verifyDigest } from './integrity.mjs';
import { extract } from './untar.mjs';

/**
 * The audience the token is minted for, and the same string the Worker
 * requires.
 *
 * A copy rather than an import, and that is not laziness: this file runs before
 * any Credda code exists on the machine, so there is nothing to import it
 * from. A test in `@credda/metering` asserts the two are identical, which is
 * how a copy stays honest.
 *
 * The audience is what stops a token this job already minted for AWS or Vault
 * from opening Credda's endpoint, and stops one minted here from opening
 * theirs.
 *
 * ## WHY THIS MOVED, AND WHAT WAS CHECKED BEFORE IT DID
 *
 * This value changed from `https://metering.codereef.app/v1/engine` to the
 * `backend.credda.io` string below. That is the single most breakable edit in this
 * repository: if the verifier does not accept what this asks GitHub to mint,
 * every job in the fleet fails at the fetch step with `wrong-audience` -- for
 * customers who did nothing but run the workflow they already had, on a tag
 * they pinned and cannot un-pin retroactively.
 *
 * So it was gated on reading the verifier rather than on anybody's assurance.
 * As of 2026-08-27, `core/packages/metering/src/oidc.ts` declares
 *
 *     export const ACCEPTED_ENGINE_AUDIENCES = [
 *       'https://backend.credda.io/v1/engine',        // ENGINE_AUDIENCE_CREDDA
 *       'https://metering.codereef.app/v1/engine' // ENGINE_AUDIENCE_LEGACY
 *     ];
 *
 * and `verifyActionsToken` defaults its comparison to that whole set, matching
 * a token whose `aud` equals ANY member. Both the new and the old string are
 * accepted, so the two sides are no longer required to move in one instant.
 * That set is what makes this edit survivable; without it this constant would
 * have had to stay on the old value.
 *
 * ## THE ORDER, WHICH IS NOT SYMMETRIC
 *
 * THE WORKER DEPLOYS FIRST. ALWAYS. The verifier is the side that has to
 * already accept a value before the launcher may start sending it, and a
 * merged diff is not a deployed Worker. The dual-accept above exists in
 * SOURCE; until it is released to the Worker that actually answers
 * `/v1/engine`, the deployed verifier may still be the one-string version, and
 * a tag cut from this file would fail every install against it.
 *
 * The sequence, therefore: (1) the dual-accept Worker is deployed; (2) that is
 * confirmed against the running service, not the repository; (3) a tag
 * carrying this file is published; (4) the legacy audience is retired only
 * once no supported pin still requests it -- `oidc.ts` states the three
 * conditions for that, and pinned older tags are the one that takes longest.
 *
 * One companion constant tracks this one: `ENGINE_AUDIENCE` in `oidc.ts`,
 * documented there as "whatever the launcher requests TODAY". The drift test
 * at the bottom of `core/packages/metering/test/engine.test.ts` asserts it
 * equals this constant, and it has been moved to `ENGINE_AUDIENCE_CREDDA` to
 * match. It is bookkeeping, not the verifier's rule -- `ACCEPTED_ENGINE_AUDIENCES`
 * is -- so it records the state of the world rather than enforcing it. If this
 * constant is ever changed again, that one changes with it or the drift test
 * reddens, which is precisely what it is for.
 */
export const ENGINE_AUDIENCE = 'https://backend.credda.io/v1/engine';

/**
 * Where the engine is fetched from unless `engine-url` says otherwise.
 *
 * Still on `codereef.app`, and DELIBERATELY not moved with the audience above.
 * The two look like the same rename and are not.
 *
 * The audience is a string compared against a set the verifier already accepts,
 * so moving it is safe the moment that set is deployed. This is a URL that must
 * ANSWER, and today it does not.
 *
 * Its home is `https://backend.credda.io/v1/engine`. The metering service has
 * been ported out of the Cloudflare Worker and into the Express backend that
 * already serves that hostname.
 *
 * THE PRECONDITION THIS PARAGRAPH SET HAS NOW BEEN MET, AND THE OLD
 * MEASUREMENT IS SUPERSEDED. It read: "it is not deployed, and nginx does not
 * yet pass `/v1/*` to it. Measured rather than assumed: `POST
 * https://backend.credda.io/v1/engine` answers 404 today." That was true when
 * written and is not true now. Re-measured 2026-08-28:
 *
 *     POST https://backend.credda.io/v1/engine   (content-type json, body {})
 *       -> 401, Server: nginx, and the METERING HANDLER'S OWN BODY:
 *          {"ok":false,"error":"engine_unavailable","reason":"missing",
 *           "message":"No GitHub OIDC token was presented. ... see the Credda README."}
 *
 *     POST https://backend.credda.io/v1/definitely-not-a-route
 *       -> 404
 *
 * The control is what makes this evidence rather than a hopeful reading: a 404
 * on a neighbouring path on the same host proves the 401 is a handler
 * answering, not a catch-all. nginx passes `/v1/*` and the Express port is
 * live. The test this paragraph named -- reached versus not reached -- is
 * satisfied, and satisfied more strongly than the 400 it asked for.
 *
 * THE CONSTANT STILL DOES NOT MOVE IN THIS COMMIT, AND THE REASON IS NO LONGER
 * THE ENDPOINT. Moving it means cutting a tag, and the deploy order below is
 * not symmetric. What is unverified is the other half: the published `v1` tag
 * requests the LEGACY audience (`metering.codereef.app/v1/engine`) and fetches
 * from the legacy host, so the fleet is self-consistent and working today. The
 * audience move above exists only on this branch, unreleased. Before any tag
 * carrying it is published, the DEPLOYED verifier on whichever host the fetch
 * targets must be confirmed to accept `https://backend.credda.io/v1/engine` --
 * against the running service, not the repository. That cannot be checked
 * without minting a GitHub OIDC token, so it is a release step and not a
 * reading exercise.
 *
 * The standing risk while this stays on the legacy value: every install in the
 * fleet fetches its engine from a Cloudflare Worker that the port exists to
 * retire. Turning that Worker off breaks every install at the one step that
 * genuinely stops a customer's build. This is now a sequencing decision rather
 * than a blocked one.
 */
export const DEFAULT_ENGINE_URL = 'https://metering.codereef.app/v1/engine';

/** Largest archive accepted, in bytes. The real one is about a megabyte. */
const MAX_ARCHIVE_BYTES = 32 * 1024 * 1024;

/** Per-attempt timeout for the download, in milliseconds. */
const REQUEST_TIMEOUT_MS = 60_000;

/** How many times a transient failure is retried. Refusals are never retried. */
const ATTEMPTS = 3;

const here = dirname(fileURLToPath(import.meta.url));
const actionRoot = resolve(here, '..');

/**
 * The one way this file ends badly.
 *
 * It sets `exitCode` and THROWS rather than calling `process.exit()`, and the
 * difference is not stylistic. `process.exit()` tears the process down while
 * the HTTP client still holds open handles, which on Windows trips an assertion
 * inside libuv -- so the job would fail (correctly, fail-closed) but report the
 * crash code 0xC0000409 instead of 1, and "Credda crashed" is a different and
 * much worse thing to read in a log than "Credda refused". Setting the code
 * and unwinding lets the runtime close its own handles and exit 1.
 *
 * Everything a caller needs is on the FIRST line, because `::error::` takes one
 * line into the job's annotation list, and that list is where somebody looks
 * before they open the log at all.
 */
class LauncherFailure extends Error {}

function fail(message) {
  console.log(`::error::${message.split('\n')[0]}`);
  console.error(message);
  process.exitCode = 1;
  throw new LauncherFailure(message);
}

/* ------------------------------ the OIDC token ----------------------------- */

/**
 * Mints a GitHub Actions OIDC token for Credda's audience.
 *
 * The two environment variables are injected by the runner ONLY when the job
 * declares `id-token: write`, so their absence has exactly one cause and the
 * message says it rather than describing the symptom.
 *
 * `ACTIONS_ID_TOKEN_REQUEST_TOKEN` is a credential belonging to the runner. It
 * is used here and nowhere else, is never written to a file, never logged, and
 * never sent anywhere except the URL the runner itself supplied.
 */
export async function mintIdToken(env = process.env, fetchImpl = fetch) {
  const url = env['ACTIONS_ID_TOKEN_REQUEST_URL'];
  const runnerToken = env['ACTIONS_ID_TOKEN_REQUEST_TOKEN'];
  if (!url || !runnerToken) {
    throw new Error(
      'Credda could not mint a GitHub OIDC token, because this job was not granted permission to.\n' +
        'Add `id-token: write` to the workflow job:\n\n' +
        '    permissions:\n' +
        '      contents: read\n' +
        '      issues: write\n' +
        '      id-token: write\n\n' +
        'Credda needs it to prove to its own service which repository is asking for the engine. ' +
        'It grants the job no access to anything of yours. See the Credda README, "Why id-token: write".',
    );
  }

  const request = new URL(url);
  request.searchParams.set('audience', ENGINE_AUDIENCE);

  const response = await fetchImpl(request.toString(), {
    headers: { authorization: `Bearer ${runnerToken}`, accept: 'application/json' },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(
      `GitHub's OIDC provider answered ${response.status} when Credda asked it for a token. ` +
        'This is between the runner and GitHub; it is not a problem with your repository. Re-running the job usually clears it.',
    );
  }
  const body = await response.json();
  const value = body?.value;
  if (typeof value !== 'string' || value === '') {
    throw new Error("GitHub's OIDC provider returned no token value. Re-running the job usually clears it.");
  }
  return value;
}

/* ------------------------------ the download ------------------------------ */

/** Whether a status is worth retrying. A refusal never is; re-asking cannot change the answer. */
function transient(status) {
  return status === 408 || status === 429 || status >= 500;
}

/**
 * Downloads the engine archive, returning its bytes.
 *
 * A refusal is turned into the sentence the server sent. That sentence is
 * written on the server precisely so that this file does not have to guess
 * which of a dozen causes applied -- expired licence, wrong organisation, our
 * database down -- and so that the answer a customer reads is the one the
 * service actually decided.
 */
export async function download({ endpoint, version, licenseKey, token, fetchImpl = fetch, sleep }) {
  const wait = sleep ?? ((ms) => new Promise((done) => setTimeout(done, ms)));
  let lastTransient = null;

  for (let attempt = 1; attempt <= ATTEMPTS; attempt += 1) {
    let response;
    try {
      response = await fetchImpl(endpoint, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          accept: 'application/octet-stream',
        },
        body: JSON.stringify({
          v: 1,
          version,
          ...(licenseKey ? { licenseKey } : {}),
        }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (error) {
      lastTransient =
        `Credda could not reach its engine service at ${endpoint} (${error.message}). ` +
        'This is an outage on our side or a network problem on the runner, not a problem with your repository.';
      if (attempt < ATTEMPTS) {
        await wait(attempt * 2000);
        continue;
      }
      throw new Error(lastTransient);
    }

    if (response.ok) {
      const bytes = Buffer.from(await response.arrayBuffer());
      if (bytes.length === 0) throw new Error('Credda received an empty engine archive.');
      if (bytes.length > MAX_ARCHIVE_BYTES) {
        throw new Error(
          `Credda received an engine archive of ${bytes.length} bytes, past the ${MAX_ARCHIVE_BYTES} byte ceiling this launcher accepts.`,
        );
      }
      return bytes;
    }

    // A refusal carries a `message` written for a human. Read it if it is
    // there; never invent one on top of it.
    let served = '';
    try {
      const problem = await response.json();
      if (typeof problem?.message === 'string') served = problem.message;
      if (typeof problem?.checkoutUrl === 'string' && response.status === 402) {
        served += `\nPlans and the seat definition: ${problem.checkoutUrl}`;
      }
    } catch {
      /* a body that is not JSON tells us nothing; the status still does */
    }

    if (transient(response.status) && attempt < ATTEMPTS) {
      lastTransient = served;
      await wait(attempt * 2000);
      continue;
    }

    throw new Error(
      served !== ''
        ? `Credda could not start: ${served}`
        : `Credda's engine service answered ${response.status} and said nothing readable. ` +
          'This is an outage on our side, not a problem with your repository.',
    );
  }

  throw new Error(lastTransient ?? 'Credda could not download its engine.');
}

/* ------------------------------ the integrity ----------------------------- */

/**
 * Verifies an archive and writes its contents, or writes nothing at all.
 *
 * THE ORDER HERE IS THE WHOLE SECURITY PROPERTY, so it is stated rather than
 * left to be inferred from the sequence of statements:
 *
 *   1. The archive as a whole is hashed and compared to the digest committed in
 *      this repository. A mismatch throws before a single byte touches disk.
 *   2. It is unpacked IN MEMORY, through a reader that can only produce members
 *      the lockfile already named (see untar.mjs).
 *   3. Every member is hashed and compared to its own pinned digest. A
 *      mismatch throws, still before anything is written.
 *   4. Only then is the directory created and the files written.
 *
 * Step 3 is not redundant given step 1. Step 1 proves the archive is the one
 * this release was built against; step 3 is what makes a bug in the unpacker --
 * an off-by-one that splices two members, say -- fail closed rather than
 * produce a file nobody checked. They are cheap and they fail differently.
 *
 * If any write fails partway, the directory is removed. A half-written engine
 * directory is the one state that could let a later run find files that were
 * never verified together.
 */
export function materialise(archive, lock, targetDir) {
  verifyDigest('the Credda engine archive', archive, lock.archiveDigest);

  const members = extract(archive, new Set(Object.keys(lock.files)));

  for (const [name, bytes] of members) {
    verifyDigest(`the Credda engine file '${name}'`, bytes, lock.files[name]);
  }

  const root = resolve(targetDir);
  try {
    rmSync(root, { recursive: true, force: true });
    mkdirSync(root, { recursive: true });
    for (const [name, bytes] of members) {
      const destination = resolve(root, name);
      // Belt and braces. The names came from the lockfile, which is in git, and
      // the allow-list already refused everything else -- but a path check next
      // to a filesystem write costs one line and does not depend on a property
      // established two files away staying true.
      if (destination !== root && !destination.startsWith(root + sep)) {
        throw new Error(`engine.lock.json names '${name}', which resolves outside the engine directory.`);
      }
      mkdirSync(dirname(destination), { recursive: true });
      writeFileSync(destination, bytes);
    }
  } catch (error) {
    rmSync(root, { recursive: true, force: true });
    throw error;
  }

  return root;
}

/* --------------------------------- the job -------------------------------- */

function output(name, value) {
  const file = process.env['GITHUB_OUTPUT'];
  if (file) appendFileSync(file, `${name}=${value}\n`, 'utf8');
}

async function main() {
  const lock = parseLockfile(readFileSync(join(actionRoot, 'engine.lock.json'), 'utf8'));

  /*
   * The unpacked layout reproduces the one the action used to ship, and that is
   * deliberate rather than incidental.
   *
   *   <engineRoot>/package.json     copied from this repository
   *   <engineRoot>/bundle/reef.mjs  the engine, plus its Dockerfile and sql/
   *
   * `reef.mjs` answers `credda --version` by reading
   * `new URL('../package.json', import.meta.url)`, and it locates the sandbox
   * Dockerfile and the migrations by probing its own directory. Unpacking the
   * members straight into a flat directory would have made `credda --version`
   * print "unknown" -- which is also the value that goes onto every metering
   * receipt as `actionVersion`, so the whole fleet's receipts would have become
   * indistinguishable from each other, silently, with nothing failing.
   *
   * The package.json is COPIED from this repository rather than carried in the
   * archive, because it is the launcher's own manifest: it is in git, it
   * arrived with the tag the customer pinned, and putting it in the downloaded
   * artifact would mean the version string a receipt reports came from the
   * server instead of from the customer's own checkout of the action.
   */
  const engineRoot = join(process.env['RUNNER_TEMP'] ?? actionRoot, 'credda-engine', lock.version);
  const engineDir = join(engineRoot, 'bundle');

  /*
   * The mirror. A customer who cannot accept a hard runtime dependency on our
   * infrastructure points `engine-archive` at a copy of the same `.tar.gz` on
   * storage they control, and no request is made to Credda at all.
   *
   * This weakens NOTHING, which is the only reason it exists: a mirrored
   * archive goes through the identical digest check against the identical
   * lockfile, so the escape hatch cannot be used to run unverified code. It is
   * an availability escape hatch, not an integrity one, and there is no
   * integrity one.
   */
  const mirror = (process.env['CREDDA_ENGINE_ARCHIVE'] ?? '').trim();
  let archive;
  if (mirror !== '') {
    console.log(`Reading the Credda engine ${lock.version} from ${mirror} (no request to Credda).`);
    try {
      archive = readFileSync(mirror);
    } catch (error) {
      fail(
        `Credda could not read the mirrored engine archive at ${mirror}: ${error.message}\n` +
          'engine-archive is set, so no download was attempted.',
      );
    }
  } else {
    const endpoint = (process.env['CREDDA_ENGINE_URL'] ?? DEFAULT_ENGINE_URL).trim();
    if (endpoint === '') {
      fail(
        'engine-url is empty and engine-archive is not set, so Credda has no way to obtain its engine.',
      );
    }

    let token;
    try {
      token = await mintIdToken();
    } catch (error) {
      fail(error.message);
    }

    console.log(`Fetching the Credda engine ${lock.version} from ${endpoint}.`);
    try {
      archive = await download({
        endpoint,
        version: lock.version,
        licenseKey: (process.env['CREDDA_LICENSE'] ?? '').trim(),
        token,
      });
    } catch (error) {
      fail(error.message);
    }
  }

  try {
    rmSync(engineRoot, { recursive: true, force: true });
    materialise(archive, lock, engineDir);
    writeFileSync(
      join(engineRoot, 'package.json'),
      readFileSync(join(actionRoot, 'package.json')),
    );
  } catch (error) {
    rmSync(engineRoot, { recursive: true, force: true });
    fail(error.message);
  }

  console.log(
    `Engine ${lock.version} verified against engine.lock.json (sha256 ${lock.archiveDigest}) and unpacked to ${engineRoot}.`,
  );
  output('engine-root', engineRoot);
  output('engine-version', lock.version);
}

// Run only when executed, so the tests can import `materialise` and `download`
// without the file trying to mint a token.
if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  try {
    await main();
  } catch (error) {
    // `fail()` has already said everything there is to say and set the exit
    // code. Anything else reaching here is a bug in this file rather than a
    // refusal, and is reported as one -- with the same guarantee either way,
    // which is that a launcher that did not finish leaves no engine directory
    // behind for the next step to find.
    if (!(error instanceof LauncherFailure)) {
      console.log(`::error::Credda's launcher failed unexpectedly: ${error.message}`);
      console.error(error);
      process.exitCode = 1;
    }
  }
}
