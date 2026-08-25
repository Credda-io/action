# Cutting a release

**Read this before releasing. `engine.lock.json` is generated, and it is what
every customer runner checks downloaded code against. Nothing in this repository
checks that it is current.**

This repository is a launcher. It contains no engine. `launcher/fetch-engine.mjs`
downloads the engine at run time from CodeReef's own service, verifies it against
the digests in `engine.lock.json`, and unpacks it; only then does `run.mjs` run
anything.

The failure this shape has, stated up front, is the same one the old committed
bundle had and one more:

- **A release that forgets to re-pack ships a stale engine**, and nothing will
  complain. The stale engine runs perfectly, it is just old.
- **A release that uploads a new artifact without shipping the matching
  lockfile, or the other way round, breaks every job at once** with a digest
  mismatch that looks exactly like an attack. The packer writes both in one
  command specifically so this cannot happen by forgetting; it can still happen
  by uploading and not committing, so the order below is not optional.

## What is generated, and from what

| File | Produced from | By |
| --- | --- | --- |
| `engine-dist/bundle/reef.mjs` | `apps/cli/src/main.ts` in the engine repo | `apps/cli/scripts/bundle.mjs` (esbuild) |
| `engine-dist/bundle/Dockerfile` | `packages/workspace/Dockerfile` | the same script |
| `engine-dist/bundle/sql/*.sql` | `packages/db/src/*.sql` | the same script |
| `engine-dist/bundle/metering.mjs` | `packages/metering/src/client.ts` | a separate esbuild invocation, below |
| `engine-dist/build/engine.tar.gz` | all of the above | `engine-dist/pack.mjs` |
| `engine.lock.json` (here) | the same run of the packer | `engine-dist/pack.mjs` |

Everything else here is hand-maintained: `action.yml`, `run.mjs`,
`launcher/*.mjs`, `README.md`, this file, and `package.json` except for its
`version`.

## The procedure

### 1. Build the bundle

From a clean checkout of the engine repository, on the commit being released:

```sh
# The engine bundle, plus the Dockerfile and migrations that ride along.
cd apps/cli && node scripts/bundle.mjs && cd ../..

# The metering client, which the CLI bundle does NOT contain -- it is only ever
# called by run.mjs, so it is unreachable from the CLI entry point and esbuild
# correctly leaves it out.
node node_modules/esbuild/bin/esbuild packages/metering/src/client.ts \
  --bundle --platform=node --format=esm --target=node24 \
  --outfile=/tmp/metering.mjs

# Stage it.
cp apps/cli/dist/reef.mjs    <weave>/engine-dist/bundle/reef.mjs
cp apps/cli/dist/Dockerfile  <weave>/engine-dist/bundle/Dockerfile
rm -rf <weave>/engine-dist/bundle/sql
cp -r apps/cli/dist/sql      <weave>/engine-dist/bundle/sql
cp /tmp/metering.mjs         <weave>/engine-dist/bundle/metering.mjs
```

### 2. Bump `version` in `package.json` here

**Before packing.** The packer refuses to run if `--version` and this field
disagree, because the engine version and the Action version are one number: the
tag a customer pins names both, and `reef --version` and the `actionVersion` on
every metering receipt both read this file. It must match
`/^[A-Za-z0-9._-]{1,32}$/` and must never be a commit SHA -- the metering
protocol rejects SHA-shaped values at the client and again at the server.

### 3. Pack

```sh
node engine-dist/pack.mjs --from engine-dist/bundle --version vX.Y.Z
```

This writes `engine-dist/build/engine.tar.gz`, writes
`engine-dist/build/engine.lock.json`, and copies the lockfile straight into this
repository. It then unpacks its own output through the launcher's real
`materialise()` -- the same digest check, the same hardened tar reader, the same
per-file verification a customer's runner runs -- so a release the launcher
cannot accept fails here rather than in every customer's CI at once.

### 4. Upload the artifact

```sh
wrangler r2 object put codereef-engine/engine/vX.Y.Z/engine.tar.gz \
  --file engine-dist/build/engine.tar.gz --remote
```

The bucket has **no public access and no custom domain**. The only address the
engine has is the authenticated `POST /v1/engine`; a bucket made public would
undo the entire change.

### 5. Commit the lockfile, then tag

`engine.lock.json` and the artifact must ship together. Upload first, commit
second, tag third: a lockfile in a tag whose artifact is not in the bucket yet
fails every job with `unknown-version`, which is diagnosable; an artifact in the
bucket with no tag pointing at it costs nothing.

Then move the floating `v1` tag onto the release.

## Verification, which is not optional

### The engine stands alone

The failure this shape exists to prevent is "the action needs the monorepo".

```sh
# In a scratch directory with no access to the engine checkout:
mkdir standalone && cd standalone
tar xzf <weave>/engine-dist/build/engine.tar.gz
cp <weave>/action-dist/package.json .

node reef.mjs --help        # must print usage
node reef.mjs --version     # must print the version from package.json, NOT
                            # "unknown" -- and note this needs package.json one
                            # directory ABOVE reef.mjs, which is the layout the
                            # launcher creates on a runner
node reef.mjs doctor        # must reach "All checks usable"; the Database line
                            # proves sql/ was found
```

No `pnpm install`, no `npm install`, no `tsx`, no network.

### The launcher refuses what it cannot verify

`core/packages/metering/test/engine.test.ts` covers this and runs in the engine
repository's suite. It uses the **real** committed lockfile and the **real**
packed artifact, so it fails when a release is packed and not re-pinned.

```sh
cd core && ./node_modules/.bin/vitest run --reporter=dot packages/metering
```

At minimum, one manual check per release, because it is the one that matters:
serve the artifact with one byte flipped and confirm the launcher exits 1,
prints both digests, says `NOTHING WAS EXECUTED`, and leaves no engine directory
behind.

### The metering fail-open guarantee still holds

Unchanged from before, and still checked on every release because it is a
guarantee about a customer's build going red:

```sh
CODEREEF_ACTION_ROOT="$PWD" CODEREEF_ENGINE_ROOT="$PWD" CODEREEF_MODE=triage \
CODEREEF_LABEL=codereef CODEREEF_COMMENT=true CODEREEF_METERING_URL='' \
GITHUB_WORKSPACE=/some/checkout GITHUB_EVENT_PATH=./event.json \
GITHUB_OUTPUT=./out.txt GITHUB_STEP_SUMMARY=./summary.md \
RUNNER_TEMP=./tmp GITHUB_REPOSITORY=acme/widget \
GITHUB_REPOSITORY_OWNER=acme GITHUB_ACTOR=someone GITHUB_RUN_ID=1 \
node run.mjs
```

Point `CODEREEF_METERING_URL` at a host that does not resolve for one run and
confirm the run still finishes normally, logging `entitlement unknown`.

Note the distinction that now exists and did not before: **metering fails open,
engine delivery fails closed.** A metering outage is invisible; an engine
outage stops the job. That asymmetry is deliberate -- one is a receipt, the
other is the code.

## Drifts to watch for specifically

- **The OIDC audience.** `ENGINE_AUDIENCE` in `launcher/fetch-engine.mjs` is a
  copy of the constant in `core/packages/metering/src/oidc.ts`, because the
  launcher runs before any CodeReef code exists on the machine and has nothing
  to import it from. A test in that package asserts the two are identical. If
  the audience ever drifts, every job in the fleet gets `wrong-audience` at
  once.
- **`metering-url` default.** `action.yml` here and `DEFAULT_ENDPOINT` in
  `packages/metering/src/client.ts` must agree. The test that used to assert
  this pointed at the engine repo's own `action/action.yml`, which no longer
  ships -- so this is a manual check on every release.
- **The engine's own copy of the action.** If `core/action/` is left behind,
  there are two manifests claiming to be the CodeReef action and only one is
  shipped. Delete it there, or mark it dead.

## NEVER SHIP THE SOURCEMAP

`esbuild` emits `reef.mjs.map` beside the bundle. **Do not stage it into
`engine-dist/bundle/`, and delete it if a build produces one there.**

It is not a debugging convenience, it is the entire private engine. The map
carries `sourcesContent` for **189 complete source files**, among them:

```
packages/agents/src/prompts.ts        the prompting, which is the product
packages/agents/src/roles.ts
packages/engine/src/orchestrator.ts
packages/engine/src/redaction.ts
packages/shared/src/secrets.ts        SECRET_PATTERNS, the scrubbing map
```

The packer archives everything under `--from`, so a map left in the staging
directory would be uploaded and then served to every customer runner. Check on
every sync:

```sh
test ! -e engine-dist/bundle/reef.mjs.map && echo ok || echo 'DELETE IT'
```

Also strip the trailing `//# sourceMappingURL=` comment from `reef.mjs`.

Note what this does NOT fix, so nobody mistakes it for secrecy: `reef.mjs` is
unminified and the agent prompts are plain string literals inside it. Anything
shipped to a customer's runner is readable by that customer, by construction.
Moving it behind an authenticated endpoint stops casual copying, keeps it out of
git history and search, and makes the paid tier enforceable. It does not hide
the code from the people running it, and the README says so in as many words.

## `engine-dist/` is not published

`engine-dist/bundle/` holds the engine in the clear and `engine-dist/build/`
holds the artifact. Neither belongs in any public repository -- that is the whole
thing this arrangement exists to stop. What is published is this directory.
