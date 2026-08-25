# Releasing this action

The release procedure lives with the engine, in the private tree, and not here.

## Why it moved

It described how to build and upload the engine artifact: the layout of the
private repository, which of its files matter and why, the R2 bucket the
artifact is served from, and the wrangler commands that put it there. None of
that is a credential and none of it defeats the digest check in
`engine.lock.json` -- the bucket has no public access, and a runner refuses any
archive whose SHA-256 does not match the lockfile committed beside it.

It was still a map of the thing this repository exists to avoid publishing.
Nobody outside the organisation can act on it, because the engine repository is
private, so publishing it bought a reader nothing and cost a description of the
private tree.

**It is in the git history of this repository, so moving it does not unpublish
it.** Removing it from history means rewriting and force-pushing published
commits, which is a separate decision.

## What is public here, and stays public

Everything a person needs to audit what runs in their CI:

- `action.yml`, every input and what it defaults to.
- `run.mjs` and `launcher/`, the whole download-verify-execute path.
- `engine.lock.json`, the digests the launcher checks the engine against.

The engine is fetched, not vendored, and is verified against those digests
before a line of it runs.
