<!--
This repository is a launcher, not the engine. It mints an OIDC token, fetches
an artifact, verifies a digest and executes it. The engine itself is elsewhere
and is not public, so a change to what Credda *concludes* cannot start here.

Three things are load-bearing and easy to break by accident:

  engine.lock.json IS THE TRUST ANCHOR. It is committed so that it arrives with
  the tag the caller pinned. A change that reads the expected digest from
  anywhere else — a response header, an environment variable, a default — turns
  a verified download into an unverified one and will be declined.

  NO RELEASE-CRITICAL STRING GETS A SECOND HOME. The audience, the endpoint and
  the version are read from launcher/fetch-engine.mjs and engine.lock.json, in
  the workflow as well as in the code, because a literal in a second place rots
  without anything going red. It already did once; .github/workflows/smoke.yml
  says so at length.

  THE DEFAULT INSTALL GRANTS NO WRITE SCOPE. `open-pull-request` defaults to
  'false' and the "Least privilege" header in action.yml is parsed by
  web/tools/check-install.mjs as the exact set a default install must grant. A
  change to either has to move both, deliberately, and say so.

And the one that is not a matter of degree: Credda does not merge. There is no
merge call on this path and there will not be one.
-->

**What is wrong today.** <!-- The behaviour, not the change. -->

**What this changes.**

**How you know it works.** <!-- The success path needs an OIDC token GitHub signed, so a laptop cannot prove it: say whether `smoke.yml` ran and what it printed. -->

- [ ] No release-critical string gained a literal copy: the audience, the endpoint and the version are still read from the launcher and the lockfile.
- [ ] The digest is still verified against the committed `engine.lock.json` before anything executes.
- [ ] The permission set a default install needs is unchanged, or this pull request changes `action.yml` and `web/tools/check-install.mjs` together and says why.
- [ ] Nothing here merges anything.
- [ ] Comments added here explain *why*, not *what*.
