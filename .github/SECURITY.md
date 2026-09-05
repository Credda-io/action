# Security

## Reporting a vulnerability

Use **GitHub's private vulnerability reporting** on this repository: the
Security tab, then "Report a vulnerability". That opens a private advisory
visible to the maintainers and to you, and nowhere else.

Please do not open a public issue for something exploitable, and please do not
wait for us to be ready before you tell us.

What helps, in rough order:

- what an attacker gets, stated first
- the smallest input that demonstrates it
- the tag or commit SHA you had pinned

If you would rather not use GitHub, [credda.io](https://credda.io) has the
contact details.

## What this action is, and therefore what its attack surface is

**This action downloads code and runs it on your runner.** That is the sentence
everything else here is about, and it is worth stating before any reassurance.

`launcher/fetch-engine.mjs` mints a GitHub OIDC token, presents it to Credda's
service, downloads the engine, verifies it against the SHA-256 digest pinned in
`engine.lock.json`, and unpacks it. Only then does `run.mjs` execute anything.

- **The trust anchor is committed here, not served.** `engine.lock.json` is in
  this repository, so it arrives with the tag or SHA *you* pinned rather than
  from the server that answers the request. A server that serves different bytes
  fails the digest check on your runner and the job stops. **If you ever see a
  digest mismatch, do not work around it — report it privately.** That is the
  single highest-severity report this repository can receive.
- **`@v1` is a moving tag with no published Release behind it.** Pinning it
  means accepting whatever it points at later. Pin a commit SHA if that is not
  a trade you want to make. This is a real property of the current setup, not a
  recommendation to ignore.
- **What runs on your runner runs with your token.** The default install grants
  `contents: read`, `issues: write` and `id-token: write`, and holds a token
  that cannot write to your repository. `open-pull-request` is opt-in and off by
  default; turning it on requires **you** to add `contents: write` and
  `pull-requests: write` to your own workflow's permission block. Credda supplies
  no credential to any of it — the push and the pull request are made by your own
  job. Read the diff before granting `contents: write` to anything: a workflow
  that can write to contents can write to `main`.
- **Credda never merges.** There is no merge call, no auto-merge, no approval and
  no branch-protection bypass on this path, and a test fails if one appears. A
  pull request is a claim made to a human.
- **The engine reads attacker-chosen text.** Issue bodies are written by whoever
  can open an issue, and the `investigate` job checks your repository out and
  executes code in a Docker sandbox. `sandbox: docker` is the only isolated plane
  and it refuses to fall back to the host, by design. **A path that escapes that
  sandbox, or that lets issue text steer the run into a privileged operation, is
  a vulnerability and it is the second thing to report.**

## What is not a vulnerability here

An issue body containing a prompt-injection payload, on its own. The engine reads
untrusted text as its whole job; that a payload *arrives* is expected. What it
manages to make the run *do* — write outside the sandbox, reach the runner's
token, exfiltrate a secret, open a proposal from a run that proved nothing — is
the report.

## Supported versions

The `v1` tag, and whatever `engine.lock.json` on it pins. Fixes go to the default
branch and to a new tag rather than to a branch per version.
