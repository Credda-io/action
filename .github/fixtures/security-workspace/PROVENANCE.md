# Where these fixtures came from

Every `security.json` here was written by `credda security`, not by hand.

The engine was run from source on the `feat/workspace-scan` branch of the
engine repository (core pull request #213), the first engine that scans every
package of a workspace. So `engineVersion` is the CLI package's own version
(1.2.0), not a release number. Each checkout was a local clone of a public
monorepo, scanned at the workspace root with the whole workspace in scope:

- `zod.json`: colinhacks/zod, a workspace of 8 packages declared in
  package.json. 1 exercised.
- `changesets.json`: changesets/changesets, a pnpm workspace of 24 packages.
  10 scanned, 5 exercised, 14 over the cap.
- `material-ui.json`: mui/material-ui, a pnpm workspace of 30 packages. 10
  scanned, 3 exercised, 20 over the cap, and 2 proven findings.

Two changes were made after the engine wrote each file, and only these: the
absolute path of the checkout on the machine that ran it was rewritten to
`/home/runner/work/_temp/<name>`, and each finding's `program` (the exploit)
was replaced by a note giving its length. No source code of those projects is
in these files beyond what the engine itself wrote: file paths, function names,
and the probe sentences.
