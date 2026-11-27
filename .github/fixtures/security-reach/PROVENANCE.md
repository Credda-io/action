# Where these fixtures came from

Every `security.json` here was written by `credda security`, not by hand.

- `flat-vulnerable.json` and `flat-clean.json`: engine v0.1.17, the released
  archive verified against its lockfile, run through this Action's own `run.mjs`
  with `mode: security`. The checkouts were the `flat` package, version 5.0.2,
  with its `__proto__` guard removed (`flat-vulnerable`) and as published
  (`flat-clean`). Neither has a `fuzz.reach` record, because v0.1.17 does not
  write one.
- `ts-not-loaded.json`, `ts-loaded.json` and `ts-xss.json`: the engine run from
  source in the release-candidate checkout, so `engineVersion` is the CLI
  package's own version (1.2.0), not a release number. The checkout was
  Credda's public TypeScript demo repository, which has no build output.
  `ts-not-loaded` is the engine before it could load TypeScript source: the
  package could not be loaded, every probe of its exports abstained and no
  function was fuzzed. `ts-loaded` is the same repository after that change,
  with a `fuzz.reach` record. `ts-xss` is the same again with
  `CREDDA_XSS_PROBE=1`, and has one proven finding.

Two changes were made after the engine wrote each file, and only these:
absolute paths on the machine that ran it were rewritten to
`/home/runner/work/_temp`, and each finding's `program` (the exploit, 17 KB to
30 KB each) was replaced by a note giving its length.
