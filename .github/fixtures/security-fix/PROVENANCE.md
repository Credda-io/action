# Where these fixtures came from

Every `security.json` here was written by the engine, not by hand. Each came
from `credda security --fix`, run through this Action's own `run.mjs` with
`mode: security` and `fix: true`, using an engine built from core commit
`98d91b87` and packed as a local v0.1.18 build. The checkout scanned was
`pre-image/`.

- `heuristic/`: no model key. Every class is `NOT_ATTEMPTED`.
- `model/`: `model-base-url` pointed at a local stand-in for an
  OpenAI-compatible endpoint that returns a fixed answer. For
  `PROTOTYPE_POLLUTION` it returns a guard on `__proto__`, `constructor` and
  `prototype`; every other class it declines. The real check-fix gates judged
  the patch in Docker. `fix-PROTOTYPE_POLLUTION.patch` is the file the engine
  wrote beside the report.
- `broke/`: the same, except the patch makes `unflatten` throw on every nested
  key, which the functional gate rejects.

Two changes were made after the engine wrote each file, and only these:
absolute paths on the machine that ran it were rewritten to
`/home/runner/work/_temp`, and each finding's `program` (the exploit, 60 KB or
more in all) was replaced by a note giving its length.

`pre-image/index.js` is `index.js` from the `flat` package, version 5.0.2, with
its `__proto__` guard removed: the shape that was vulnerable before the upstream
fix. `flat` is BSD-3-Clause, copyright Hugh Kennedy; its licence is
`pre-image/LICENSE`.

No real model wrote any patch here.
