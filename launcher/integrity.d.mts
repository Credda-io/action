// Types for integrity.mjs.
//
// WHY A HAND-WRITTEN .d.mts AND NOT TYPESCRIPT. This directory ships to a
// customer's runner and runs there with no build step, no loader and no
// dependencies -- that is the property that let the install step disappear, and
// writing it in TypeScript would put a compiler back in front of the one thing
// that must never need one. So the source is `.mjs` and this file exists only
// so the engine repository's test suite, which IS TypeScript, can import it.
//
// These declarations are not checked against the implementation by anything.
// The tests are what check the behaviour.

/** The parsed, validated contents of engine.lock.json. */
export interface Lockfile {
  readonly version: string;
  readonly archiveDigest: string;
  readonly archiveBytes: number | null;
  /** Member name to SHA-256 hex. Doubles as the tar reader's allow-list. */
  readonly files: Record<string, string>;
  readonly entry: string;
}

export function sha256(bytes: Uint8Array): string;
export function verifyDigest(what: string, bytes: Uint8Array, expected: string): string;
export function parseLockfile(text: string): Lockfile;
