// Types for fetch-engine.mjs. See integrity.d.mts for why these are hand-written.

import type { Lockfile } from './integrity.mjs';

/** The OIDC audience the launcher mints for. A test in @credda/metering asserts it matches the Worker's. */
export const ENGINE_AUDIENCE: string;
export const DEFAULT_ENGINE_URL: string;

/** Verifies an archive against `lock` and writes it, or writes nothing at all. Returns the directory. */
export function materialise(archive: Uint8Array, lock: Lockfile, targetDir: string): string;

export function mintIdToken(env?: NodeJS.ProcessEnv, fetchImpl?: typeof fetch): Promise<string>;

export function download(options: {
  endpoint: string;
  version: string;
  licenseKey?: string;
  token: string;
  fetchImpl?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
}): Promise<Buffer>;
