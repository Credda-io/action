// Types for untar.mjs. See integrity.d.mts for why these are hand-written.

/**
 * Unpacks a gzipped tar in memory, refusing any member the allow-list does not
 * name and any tar type that is not a regular file.
 */
export function extract(gz: Uint8Array, allowed: ReadonlySet<string>): Map<string, Buffer>;
