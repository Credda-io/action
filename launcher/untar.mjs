// A tar reader that can only produce the files a manifest already named.
//
// WHY NOT `tar -xzf`. Shelling out to the runner's tar would hand a general
// purpose extractor an archive that arrived over the network, and general
// purpose extractors are general: they follow symlinks, honour absolute paths,
// create device nodes, and have a twenty-year history of path traversal bugs
// with names (Zip Slip, and every tar analogue of it). The archive this reads
// contains a fixed, known set of regular files. Writing eighty lines that can
// express exactly that -- and cannot express anything else -- is a smaller
// attack surface than configuring a tool that can express everything.
//
// THE MANIFEST IS AN ALLOW-LIST, NOT A CHECKLIST. Every entry's name must
// already be a key in `engine.lock.json`. An archive carrying an extra file
// does not get it written and ignored; it is refused outright, because "the
// server sent us a file our release never heard of" is not a condition to
// recover from quietly. Combined with the archive digest check that runs before
// this function is ever called, the effect is that the set of paths this can
// write is fixed at release time by a file in git.
//
// WHAT IS REFUSED, AND WHY EACH ONE IS SPELLED OUT. Symlinks and hardlinks
// (typeflag 1, 2) are the classic escape: extract a link named `x` pointing at
// `/etc/cron.d`, then extract a regular file named `x`, and the write lands
// outside the directory. Character and block devices, FIFOs and contiguous
// files (3, 4, 6, 7) have no business in an archive of JavaScript. GNU and pax
// extension headers (L, K, x, g) exist to carry names longer than the 100-byte
// field and are how long-name handling bugs happen; the packer emits none, so
// encountering one means the archive is not the one we built.

import { gunzipSync } from 'node:zlib';

const BLOCK = 512;

/** Reads a NUL-terminated ASCII field. */
function field(block, offset, length) {
  const slice = block.subarray(offset, offset + length);
  const end = slice.indexOf(0);
  return slice.subarray(0, end === -1 ? slice.length : end).toString('ascii').trim();
}

/** Reads a tar octal numeric field. Empty means zero, which is what the size field of a directory is. */
function octal(block, offset, length) {
  const text = field(block, offset, length);
  if (text === '') return 0;
  const value = Number.parseInt(text, 8);
  if (!Number.isInteger(value) || value < 0) return null;
  return value;
}

/**
 * The header checksum, which tar computes over the header with the checksum
 * field itself replaced by spaces.
 *
 * This is not a security control -- it is a sum, and anybody rewriting a header
 * can fix it -- and it is checked anyway because it is what distinguishes "this
 * is a tar header" from "this is 512 bytes of something else" without guessing.
 * The security control is the digest check that already passed before this file
 * ran, plus the allow-list below.
 */
function checksumOk(block) {
  const stated = octal(block, 148, 8);
  if (stated === null) return false;
  let unsigned = 0;
  for (let i = 0; i < BLOCK; i += 1) {
    unsigned += i >= 148 && i < 156 ? 0x20 : block[i];
  }
  return unsigned === stated;
}

/**
 * Extracts a gzipped tar into a map of name to Buffer.
 *
 * Nothing is written to disk here. The caller verifies each file against the
 * lockfile's per-file digest and only then writes, so a tampered member cannot
 * exist on the filesystem even momentarily.
 *
 * @param {Buffer} gz the gzipped archive, already verified against the pinned archive digest
 * @param {ReadonlySet<string>} allowed the exact set of member names the manifest pins
 */
export function extract(gz, allowed) {
  let tar;
  try {
    tar = gunzipSync(gz);
  } catch (error) {
    throw new Error(`The Credda engine archive is not valid gzip: ${error.message}`);
  }
  if (tar.length % BLOCK !== 0) {
    throw new Error('The Credda engine archive is not a whole number of tar blocks.');
  }

  const files = new Map();
  let offset = 0;

  while (offset + BLOCK <= tar.length) {
    const header = tar.subarray(offset, offset + BLOCK);

    // Two consecutive zero blocks end the archive. One is enough to stop on:
    // the packer writes the pair, and anything after them is not ours.
    if (header.every((byte) => byte === 0)) break;
    if (!checksumOk(header)) {
      throw new Error(`The Credda engine archive has a corrupt tar header at byte ${offset}.`);
    }

    const name = field(header, 0, 100);
    const type = String.fromCharCode(header[156] === 0 ? 0x30 : header[156]);
    const size = octal(header, 124, 12);
    if (size === null) {
      throw new Error(`The Credda engine archive states an unreadable size for '${name}'.`);
    }

    offset += BLOCK;
    const dataBlocks = Math.ceil(size / BLOCK) * BLOCK;

    // Directories carry no data and the packer emits none, but tolerating one
    // costs nothing and an archive rebuilt by a different tool may include them.
    if (type === '5') {
      offset += dataBlocks;
      continue;
    }
    if (type !== '0') {
      throw new Error(
        `The Credda engine archive contains '${name}' as tar type '${type}'. ` +
          'Only regular files are accepted; symlinks, hardlinks, devices and extension headers are refused. ' +
          'Nothing was extracted.',
      );
    }

    // The allow-list. Traversal, absolute paths and drive letters are all
    // refused by this one comparison rather than by three pattern checks that
    // each have to be right -- a name that is not literally a key in the
    // lockfile does not get written, whatever it looks like.
    if (!allowed.has(name)) {
      throw new Error(
        `The Credda engine archive contains '${name}', which this release does not pin in ` +
          'engine.lock.json. Nothing was extracted.',
      );
    }
    if (files.has(name)) {
      throw new Error(
        `The Credda engine archive contains '${name}' twice. Nothing was extracted. ` +
          'A duplicate member is how an extractor is made to write one file and verify another.',
      );
    }
    if (offset + size > tar.length) {
      throw new Error(`The Credda engine archive is truncated inside '${name}'.`);
    }

    files.set(name, Buffer.from(tar.subarray(offset, offset + size)));
    offset += dataBlocks;
  }

  for (const name of allowed) {
    if (!files.has(name)) {
      throw new Error(
        `The Credda engine archive is missing '${name}', which this release pins in ` +
          'engine.lock.json. Nothing was extracted.',
      );
    }
  }

  return files;
}
