/**
 * QR encoding (byte mode), zero dependencies.
 *
 * The TUI wants to show a TOTP `otpauth://` URI or a key as a scannable code.
 * Pulling in a QR library for that would mean adding a dependency to a
 * process that holds unlocked parent seeds, which is not a trade worth making
 * for a display convenience — so this implements the encoder instead.
 *
 * A wrong QR code is worse than no QR code: it scans cleanly and yields the
 * wrong secret, and the user has no way to notice until their 2FA stops
 * working. The block-structure table below was extracted programmatically
 * from the reference `qrcode` Python library rather than transcribed, and
 * `test/qr.test.ts` compares the full module matrix against that library's
 * output for a spread of inputs, versions and error-correction levels.
 *
 * Byte mode only. That covers every string the TUI shows (URIs, bech32 keys,
 * base32 secrets); numeric and alphanumeric modes would encode the same data
 * more compactly but add branches with no user-visible benefit here.
 *
 * One deliberate divergence from that reference library: mask selection. The
 * spec picks the mask with the lowest penalty on the finished symbol, which is
 * what happens below. `qrcode` scores each candidate with its format modules
 * blanked and its dark module light (`makeImpl(test=True, ...)`) — i.e. it
 * scores a symbol that is not a legal one — and so occasionally picks a
 * different mask. Every one of the eight masks yields a valid, scannable code;
 * the choice only trades off scanning robustness. The tests therefore pin the
 * mask when comparing matrices, and check the selection rule separately,
 * rather than reproducing a known quirk to make an equality assertion pass.
 */

/** Error-correction level, in the spec's own order. */
export const EC_LEVELS = ["L", "M", "Q", "H"] as const;
export type EcLevel = (typeof EC_LEVELS)[number];

/**
 * Block structure per version and EC level.
 *
 * Each entry is a flat list of (blockCount, totalCodewords, dataCodewords)
 * triples. Extracted from qrcode.base.RS_BLOCK_TABLE; see the file header for
 * why it is not typed out by hand.
 */
const RS_BLOCK_TABLE: number[][][] = [
  /* v1 */ [[1,26,19], [1,26,16], [1,26,13], [1,26,9]],
  /* v2 */ [[1,44,34], [1,44,28], [1,44,22], [1,44,16]],
  /* v3 */ [[1,70,55], [1,70,44], [2,35,17], [2,35,13]],
  /* v4 */ [[1,100,80], [2,50,32], [2,50,24], [4,25,9]],
  /* v5 */ [[1,134,108], [2,67,43], [2,33,15,2,34,16], [2,33,11,2,34,12]],
  /* v6 */ [[2,86,68], [4,43,27], [4,43,19], [4,43,15]],
  /* v7 */ [[2,98,78], [4,49,31], [2,32,14,4,33,15], [4,39,13,1,40,14]],
  /* v8 */ [[2,121,97], [2,60,38,2,61,39], [4,40,18,2,41,19], [4,40,14,2,41,15]],
  /* v9 */ [[2,146,116], [3,58,36,2,59,37], [4,36,16,4,37,17], [4,36,12,4,37,13]],
  /* v10 */ [[2,86,68,2,87,69], [4,69,43,1,70,44], [6,43,19,2,44,20], [6,43,15,2,44,16]],
  /* v11 */ [[4,101,81], [1,80,50,4,81,51], [4,50,22,4,51,23], [3,36,12,8,37,13]],
  /* v12 */ [[2,116,92,2,117,93], [6,58,36,2,59,37], [4,46,20,6,47,21], [7,42,14,4,43,15]],
  /* v13 */ [[4,133,107], [8,59,37,1,60,38], [8,44,20,4,45,21], [12,33,11,4,34,12]],
  /* v14 */ [[3,145,115,1,146,116], [4,64,40,5,65,41], [11,36,16,5,37,17], [11,36,12,5,37,13]],
  /* v15 */ [[5,109,87,1,110,88], [5,65,41,5,66,42], [5,54,24,7,55,25], [11,36,12,7,37,13]],
  /* v16 */ [[5,122,98,1,123,99], [7,73,45,3,74,46], [15,43,19,2,44,20], [3,45,15,13,46,16]],
  /* v17 */ [[1,135,107,5,136,108], [10,74,46,1,75,47], [1,50,22,15,51,23], [2,42,14,17,43,15]],
  /* v18 */ [[5,150,120,1,151,121], [9,69,43,4,70,44], [17,50,22,1,51,23], [2,42,14,19,43,15]],
  /* v19 */ [[3,141,113,4,142,114], [3,70,44,11,71,45], [17,47,21,4,48,22], [9,39,13,16,40,14]],
  /* v20 */ [[3,135,107,5,136,108], [3,67,41,13,68,42], [15,54,24,5,55,25], [15,43,15,10,44,16]],
  /* v21 */ [[4,144,116,4,145,117], [17,68,42], [17,50,22,6,51,23], [19,46,16,6,47,17]],
  /* v22 */ [[2,139,111,7,140,112], [17,74,46], [7,54,24,16,55,25], [34,37,13]],
  /* v23 */ [[4,151,121,5,152,122], [4,75,47,14,76,48], [11,54,24,14,55,25], [16,45,15,14,46,16]],
  /* v24 */ [[6,147,117,4,148,118], [6,73,45,14,74,46], [11,54,24,16,55,25], [30,46,16,2,47,17]],
  /* v25 */ [[8,132,106,4,133,107], [8,75,47,13,76,48], [7,54,24,22,55,25], [22,45,15,13,46,16]],
  /* v26 */ [[10,142,114,2,143,115], [19,74,46,4,75,47], [28,50,22,6,51,23], [33,46,16,4,47,17]],
  /* v27 */ [[8,152,122,4,153,123], [22,73,45,3,74,46], [8,53,23,26,54,24], [12,45,15,28,46,16]],
  /* v28 */ [[3,147,117,10,148,118], [3,73,45,23,74,46], [4,54,24,31,55,25], [11,45,15,31,46,16]],
  /* v29 */ [[7,146,116,7,147,117], [21,73,45,7,74,46], [1,53,23,37,54,24], [19,45,15,26,46,16]],
  /* v30 */ [[5,145,115,10,146,116], [19,75,47,10,76,48], [15,54,24,25,55,25], [23,45,15,25,46,16]],
  /* v31 */ [[13,145,115,3,146,116], [2,74,46,29,75,47], [42,54,24,1,55,25], [23,45,15,28,46,16]],
  /* v32 */ [[17,145,115], [10,74,46,23,75,47], [10,54,24,35,55,25], [19,45,15,35,46,16]],
  /* v33 */ [[17,145,115,1,146,116], [14,74,46,21,75,47], [29,54,24,19,55,25], [11,45,15,46,46,16]],
  /* v34 */ [[13,145,115,6,146,116], [14,74,46,23,75,47], [44,54,24,7,55,25], [59,46,16,1,47,17]],
  /* v35 */ [[12,151,121,7,152,122], [12,75,47,26,76,48], [39,54,24,14,55,25], [22,45,15,41,46,16]],
  /* v36 */ [[6,151,121,14,152,122], [6,75,47,34,76,48], [46,54,24,10,55,25], [2,45,15,64,46,16]],
  /* v37 */ [[17,152,122,4,153,123], [29,74,46,14,75,47], [49,54,24,10,55,25], [24,45,15,46,46,16]],
  /* v38 */ [[4,152,122,18,153,123], [13,74,46,32,75,47], [48,54,24,14,55,25], [42,45,15,32,46,16]],
  /* v39 */ [[20,147,117,4,148,118], [40,75,47,7,76,48], [43,54,24,22,55,25], [10,45,15,67,46,16]],
  /* v40 */ [[19,148,118,6,149,119], [18,75,47,31,76,48], [34,54,24,34,55,25], [20,45,15,61,46,16]],
];

/** Galois field GF(256) with the QR primitive polynomial 0x11d. */
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]!;
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a]! + LOG[b]!]!;
}

/** Generator polynomial for `degree` error-correction codewords. */
function rsGenerator(degree: number): Uint8Array {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1);
    for (let j = 0; j < poly.length; j++) {
      next[j] = next[j]! ^ poly[j]!;
      next[j + 1] = next[j + 1]! ^ gfMul(poly[j]!, EXP[i]!);
    }
    poly = next;
  }
  return poly;
}

/** Reed-Solomon remainder for one block. */
function rsEncode(data: Uint8Array, ecCount: number): Uint8Array {
  const gen = rsGenerator(ecCount);
  const res = new Uint8Array(data.length + ecCount);
  res.set(data);
  for (let i = 0; i < data.length; i++) {
    const factor = res[i]!;
    if (factor === 0) continue;
    for (let j = 0; j < gen.length; j++) {
      res[i + j] = res[i + j]! ^ gfMul(gen[j]!, factor);
    }
  }
  return res.slice(data.length);
}

/** Alignment-pattern centre coordinates per version (spec Annex E). */
function alignmentPositions(version: number): number[] {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2;
  const size = version * 4 + 17;
  // The spec's step rule: last coordinate is size-7, first is 6, and the
  // interval is even.
  const step = version === 32 ? 26 : Math.ceil((size - 13) / (2 * count - 2)) * 2;
  const positions = [6];
  for (let i = count - 1; i >= 1; i--) positions.push(size - 7 - (count - 1 - i) * step);
  return positions.slice(0, 1).concat(positions.slice(1).sort((a, b) => a - b));
}

const FORMAT_EC_BITS: Record<EcLevel, number> = { L: 1, M: 0, Q: 3, H: 2 };

/** BCH(15,5) format information, including the fixed XOR mask. */
function formatBits(level: EcLevel, mask: number): number {
  const data = (FORMAT_EC_BITS[level] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) {
    rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  }
  return ((data << 10) | rem) ^ 0x5412;
}

/** BCH(18,6) version information, for versions 7 and up. */
function versionBits(version: number): number {
  let rem = version;
  for (let i = 0; i < 12; i++) {
    rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  }
  return (version << 12) | rem;
}

function maskAt(mask: number, row: number, col: number): boolean {
  switch (mask) {
    case 0: return (row + col) % 2 === 0;
    case 1: return row % 2 === 0;
    case 2: return col % 3 === 0;
    case 3: return (row + col) % 3 === 0;
    case 4: return (Math.floor(row / 2) + Math.floor(col / 3)) % 2 === 0;
    case 5: return ((row * col) % 2) + ((row * col) % 3) === 0;
    case 6: return (((row * col) % 2) + ((row * col) % 3)) % 2 === 0;
    default: return (((row + col) % 2) + ((row * col) % 3)) % 2 === 0;
  }
}

export interface QrMatrix {
  version: number;
  level: EcLevel;
  mask: number;
  size: number;
  /** Row-major; true is a dark module. */
  modules: boolean[][];
}

/** Data capacity in bytes for byte mode at this version and level. */
function byteCapacity(version: number, level: EcLevel): number {
  const spec = RS_BLOCK_TABLE[version - 1]![EC_LEVELS.indexOf(level)]!;
  let dataCodewords = 0;
  for (let i = 0; i < spec.length; i += 3) {
    dataCodewords += spec[i]! * spec[i + 2]!;
  }
  const countBits = version < 10 ? 8 : 16;
  // 4 mode bits + the character-count indicator.
  return dataCodewords - Math.ceil((4 + countBits) / 8);
}

function smallestVersion(byteLength: number, level: EcLevel): number {
  for (let version = 1; version <= 40; version++) {
    if (byteCapacity(version, level) >= byteLength) return version;
  }
  throw new Error(
    `${byteLength} bytes does not fit in a QR code at error-correction level ${level} ` +
      `(max ${byteCapacity(40, level)})`,
  );
}

/** Mode indicator + count + payload + terminator + padding, as codewords. */
function buildDataCodewords(data: Uint8Array, version: number, level: EcLevel): Uint8Array {
  const spec = RS_BLOCK_TABLE[version - 1]![EC_LEVELS.indexOf(level)]!;
  let totalData = 0;
  for (let i = 0; i < spec.length; i += 3) totalData += spec[i]! * spec[i + 2]!;

  const bits: number[] = [];
  const push = (value: number, length: number): void => {
    for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  push(0b0100, 4); // byte mode
  push(data.length, version < 10 ? 8 : 16);
  for (const byte of data) push(byte, 8);
  // Terminator, up to four zero bits, then pad to a byte boundary.
  for (let i = 0; i < 4 && bits.length < totalData * 8; i++) bits.push(0);
  while (bits.length % 8 !== 0) bits.push(0);

  const codewords = new Uint8Array(totalData);
  for (let i = 0; i < bits.length / 8; i++) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i * 8 + j]!;
    codewords[i] = byte;
  }
  // Alternating pad codewords, as the spec prescribes.
  for (let i = Math.ceil(bits.length / 8); i < totalData; i++) {
    codewords[i] = (i - Math.ceil(bits.length / 8)) % 2 === 0 ? 0xec : 0x11;
  }
  return codewords;
}

/** Split into blocks, add error correction, and interleave. */
function interleave(dataCodewords: Uint8Array, version: number, level: EcLevel): Uint8Array {
  const spec = RS_BLOCK_TABLE[version - 1]![EC_LEVELS.indexOf(level)]!;
  const dataBlocks: Uint8Array[] = [];
  const ecBlocks: Uint8Array[] = [];
  let offset = 0;
  for (let i = 0; i < spec.length; i += 3) {
    const [count, total, dataLen] = [spec[i]!, spec[i + 1]!, spec[i + 2]!];
    for (let b = 0; b < count; b++) {
      const block = dataCodewords.slice(offset, offset + dataLen);
      offset += dataLen;
      dataBlocks.push(block);
      ecBlocks.push(rsEncode(block, total - dataLen));
    }
  }
  const out: number[] = [];
  const maxData = Math.max(...dataBlocks.map((b) => b.length));
  for (let i = 0; i < maxData; i++) {
    for (const block of dataBlocks) if (i < block.length) out.push(block[i]!);
  }
  const maxEc = Math.max(...ecBlocks.map((b) => b.length));
  for (let i = 0; i < maxEc; i++) {
    for (const block of ecBlocks) if (i < block.length) out.push(block[i]!);
  }
  return new Uint8Array(out);
}

type Grid = Array<Array<boolean | null>>;

/** Place the fixed patterns; leaves data modules null. */
function buildTemplate(version: number): { grid: Grid; reserved: boolean[][] } {
  const size = version * 4 + 17;
  const grid: Grid = Array.from({ length: size }, () => Array<boolean | null>(size).fill(null));
  const reserved = Array.from({ length: size }, () => Array<boolean>(size).fill(false));

  const setFn = (r: number, c: number, dark: boolean): void => {
    grid[r]![c] = dark;
    reserved[r]![c] = true;
  };

  // Finder patterns and their separators.
  for (const [fr, fc] of [[0, 0], [0, size - 7], [size - 7, 0]] as const) {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const rr = fr + r;
        const cc = fc + c;
        if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
        const onRing = (r >= 0 && r <= 6 && (c === 0 || c === 6)) || (c >= 0 && c <= 6 && (r === 0 || r === 6));
        const inCore = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        setFn(rr, cc, onRing || inCore);
      }
    }
  }

  // Timing patterns.
  for (let i = 8; i < size - 8; i++) {
    setFn(6, i, i % 2 === 0);
    setFn(i, 6, i % 2 === 0);
  }

  // Alignment patterns, skipping the ones that would overlap a finder.
  const positions = alignmentPositions(version);
  for (const r of positions) {
    for (const c of positions) {
      if ((r === 6 && c === 6) || (r === 6 && c === size - 7) || (r === size - 7 && c === 6)) {
        continue;
      }
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          const ring = Math.max(Math.abs(dr), Math.abs(dc));
          setFn(r + dr, c + dc, ring !== 1);
        }
      }
    }
  }

  // Dark module — always set, always at this coordinate.
  setFn(size - 8, 8, true);

  // Reserve the format-information areas; the values are written later,
  // because they depend on the mask that has not been chosen yet.
  for (let i = 0; i < 9; i++) {
    if (!reserved[8]![i]) { grid[8]![i] = false; reserved[8]![i] = true; }
    if (!reserved[i]![8]) { grid[i]![8] = false; reserved[i]![8] = true; }
  }
  for (let i = 0; i < 8; i++) {
    if (!reserved[8]![size - 1 - i]) { grid[8]![size - 1 - i] = false; reserved[8]![size - 1 - i] = true; }
    if (!reserved[size - 1 - i]![8]) { grid[size - 1 - i]![8] = false; reserved[size - 1 - i]![8] = true; }
  }

  // Version information blocks (versions 7+).
  if (version >= 7) {
    const bits = versionBits(version);
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) === 1;
      const r = Math.floor(i / 3);
      const c = size - 11 + (i % 3);
      setFn(r, c, dark);
      setFn(c, r, dark);
    }
  }

  return { grid, reserved };
}

/** Zigzag placement of the interleaved codewords into the free modules. */
function placeData(grid: Grid, reserved: boolean[][], codewords: Uint8Array): void {
  const size = grid.length;
  let bitIndex = 0;
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    // Column 6 is the vertical timing pattern and is skipped entirely.
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      const row = upward ? size - 1 - vert : vert;
      for (const col of [right, right - 1]) {
        if (reserved[row]![col]) continue;
        let dark = false;
        if (bitIndex < codewords.length * 8) {
          dark = ((codewords[bitIndex >>> 3]! >>> (7 - (bitIndex & 7))) & 1) === 1;
        }
        grid[row]![col] = dark;
        bitIndex++;
      }
    }
    upward = !upward;
  }
}

/** The four penalty rules, used to pick the least-bad mask. */
function penalty(modules: boolean[][]): number {
  const size = modules.length;
  let score = 0;

  // Rule 1: runs of five or more same-coloured modules.
  for (let i = 0; i < size; i++) {
    for (const line of [modules[i]!, modules.map((row) => row[i]!)]) {
      let run = 1;
      for (let j = 1; j < size; j++) {
        if (line[j] === line[j - 1]) {
          run++;
        } else {
          if (run >= 5) score += 3 + (run - 5);
          run = 1;
        }
      }
      if (run >= 5) score += 3 + (run - 5);
    }
  }

  // Rule 2: 2x2 blocks of one colour.
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = modules[r]![c];
      if (v === modules[r]![c + 1] && v === modules[r + 1]![c] && v === modules[r + 1]![c + 1]) {
        score += 3;
      }
    }
  }

  // Rule 3: the finder-like 1:1:3:1:1 pattern with four light modules beside it.
  const A = [true, false, true, true, true, false, true, false, false, false, false];
  const B = [false, false, false, false, true, false, true, true, true, false, true];
  const matches = (line: boolean[], start: number, pattern: boolean[]): boolean =>
    pattern.every((want, k) => line[start + k] === want);
  for (let i = 0; i < size; i++) {
    for (const line of [modules[i]!, modules.map((row) => row[i]!)]) {
      for (let j = 0; j + 11 <= size; j++) {
        if (matches(line, j, A) || matches(line, j, B)) score += 40;
      }
    }
  }

  // Rule 4: deviation from an even balance of dark and light.
  let dark = 0;
  for (const row of modules) for (const v of row) if (v) dark++;
  const percent = (dark * 100) / (size * size);
  score += Math.floor(Math.abs(percent - 50) / 5) * 10;

  return score;
}

/**
 * Encode `text` as a QR module matrix.
 *
 * Picks the smallest version that fits, and the mask with the lowest penalty
 * — both exactly as the spec prescribes, so the output matches any conforming
 * encoder module for module.
 */
export function encodeQr(
  text: string,
  options: { level?: EcLevel; version?: number; mask?: number } = {},
): QrMatrix {
  const level = options.level ?? "M";
  const data = new TextEncoder().encode(text);
  const version = options.version ?? smallestVersion(data.length, level);
  if (version < 1 || version > 40) throw new Error(`QR version must be 1..40, got ${version}`);
  if (data.length > byteCapacity(version, level)) {
    throw new Error(
      `${data.length} bytes does not fit in a version-${version} QR at level ${level} ` +
        `(capacity ${byteCapacity(version, level)})`,
    );
  }

  const codewords = interleave(buildDataCodewords(data, version, level), version, level);

  let best: { modules: boolean[][]; mask: number; score: number } | null = null;
  // An explicit mask is for tests and for reproducing another encoder's
  // output; production always selects by penalty, as the spec prescribes.
  const masks =
    options.mask === undefined ? [0, 1, 2, 3, 4, 5, 6, 7] : [options.mask];
  for (const mask of masks) {
    const { grid, reserved } = buildTemplate(version);
    placeData(grid, reserved, codewords);
    const size = grid.length;
    const modules = grid.map((row, r) =>
      row.map((v, c) => {
        const dark = v === true;
        return reserved[r]![c] ? dark : dark !== maskAt(mask, r, c);
      }),
    );
    // Format information depends on the mask, so it is written per candidate.
    const bits = formatBits(level, mask);
    for (let i = 0; i < 15; i++) {
      const dark = ((bits >>> i) & 1) === 1;
      if (i < 6) modules[i]![8] = dark;
      else if (i < 8) modules[i + 1]![8] = dark;
      else if (i === 8) modules[8]![7] = dark;
      else modules[8]![14 - i] = dark;

      if (i < 8) modules[8]![size - 1 - i] = dark;
      else modules[size - 15 + i]![8] = dark;
    }
    const score = penalty(modules);
    if (!best || score < best.score) best = { modules, mask, score };
  }

  const chosen = best!;
  return {
    version,
    level,
    mask: chosen.mask,
    size: chosen.modules.length,
    modules: chosen.modules,
  };
}

/**
 * Render a matrix as text, two modules per character cell.
 *
 * Half-block characters give square-ish modules in a terminal, where cells are
 * about twice as tall as they are wide. The quiet zone is four modules on
 * every side; without it many scanners simply fail.
 */
export function renderQrText(matrix: QrMatrix, options: { quietZone?: number } = {}): string {
  const quiet = options.quietZone ?? 4;
  const size = matrix.size + quiet * 2;
  const dark = (r: number, c: number): boolean => {
    const rr = r - quiet;
    const cc = c - quiet;
    if (rr < 0 || cc < 0 || rr >= matrix.size || cc >= matrix.size) return false;
    return matrix.modules[rr]![cc]!;
  };
  const lines: string[] = [];
  for (let r = 0; r < size; r += 2) {
    let line = "";
    for (let c = 0; c < size; c++) {
      const top = dark(r, c);
      const bottom = r + 1 < size ? dark(r + 1, c) : false;
      // Dark modules print as light glyphs: terminals are dark-on-light or
      // light-on-dark, and scanners want the DATA modules dark. Using the
      // block characters this way round keeps it scannable on a light
      // terminal, which is the common default.
      line += top && bottom ? " " : top ? "\u2584" : bottom ? "\u2580" : "\u2588";
    }
    lines.push(line);
  }
  return lines.join("\n");
}
