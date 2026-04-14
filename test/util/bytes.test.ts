import { describe, expect, it } from "vitest";
import {
  bytesToHex,
  concat,
  ctEqual,
  hexToBytes,
  leb128,
  lvCat,
  lvU64,
  oCat,
  u64LE,
  utf8,
  zeroBytes,
} from "../../src/util/bytes.js";

describe("bytes.concat", () => {
  it("concatenates multiple buffers", () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3]);
    const c = new Uint8Array([4, 5, 6]);
    expect(concat(a, b, c)).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
  });

  it("handles empty inputs", () => {
    expect(concat()).toEqual(new Uint8Array(0));
    expect(concat(new Uint8Array(0), new Uint8Array([1]))).toEqual(
      new Uint8Array([1]),
    );
  });
});

describe("bytes.hex", () => {
  it("round-trips hex <-> bytes", () => {
    const src = "deadbeef0011";
    expect(bytesToHex(hexToBytes(src))).toBe(src);
  });

  it("strips 0x prefix", () => {
    expect(hexToBytes("0xabcd")).toEqual(new Uint8Array([0xab, 0xcd]));
  });

  it("rejects odd-length hex", () => {
    expect(() => hexToBytes("abc")).toThrow();
  });

  it("rejects non-hex characters", () => {
    expect(() => hexToBytes("zz")).toThrow();
  });
});

describe("bytes.ctEqual", () => {
  it("returns true for equal buffers", () => {
    expect(ctEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(
      true,
    );
  });

  it("returns false for different lengths", () => {
    expect(ctEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });

  it("returns false for same length, different content", () => {
    expect(ctEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
  });
});

describe("bytes.u64LE", () => {
  it("encodes 0", () => {
    expect(u64LE(0)).toEqual(new Uint8Array(8));
  });

  it("encodes 1", () => {
    const e = new Uint8Array(8);
    e[0] = 1;
    expect(u64LE(1)).toEqual(e);
  });

  it("encodes 0x0102030405060708 little-endian", () => {
    expect(u64LE(0x0102030405060708n)).toEqual(
      new Uint8Array([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]),
    );
  });

  it("rejects negative values", () => {
    expect(() => u64LE(-1)).toThrow();
  });
});

describe("bytes.lvU64", () => {
  it("prefixes data with 8-byte LE length", () => {
    const data = utf8("hello");
    const out = lvU64(data);
    expect(out.length).toBe(8 + data.length);
    expect(out.slice(0, 8)).toEqual(
      new Uint8Array([5, 0, 0, 0, 0, 0, 0, 0]),
    );
    expect(out.slice(8)).toEqual(data);
  });
});

describe("bytes.leb128", () => {
  // Test vectors straight from draft-irtf-cfrg-cpace-20 §4.1 `prepend_len`.
  const cases: Array<[number, number[]]> = [
    [0, [0x00]],
    [1, [0x01]],
    [127, [0x7f]],
    [128, [0x80, 0x01]],
    [255, [0xff, 0x01]],
    [16383, [0xff, 0x7f]],
    [16384, [0x80, 0x80, 0x01]],
  ];

  for (const [input, expected] of cases) {
    it(`encodes ${input} as ${expected.map((b) => b.toString(16)).join(" ")}`, () => {
      expect(leb128(input)).toEqual(new Uint8Array(expected));
    });
  }
});

describe("bytes.lvCat", () => {
  it("prefixes each argument with its LEB128 length", () => {
    const a = new Uint8Array([0xaa]);
    const b = new Uint8Array([0xbb, 0xcc]);
    // lv_cat(a, b) = leb128(1) || 0xaa || leb128(2) || 0xbb 0xcc
    expect(lvCat(a, b)).toEqual(
      new Uint8Array([0x01, 0xaa, 0x02, 0xbb, 0xcc]),
    );
  });

  it("handles empty arguments", () => {
    expect(lvCat(new Uint8Array(0), new Uint8Array(0))).toEqual(
      new Uint8Array([0x00, 0x00]),
    );
  });
});

describe("bytes.oCat", () => {
  // draft-irtf-cfrg-cpace-20 Appendix A.3.3 test vectors.
  it("o_cat('ABCD','BCD') == 6f6342434441424344 (larger first, oc tag)", () => {
    const ABCD = utf8("ABCD");
    const BCD = utf8("BCD");
    expect(bytesToHex(oCat(ABCD, BCD))).toBe("6f6342434441424344");
    expect(bytesToHex(oCat(BCD, ABCD))).toBe("6f6342434441424344");
  });

  it("o_cat('BCD','ABCDE') == 6f634243444142434445", () => {
    const BCD = utf8("BCD");
    const ABCDE = utf8("ABCDE");
    expect(bytesToHex(oCat(BCD, ABCDE))).toBe("6f634243444142434445");
    expect(bytesToHex(oCat(ABCDE, BCD))).toBe("6f634243444142434445");
  });

  it("result is commutative (order of arguments does not matter)", () => {
    const a = new Uint8Array([0x01, 0x02]);
    const b = new Uint8Array([0x01, 0x03]);
    expect(oCat(a, b)).toEqual(oCat(b, a));
  });
});

describe("bytes.zeroBytes", () => {
  it("returns a zero-filled buffer of the requested size", () => {
    expect(zeroBytes(4)).toEqual(new Uint8Array([0, 0, 0, 0]));
  });
});
