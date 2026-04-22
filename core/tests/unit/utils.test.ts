import { describe, test, expect } from "vitest";
import { bucket, bucketEnum } from "../../src/utils.js";

describe("bucket()", () => {
  const labels = ["tiny", "small", "medium", "large"] as const;
  const edges = [50, 500, 5000];

  test("maps below first edge -> first label", () => {
    expect(bucket(9.99, edges, labels)).toBe("tiny");
    expect(bucket(0, edges, labels)).toBe("tiny");
    expect(bucket(-1, edges, labels)).toBe("tiny");
  });

  test("maps between edges to the right label", () => {
    expect(bucket(49.99, edges, labels)).toBe("tiny");  // just below 50
    expect(bucket(50, edges, labels)).toBe("small");    // edge is exclusive on the low side
    expect(bucket(250, edges, labels)).toBe("small");
    expect(bucket(4999, edges, labels)).toBe("medium");
  });

  test("values >= last edge get the last label", () => {
    expect(bucket(5000, edges, labels)).toBe("large");
    expect(bucket(99999, edges, labels)).toBe("large");
  });

  test("throws when labels length mismatches", () => {
    expect(() => bucket(1, [10, 20], ["a", "b"] as const)).toThrow(/labels.length/);
    expect(() => bucket(1, [10], ["a", "b", "c"] as const)).toThrow(/labels.length/);
  });

  test("single-bucket case (no edges) returns the one label", () => {
    expect(bucket(42, [], ["only"] as const)).toBe("only");
  });
});

describe("bucketEnum()", () => {
  const allowed = ["card", "paypal", "bank"] as const;

  test("returns value when present in allowed list", () => {
    expect(bucketEnum("card", allowed)).toBe("card");
    expect(bucketEnum("paypal", allowed)).toBe("paypal");
  });

  test("returns 'other' fallback for unknown values", () => {
    expect(bucketEnum("crypto", allowed)).toBe("other");
    expect(bucketEnum("", allowed)).toBe("other");
  });

  test("custom fallback is honoured", () => {
    expect(bucketEnum("crypto", allowed, "unknown")).toBe("unknown");
  });
});
