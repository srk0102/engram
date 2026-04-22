/**
 * Map a continuous numeric value to a coarse label by walking edges
 * low -> high. Shared label across a range means repeated LLM calls for
 * the same "kind of" input coalesce into one cache row.
 *
 * Requires `labels.length === edges.length + 1` so the last label catches
 * everything >= the last edge.
 *
 * @example
 *   const label = bucket(amount,
 *     [50, 500, 5000],
 *     ["tiny", "small", "medium", "large"] as const);
 *   // 9.99   -> "tiny"
 *   // 250    -> "small"
 *   // 9999   -> "large"
 */
export function bucket<const T extends readonly string[]>(
  value: number,
  edges: readonly number[],
  labels: T,
): T[number] {
  if (labels.length !== edges.length + 1) {
    throw new Error(
      `bucket: labels.length must be edges.length + 1 (got ${labels.length} labels, ${edges.length} edges)`,
    );
  }
  for (let i = 0; i < edges.length; i++) {
    if (value < edges[i]!) return labels[i]!;
  }
  return labels[labels.length - 1]!;
}

/**
 * Snap a free-form string to a known set of labels; otherwise return
 * `fallback`. Keeps the cache key's cardinality bounded when you accept
 * untrusted input like a `payment_method` field.
 *
 * @example
 *   bucketEnum("card",   ["card", "paypal"] as const)              // "card"
 *   bucketEnum("crypto", ["card", "paypal"] as const)              // "other"
 *   bucketEnum("crypto", ["card", "paypal"] as const, "unknown")   // "unknown"
 */
export function bucketEnum<const T extends readonly string[]>(
  value: string,
  allowed: T,
  fallback: string = "other",
): T[number] | string {
  return (allowed as readonly string[]).includes(value) ? (value as T[number]) : fallback;
}
