#!/usr/bin/env bash
# Run ./curl-me.sh AFTER `node server.js` is running.
# Proves: first call = brain, second identical call = cache hit.

set -e

BASE=${BASE:-http://localhost:3000}

echo "--- call #1 (fresh cacheKey, expect source=brain, slow) ---"
curl -s -H 'x-user-id: alice' "$BASE/api/charge?amount=9.99" | python -m json.tool

echo ""
echo "--- call #2 (same shape, expect source=cache, fast) ---"
curl -s -H 'x-user-id: alice' "$BASE/api/charge?amount=9.99" | python -m json.tool

echo ""
echo "--- call #3 (same bucket but different exact amount, still cache hit) ---"
curl -s -H 'x-user-id: bob' "$BASE/api/charge?amount=8.50" | python -m json.tool

echo ""
echo "--- call #4 (different bucket -> new brain call) ---"
curl -s -H 'x-user-id: carol' "$BASE/api/charge?amount=6500&account_age_days=0" | python -m json.tool

echo ""
echo "--- dashboard ---"
curl -s "$BASE/engram/dashboard" | python -m json.tool

echo ""
echo "--- cache rows ---"
curl -s "$BASE/engram/cache" | python -m json.tool
