# Contributing to Engram

Thanks for your interest in contributing.

## How to contribute

1. Fork the repo
2. Create a branch (`git checkout -b fix/my-change`)
3. Make your changes
4. Test against a Supabase project (paste `install.sql`, run `example.sql`)
5. Commit with a clear message
6. Open a pull request

## What to contribute

- New classification rules in `engram.classify()`
- Bug fixes in SQL functions
- Documentation improvements
- New read API functions
- Performance optimizations

## Guidelines

- SQL only for the Supabase extension. No external dependencies.
- Every function must be `SECURITY DEFINER` with explicit `search_path` if it touches other schemas.
- Every new table needs RLS enabled and explicit grants.
- No em dashes. Use hyphens.
- Test your changes by running `example.sql` after applying `install.sql` on a fresh Supabase project.

## Reporting issues

Open an issue on GitHub with:
- What you expected
- What happened
- The SQL you ran
- Your Supabase Postgres version (`select version()`)

## Code of conduct

Be respectful. Be helpful. No spam.
