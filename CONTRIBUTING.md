# Contributing to Engram

Thanks for your interest. This repo ships two products — pick the one you want to work on.

| Product | Path | Stack |
|---|---|---|
| `@srk0102/engram` npm package | [`core/`](core) | Node.js / TypeScript / Postgres |
| Supabase SQL extension | [`supabase/`](supabase) | PL/pgSQL / Supabase |

Before opening a PR, please file an issue describing what you want to change. It saves both of us from spending time on a direction that doesn't fit the project.

---

## Working on the npm package (`core/`)

### Setup

```bash
git clone https://github.com/srk0102/engram
cd engram/core
npm install
```

You need Node.js >= 18 and Docker (for the Postgres used by the integration-style demos). No Supabase account needed.

### Dev loop

```bash
npm run build        # tsup, ESM + CJS + types
npm run dev          # tsup watch mode
npm run typecheck    # tsc --noEmit
npm run test:unit    # vitest, no DB needed
```

All unit tests must pass before a PR is merged (`npm run test:unit` → 34 tests today).

### What to contribute

Good fits:

- New brain adapters (`src/adapters/*.ts`). Keep the `Brain` interface (`call(prompt, opts?) => Promise<string>`). Match the existing Ollama / Anthropic / OpenAI adapters for config shape and test style.
- New middleware (Hono, Nest guard, Koa). Add an entry in `tsup.config.ts` and a subpath in `package.json` exports. Unit tests go in `tests/unit/middleware.<framework>.test.ts` with the same fake-request pattern the Express / Fastify tests use.
- Docs / examples in [`core/examples/`](core/examples).
- Bug fixes with a repro in the PR description.

Not a fit (will be closed):

- Adding built-in decision enums or policy. Engram is unopinionated — the schema is the dev's job.
- Middleware that auto-sends 403 / 429. Route handlers own responses. `onDecision` hook exists for dev-owned short-circuit.
- Changes that add mandatory runtime deps beyond `pg`.

### SQL migrations

The migrations under `core/migrations/` are hashed at install time. Any change to a migration file that's already shipped will break `engram.connect()` for upgraders with `EngramMigrationDriftError`. Either:

1. Add a **new** migration file (`004-*.sql`, `005-*.sql`, ...) that alters the existing schema, or
2. If the change is purely additive and the package hasn't shipped that file yet (i.e. the file is post-last-release), editing in place is fine.

Never edit a migration that has been published in a tagged release.

### Guidelines for PRs

- Keep PRs focused. One concern per PR.
- Match the existing style: explicit types on public API, no abbreviations in identifiers, no em dashes in user-facing strings or docs.
- Add a test for any new function / adapter / middleware.
- Update [`README.md`](core/README.md) and [`DEVELOPER_EXPERIENCE.md`](core/DEVELOPER_EXPERIENCE.md) if the public surface changes.

---

## Working on the Supabase extension (`supabase/`)

### Setup

You need a Supabase project. Clone the repo, then paste [`supabase/install.sql`](supabase/install.sql) into the SQL Editor of a throwaway project.

### Dev loop

```sql
-- Paste supabase/install.sql      (once)
-- Paste supabase/example.sql      (smoke test)
-- Iterate on your changes
-- Paste supabase/reset.sql + install.sql to re-run clean
```

### What to contribute

- New classification rules in `engram.classify()`
- Bug fixes in PL/pgSQL functions
- Documentation improvements (see [`docs.md`](docs.md))
- Performance optimizations
- Additional read-only helpers

### Guidelines

- SQL only. No external runtime dependencies.
- Every function must be `SECURITY DEFINER` with an explicit `search_path` if it reaches outside `engram`.
- Every new table needs RLS enabled and explicit grants for `authenticated` / `service_role`.
- Test every change by running `supabase/example.sql` against a fresh install. Paste the output in the PR.

---

## Reporting issues

Open an issue at https://github.com/srk0102/engram/issues with:

- Which product (`@srk0102/engram` or Supabase extension)
- Version (`npm ls @srk0102/engram` or the commit SHA of `install.sql`)
- Repro steps
- What you expected and what happened

## Security

If you find a security issue, please email the maintainer rather than opening a public issue: `ramakrishnasiva128@gmail.com`.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
