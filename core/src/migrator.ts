import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Pool, PoolClient } from "pg";
import { EngramMigrationDriftError } from "./errors.js";
import type { Logger } from "./types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// When built to dist/, migrations live at ../migrations (sibling to dist/).
// When running from src/ during dev/test, they live at ../migrations too.
const DEFAULT_MIGRATIONS_DIR = join(__dirname, "..", "migrations");

const BOOTSTRAP_SQL = `
  create schema if not exists engram;
  create table if not exists engram.migrations (
    name       text primary key,
    sha256     text not null,
    applied_at timestamptz not null default now()
  );
`;

const PG_CRON_PROBE =
  "select 1 as present from pg_extension where extname = 'pg_cron'";

export interface MigrationResult {
  name: string;
  status: "applied" | "skipped-already-applied" | "skipped-no-pg-cron";
}

export interface MigratorOptions {
  pool: Pool;
  migrationsDir?: string;
  logger?: Logger;
}

function sha256(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

export class Migrator {
  private readonly pool: Pool;
  private readonly dir: string;
  private readonly log: Logger;

  constructor(opts: MigratorOptions) {
    this.pool = opts.pool;
    this.dir = opts.migrationsDir ?? DEFAULT_MIGRATIONS_DIR;
    this.log = opts.logger ?? (() => {});
  }

  async run(): Promise<MigrationResult[]> {
    const client = await this.pool.connect();
    try {
      await client.query(BOOTSTRAP_SQL);

      const { rows: cronRows } = await client.query<{ present: number }>(
        PG_CRON_PROBE,
      );
      const hasPgCron = cronRows.length > 0;

      const files = (await readdir(this.dir))
        .filter((f) => f.endsWith(".sql"))
        .sort();

      const results: MigrationResult[] = [];

      for (const name of files) {
        if (!hasPgCron && name.includes("cron")) {
          this.log("engram migrator: pg_cron not installed; skipping", { file: name });
          results.push({ name, status: "skipped-no-pg-cron" });
          continue;
        }

        const path = join(this.dir, name);
        const content = await readFile(path, "utf8");
        const hash = sha256(content);

        const status = await this.applyOne(client, name, hash, content);
        results.push({ name, status });
      }

      return results;
    } finally {
      client.release();
    }
  }

  private async applyOne(
    client: PoolClient,
    name: string,
    hash: string,
    content: string,
  ): Promise<"applied" | "skipped-already-applied"> {
    const { rows } = await client.query<{ sha256: string }>(
      "select sha256 from engram.migrations where name = $1",
      [name],
    );

    if (rows.length > 0) {
      const stored = rows[0]!.sha256;
      if (stored !== hash) {
        throw new EngramMigrationDriftError(name, hash, stored);
      }
      return "skipped-already-applied";
    }

    await client.query("begin");
    try {
      await client.query(content);
      await client.query(
        "insert into engram.migrations (name, sha256) values ($1, $2)",
        [name, hash],
      );
      await client.query("commit");
      this.log("engram migrator: applied", { file: name });
      return "applied";
    } catch (err) {
      await client.query("rollback").catch(() => {});
      throw err;
    }
  }
}
