export class EngramError extends Error {
  constructor(message: string, public readonly details?: Record<string, unknown>) {
    super(message);
    this.name = "EngramError";
  }
}

export class EngramNotConnectedError extends EngramError {
  constructor() {
    super("Engram.connect() must be called before using this method");
    this.name = "EngramNotConnectedError";
  }
}

export class EngramMigrationDriftError extends EngramError {
  constructor(migration: string, expectedSha: string, storedSha: string) {
    super(
      `migration drift detected for "${migration}". The file on disk hashes to ${expectedSha.slice(0, 12)}... but the database has ${storedSha.slice(0, 12)}... recorded.

To fix:
  1. If you upgraded @srk0102/engram and the DB is dev-only:
       npx engram reset --force
     (drops the "engram" schema so the new migrations can re-apply)
  2. If this is production: downgrade @srk0102/engram to the version that
     wrote the stored hash, or run a targeted migration by hand.`,
      { migration, expectedSha, storedSha },
    );
    this.name = "EngramMigrationDriftError";
  }
}

export class EngramConfigError extends EngramError {
  constructor(message: string) {
    super(message);
    this.name = "EngramConfigError";
  }
}
