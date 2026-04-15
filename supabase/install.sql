-- Engram v0.1.0
-- Paste this entire file into Supabase SQL editor
-- Run it once. Done.

\i schema.sql
\i functions.sql
\i classify.sql

do $$
begin
  raise notice 'Engram installed successfully.';
  raise notice 'Tables: engram.patterns,
    engram.audit, engram.quarantine';
  raise notice 'Functions: engram.lookup,
    engram.learn, engram.feedback,
    engram.classify, engram.stats';
  raise notice 'Open Table Editor to see
    engram schema in your dashboard.';
end;
$$;
