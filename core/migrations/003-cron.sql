-- Optional: pg_cron retention job. The migrator skips this file if the
-- pg_cron extension is not installed (checked before running).
--
-- Hourly sweep: delete route_visits older than 7 days.
do $$ begin
  perform cron.unschedule('engram_route_visits_retention');
exception when others then null; end $$;

select cron.schedule(
  'engram_route_visits_retention',
  '17 * * * *',
  $$ delete from engram.route_visits where entered_at < now() - interval '7 days' $$
);
