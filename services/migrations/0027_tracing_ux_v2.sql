-- Tracing UX v2 indexes (waterfall + correlations)
CREATE INDEX IF NOT EXISTS idx_spans_project_trace_start ON spans(project_id, trace_id, start_ts ASC);
CREATE INDEX IF NOT EXISTS idx_transactions_project_trace_time ON transactions(project_id, trace_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_replay_links_project_trace ON replay_links(project_id, trace_id);
