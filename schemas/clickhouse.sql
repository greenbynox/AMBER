CREATE DATABASE IF NOT EXISTS ember;

CREATE TABLE IF NOT EXISTS ember.raw_events (
    received_at DateTime DEFAULT now(),
    project_id String,
    event_id String,
    payload String
) ENGINE = MergeTree()
ORDER BY (project_id, event_id, received_at);
