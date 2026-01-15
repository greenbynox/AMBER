CREATE TABLE IF NOT EXISTS regions (
    name TEXT PRIMARY KEY,
    api_base_url TEXT NOT NULL,
    ingest_url TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO regions (name, api_base_url, ingest_url)
VALUES
    ('us', 'https://us.api.ember.local', 'https://us.ingest.ember.local'),
    ('eu', 'https://eu.api.ember.local', 'https://eu.ingest.ember.local')
ON CONFLICT (name) DO NOTHING;
