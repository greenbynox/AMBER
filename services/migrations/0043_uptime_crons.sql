CREATE TABLE IF NOT EXISTS uptime_monitors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    expected_status INT NOT NULL DEFAULT 200,
    timeout_ms INT NOT NULL DEFAULT 5000,
    interval_minutes INT NOT NULL DEFAULT 5,
    headers JSONB,
    enabled BOOLEAN NOT NULL DEFAULT true,
    status TEXT NOT NULL DEFAULT 'unknown',
    last_check_at TIMESTAMPTZ,
    next_check_at TIMESTAMPTZ,
    last_duration_ms INT,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS uptime_checks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    monitor_id UUID NOT NULL REFERENCES uptime_monitors(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    status_code INT,
    duration_ms INT,
    error TEXT,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_uptime_monitors_project ON uptime_monitors(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_uptime_monitors_next_check ON uptime_monitors(next_check_at ASC);
CREATE INDEX IF NOT EXISTS idx_uptime_checks_monitor ON uptime_checks(monitor_id, checked_at DESC);

CREATE TABLE IF NOT EXISTS cron_monitors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    schedule_minutes INT NOT NULL DEFAULT 60,
    grace_minutes INT NOT NULL DEFAULT 5,
    timezone TEXT NOT NULL DEFAULT 'UTC',
    enabled BOOLEAN NOT NULL DEFAULT true,
    status TEXT NOT NULL DEFAULT 'unknown',
    last_checkin_at TIMESTAMPTZ,
    next_expected_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cron_checkins (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    monitor_id UUID NOT NULL REFERENCES cron_monitors(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    message TEXT,
    checked_in_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cron_monitors_project ON cron_monitors(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cron_monitors_next_expected ON cron_monitors(next_expected_at ASC);
CREATE INDEX IF NOT EXISTS idx_cron_checkins_monitor ON cron_checkins(monitor_id, checked_in_at DESC);
