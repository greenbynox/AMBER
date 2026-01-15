-- Advanced alerts: fatigue control + silences + dynamic thresholds
ALTER TABLE alert_rules
    ADD COLUMN IF NOT EXISTS cooldown_minutes INT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_triggers_per_day INT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS threshold_multiplier DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS baseline_minutes INT;

CREATE TABLE IF NOT EXISTS alert_silences (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    rule_id UUID REFERENCES alert_rules(id) ON DELETE CASCADE,
    reason TEXT,
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alert_rule_triggers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id UUID NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alert_silences_project ON alert_silences(project_id, starts_at, ends_at);
CREATE INDEX IF NOT EXISTS idx_alert_silences_rule ON alert_silences(rule_id, starts_at, ends_at);
CREATE INDEX IF NOT EXISTS idx_alert_rule_triggers_rule ON alert_rule_triggers(rule_id, triggered_at DESC);
