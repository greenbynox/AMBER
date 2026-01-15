-- SLA/SLO dashboards

CREATE TABLE IF NOT EXISTS sla_policies (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    sla_minutes INT NOT NULL DEFAULT 1440,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS slo_policies (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    target_error_rate DOUBLE PRECISION NOT NULL DEFAULT 0.01,
    window_minutes INT NOT NULL DEFAULT 1440,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sla_policies_project ON sla_policies(project_id);
CREATE INDEX IF NOT EXISTS idx_slo_policies_project ON slo_policies(project_id);
