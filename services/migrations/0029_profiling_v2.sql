-- Profiling v2 indexes
CREATE INDEX IF NOT EXISTS idx_profiles_project_created_at ON profiles(project_id, created_at DESC);
