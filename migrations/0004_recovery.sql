CREATE TABLE function_components (
 function_id TEXT PRIMARY KEY REFERENCES functions(id),
 component_id TEXT NOT NULL
);
CREATE INDEX component_members ON function_components(component_id);
CREATE TABLE runtime_sessions (
 id TEXT PRIMARY KEY, binary_id TEXT NOT NULL REFERENCES binaries(id),
 scenario TEXT NOT NULL, sha256 TEXT NOT NULL, content_hash TEXT NOT NULL,
 trace_json TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE runtime_observations (
 session_id TEXT NOT NULL REFERENCES runtime_sessions(id),
 sequence INTEGER NOT NULL, function_id TEXT REFERENCES functions(id),
 kind TEXT NOT NULL, content TEXT NOT NULL,
 PRIMARY KEY(session_id,sequence)
);
CREATE INDEX runtime_function ON runtime_observations(function_id);
CREATE TABLE type_operations (
 id TEXT PRIMARY KEY, binary_id TEXT NOT NULL REFERENCES binaries(id),
 result_id TEXT REFERENCES results(id), revision INTEGER NOT NULL DEFAULT 0,
 plan_json TEXT NOT NULL, expected_json TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'preview', error TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
ALTER TABLE functions ADD COLUMN type_context TEXT NOT NULL DEFAULT '{}';
CREATE TABLE recovery_iterations (
 id TEXT PRIMARY KEY, binary_id TEXT NOT NULL REFERENCES binaries(id),
 component_id TEXT NOT NULL, iteration INTEGER NOT NULL,
 run_id TEXT NOT NULL REFERENCES analysis_runs(id),
 status TEXT NOT NULL DEFAULT 'analyzing', plan_hash TEXT NOT NULL DEFAULT '',
 error TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
ALTER TABLE type_operations ADD COLUMN sources_json TEXT NOT NULL DEFAULT '[]';
