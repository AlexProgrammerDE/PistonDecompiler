CREATE TABLE parameter_operations (
    id TEXT PRIMARY KEY,
    binary_id TEXT NOT NULL REFERENCES binaries(id),
    function_id TEXT NOT NULL REFERENCES functions(id),
    input_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    report_json TEXT NOT NULL DEFAULT '{}',
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX parameter_operations_binary ON parameter_operations(binary_id, status);
