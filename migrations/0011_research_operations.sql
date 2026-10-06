CREATE TABLE research_operations (
    id TEXT PRIMARY KEY,
    binary_id TEXT NOT NULL REFERENCES binaries(id),
    kind TEXT NOT NULL CHECK(kind IN ('annotations','types')),
    input_json TEXT NOT NULL,
    report_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL CHECK(status IN ('preview','rejected','applying','applied','uncertain')),
    error TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX research_operations_binary ON research_operations(binary_id, status);
