CREATE TABLE binaries (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, sha256 TEXT NOT NULL UNIQUE,
 size INTEGER NOT NULL, architecture TEXT NOT NULL, format TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'imported', path TEXT NOT NULL,
 created_at INTEGER NOT NULL DEFAULT (unixepoch()), error TEXT NOT NULL DEFAULT '',
 paused INTEGER NOT NULL DEFAULT 1, budget_usd REAL NOT NULL,
 spent_usd REAL NOT NULL DEFAULT 0, reserved_usd REAL NOT NULL DEFAULT 0
);
CREATE TABLE functions (
 id TEXT PRIMARY KEY, binary_id TEXT NOT NULL REFERENCES binaries(id),
 address TEXT NOT NULL, name TEXT NOT NULL, size INTEGER NOT NULL,
 pseudocode TEXT NOT NULL DEFAULT '', disassembly TEXT NOT NULL DEFAULT '', pcode TEXT NOT NULL DEFAULT '',
 strings_json TEXT NOT NULL DEFAULT '[]', imports_json TEXT NOT NULL DEFAULT '[]',
 skip_reason TEXT NOT NULL DEFAULT '', module TEXT NOT NULL DEFAULT '',
 fingerprint TEXT NOT NULL DEFAULT '', UNIQUE(binary_id,address)
);
CREATE INDEX functions_binary ON functions(binary_id,address);
CREATE TABLE edges (caller TEXT NOT NULL REFERENCES functions(id), callee TEXT NOT NULL REFERENCES functions(id), PRIMARY KEY(caller,callee));
CREATE INDEX edges_callee ON edges(callee);
CREATE VIRTUAL TABLE function_search USING fts5(function_id UNINDEXED, name, pseudocode, summary);
CREATE TABLE jobs (
 id TEXT PRIMARY KEY, binary_id TEXT NOT NULL REFERENCES binaries(id),
 function_id TEXT NOT NULL REFERENCES functions(id), stage TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0,
 priority INTEGER NOT NULL DEFAULT 0, available_at INTEGER NOT NULL DEFAULT 0,
 updated_at INTEGER NOT NULL DEFAULT (unixepoch()), error TEXT NOT NULL DEFAULT '',
 reserved_usd REAL NOT NULL DEFAULT 0, batch_id TEXT,
 UNIQUE(function_id,stage)
);
CREATE INDEX jobs_claim ON jobs(status, available_at, priority);
CREATE TABLE results (
 id TEXT PRIMARY KEY, job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id),
 function_id TEXT NOT NULL REFERENCES functions(id), stage TEXT NOT NULL,
 model TEXT NOT NULL, prompt_hash TEXT NOT NULL, raw_json TEXT NOT NULL,
 proposed_name TEXT NOT NULL, summary TEXT NOT NULL, confidence REAL NOT NULL,
 review TEXT NOT NULL DEFAULT 'pending', input_tokens INTEGER NOT NULL,
 output_tokens INTEGER NOT NULL, cost_usd REAL NOT NULL, latency_ms INTEGER NOT NULL,
 created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX results_function ON results(function_id,created_at);
CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, binary_id TEXT NOT NULL REFERENCES binaries(id), created_at INTEGER NOT NULL DEFAULT (unixepoch()), level TEXT NOT NULL, message TEXT NOT NULL);
CREATE TABLE batches (id TEXT PRIMARY KEY, binary_id TEXT NOT NULL REFERENCES binaries(id), remote_id TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, path TEXT NOT NULL, model TEXT NOT NULL, provider_url TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT (unixepoch()));
