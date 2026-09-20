ALTER TABLE binaries ADD COLUMN recovery_writer INTEGER NOT NULL DEFAULT 0;
ALTER TABLE results ADD COLUMN automation_json TEXT NOT NULL DEFAULT '{}';
CREATE TABLE automatic_recovery (
 id TEXT PRIMARY KEY,
 binary_id TEXT NOT NULL REFERENCES binaries(id),
 run_id TEXT NOT NULL,
 pass INTEGER NOT NULL DEFAULT 0,
 max_passes INTEGER NOT NULL DEFAULT 3,
 status TEXT NOT NULL DEFAULT 'assessing',
 name_operation TEXT,
 type_operation TEXT,
 type_results TEXT NOT NULL DEFAULT '[]',
 attempts INTEGER NOT NULL DEFAULT 0,
 error TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL DEFAULT (unixepoch()),
 updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
 UNIQUE(binary_id,run_id)
);
