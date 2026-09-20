ALTER TABLE jobs ADD COLUMN started_at INTEGER;
ALTER TABLE jobs ADD COLUMN finished_at INTEGER;
CREATE TRIGGER job_progress_started AFTER UPDATE OF status ON jobs
WHEN NEW.status='running' AND OLD.status!='running'
BEGIN UPDATE jobs SET started_at=unixepoch(),finished_at=NULL WHERE id=NEW.id; END;
CREATE TRIGGER job_progress_finished AFTER UPDATE OF status ON jobs
WHEN NEW.status IN ('completed','failed','uncertain') AND OLD.status!=NEW.status
BEGIN UPDATE jobs SET finished_at=unixepoch() WHERE id=NEW.id; END;
CREATE TABLE extraction_progress (
 binary_id TEXT PRIMARY KEY REFERENCES binaries(id),
 phase TEXT NOT NULL, completed INTEGER NOT NULL DEFAULT 0, total INTEGER NOT NULL DEFAULT 0,
 started_at INTEGER NOT NULL DEFAULT (unixepoch()), phase_started_at INTEGER NOT NULL DEFAULT (unixepoch()),
 updated_at INTEGER NOT NULL DEFAULT (unixepoch()), detail TEXT NOT NULL DEFAULT ''
);
ALTER TABLE apply_operations ADD COLUMN updated_at INTEGER;
ALTER TABLE type_operations ADD COLUMN updated_at INTEGER;
ALTER TABLE recovery_iterations ADD COLUMN updated_at INTEGER;
CREATE TRIGGER apply_progress AFTER UPDATE OF status ON apply_operations
BEGIN UPDATE apply_operations SET updated_at=unixepoch() WHERE id=NEW.id; END;
CREATE TRIGGER type_progress AFTER UPDATE OF status ON type_operations
BEGIN UPDATE type_operations SET updated_at=unixepoch() WHERE id=NEW.id; END;
CREATE TRIGGER recovery_progress AFTER UPDATE OF status ON recovery_iterations
BEGIN UPDATE recovery_iterations SET updated_at=unixepoch() WHERE id=NEW.id; END;
