CREATE TABLE recordings (
 id TEXT PRIMARY KEY, binary_id TEXT NOT NULL REFERENCES binaries(id),
 scenario TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL,
 options_json TEXT NOT NULL, error TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL DEFAULT (unixepoch()), finished_at INTEGER,
 analysis_run_id TEXT, ghidra_status TEXT NOT NULL DEFAULT 'pending'
);
CREATE UNIQUE INDEX one_active_recording ON recordings((1))
 WHERE status IN ('starting','recording','stopping','importing');
CREATE TRIGGER recording_pause_guard BEFORE UPDATE OF paused ON binaries
 WHEN NEW.paused=0 AND EXISTS(SELECT 1 FROM recordings WHERE binary_id=NEW.id AND status IN ('starting','recording','stopping','importing'))
 BEGIN SELECT RAISE(ABORT,'Stop the recording before resuming analysis'); END;
