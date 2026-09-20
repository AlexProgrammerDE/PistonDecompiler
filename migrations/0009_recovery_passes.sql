CREATE TABLE recovery_passes (
 cycle_id TEXT NOT NULL REFERENCES automatic_recovery(id),
 run_id TEXT NOT NULL,
 pass INTEGER NOT NULL,
 selected INTEGER NOT NULL,
 reason TEXT NOT NULL,
 created_at INTEGER NOT NULL DEFAULT (unixepoch()),
 PRIMARY KEY(cycle_id, pass)
);
