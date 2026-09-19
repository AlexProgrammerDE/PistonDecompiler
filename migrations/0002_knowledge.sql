CREATE TABLE jobs_new (
 id TEXT PRIMARY KEY, binary_id TEXT NOT NULL REFERENCES binaries(id),
 function_id TEXT NOT NULL REFERENCES functions(id), stage TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0,
 priority INTEGER NOT NULL DEFAULT 0, available_at INTEGER NOT NULL DEFAULT 0,
 updated_at INTEGER NOT NULL DEFAULT (unixepoch()), error TEXT NOT NULL DEFAULT '',
 reserved_usd REAL NOT NULL DEFAULT 0, batch_id TEXT,
 run_id TEXT NOT NULL DEFAULT 'legacy', input_json TEXT NOT NULL DEFAULT '', transcript_json TEXT NOT NULL DEFAULT '[]', accounted_usd REAL NOT NULL DEFAULT 0,
 UNIQUE(function_id,stage,run_id)
);

CREATE TABLE results_new (
 id TEXT PRIMARY KEY, job_id TEXT UNIQUE REFERENCES jobs_new(id),
 function_id TEXT NOT NULL REFERENCES functions(id), stage TEXT NOT NULL,
 model TEXT NOT NULL, prompt_hash TEXT NOT NULL, raw_json TEXT NOT NULL,
 proposed_name TEXT NOT NULL, summary TEXT NOT NULL, confidence REAL NOT NULL,
 review TEXT NOT NULL DEFAULT 'pending', input_tokens INTEGER NOT NULL,
 output_tokens INTEGER NOT NULL, cost_usd REAL NOT NULL, latency_ms INTEGER NOT NULL,
 created_at INTEGER NOT NULL DEFAULT (unixepoch()),
 parent_id TEXT, author TEXT NOT NULL DEFAULT 'model', stale INTEGER NOT NULL DEFAULT 0,
 revision INTEGER NOT NULL DEFAULT 0, name_review TEXT NOT NULL DEFAULT 'pending', summary_review TEXT NOT NULL DEFAULT 'pending',
 extraction_id TEXT NOT NULL DEFAULT ''
);


INSERT INTO jobs_new(id,binary_id,function_id,stage,status,attempts,priority,available_at,updated_at,error,reserved_usd,batch_id) SELECT id,binary_id,function_id,stage,status,attempts,priority,available_at,updated_at,error,reserved_usd,batch_id FROM jobs;
INSERT INTO results_new(id,job_id,function_id,stage,model,prompt_hash,raw_json,proposed_name,summary,confidence,review,input_tokens,output_tokens,cost_usd,latency_ms,created_at,name_review,summary_review)
SELECT id,job_id,function_id,stage,model,prompt_hash,raw_json,proposed_name,summary,confidence,CASE WHEN review IN ('applying','applied') THEN 'accepted' ELSE review END,input_tokens,output_tokens,cost_usd,latency_ms,created_at,CASE WHEN review IN ('accepted','applying','applied') THEN 'accepted' ELSE review END,CASE WHEN review IN ('accepted','applying','applied') THEN 'accepted' ELSE review END FROM results;
DROP TABLE results;
DROP TABLE jobs;
ALTER TABLE jobs_new RENAME TO jobs;
ALTER TABLE results_new RENAME TO results;
CREATE INDEX jobs_claim ON jobs(status,available_at,priority);
CREATE INDEX results_function ON results(function_id,created_at);
ALTER TABLE functions ADD COLUMN current_result_id TEXT;
ALTER TABLE functions ADD COLUMN comment TEXT NOT NULL DEFAULT '';
UPDATE functions SET current_result_id=(SELECT id FROM results WHERE function_id=functions.id ORDER BY CASE stage WHEN 'escalate' THEN 3 WHEN 'propagate' THEN 2 ELSE 1 END DESC,created_at DESC,id DESC LIMIT 1);
CREATE TABLE extractions(id TEXT PRIMARY KEY,binary_id TEXT NOT NULL REFERENCES binaries(id),metadata_json TEXT NOT NULL,created_at INTEGER NOT NULL DEFAULT (unixepoch()));
CREATE TABLE artifacts(id TEXT PRIMARY KEY,extraction_id TEXT NOT NULL REFERENCES extractions(id),function_id TEXT NOT NULL REFERENCES functions(id),kind TEXT NOT NULL,content TEXT NOT NULL,sha256 TEXT NOT NULL);
CREATE INDEX artifacts_function ON artifacts(function_id,kind);
CREATE TABLE result_dependencies(result_id TEXT NOT NULL REFERENCES results(id),dependency_id TEXT NOT NULL REFERENCES results(id),PRIMARY KEY(result_id,dependency_id));
CREATE INDEX dependencies_reverse ON result_dependencies(dependency_id);
CREATE TABLE review_decisions(id TEXT PRIMARY KEY,result_id TEXT NOT NULL REFERENCES results(id),field TEXT NOT NULL,decision TEXT NOT NULL,reason TEXT NOT NULL,revision INTEGER NOT NULL,created_at INTEGER NOT NULL DEFAULT (unixepoch()));
CREATE TABLE investigations(id TEXT PRIMARY KEY,binary_id TEXT NOT NULL REFERENCES binaries(id),question TEXT NOT NULL,notes TEXT NOT NULL DEFAULT '',budget_usd REAL NOT NULL,revision INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL DEFAULT (unixepoch()));
CREATE TABLE investigation_functions(investigation_id TEXT NOT NULL REFERENCES investigations(id),function_id TEXT NOT NULL REFERENCES functions(id),PRIMARY KEY(investigation_id,function_id));
CREATE TABLE investigation_findings(investigation_id TEXT NOT NULL REFERENCES investigations(id),result_id TEXT NOT NULL REFERENCES results(id),PRIMARY KEY(investigation_id,result_id));
CREATE TABLE analysis_runs(id TEXT PRIMARY KEY,binary_id TEXT NOT NULL REFERENCES binaries(id),investigation_id TEXT REFERENCES investigations(id),reason TEXT NOT NULL,config_json TEXT NOT NULL,created_at INTEGER NOT NULL DEFAULT (unixepoch()));
CREATE TABLE apply_operations(id TEXT PRIMARY KEY,binary_id TEXT NOT NULL REFERENCES binaries(id),status TEXT NOT NULL DEFAULT 'preview',error TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL DEFAULT (unixepoch()));
CREATE TABLE apply_items(operation_id TEXT NOT NULL REFERENCES apply_operations(id),result_id TEXT NOT NULL REFERENCES results(id),revision INTEGER NOT NULL,address TEXT NOT NULL,expected_name TEXT NOT NULL,expected_comment TEXT NOT NULL,name TEXT NOT NULL,summary TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',error TEXT NOT NULL DEFAULT '',PRIMARY KEY(operation_id,result_id));

ALTER TABLE binaries ADD COLUMN active_run_id TEXT;
