ALTER TABLE jobs ADD COLUMN parent_job_id TEXT REFERENCES jobs(id);
CREATE TABLE decisions (
 id TEXT PRIMARY KEY,
 job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id),
 function_id TEXT NOT NULL REFERENCES functions(id),
 stage TEXT NOT NULL,
 model TEXT NOT NULL,
 prompt_hash TEXT NOT NULL,
 extraction_id TEXT NOT NULL,
 request_json TEXT NOT NULL,
 response_json TEXT NOT NULL,
 route TEXT NOT NULL,
 input_tokens INTEGER NOT NULL,
 output_tokens INTEGER NOT NULL,
 cost_usd REAL NOT NULL,
 latency_ms INTEGER NOT NULL,
 created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX decisions_function ON decisions(function_id, created_at);
CREATE VIEW provider_usage AS
 SELECT function_id, stage, model, input_tokens, output_tokens, cost_usd, latency_ms, created_at FROM results WHERE author='model'
 UNION ALL
 SELECT function_id, stage, model, input_tokens, output_tokens, cost_usd, latency_ms, created_at FROM decisions;
