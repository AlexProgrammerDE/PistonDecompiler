ALTER TABLE jobs ADD COLUMN dispatch_id TEXT NOT NULL DEFAULT '';
CREATE TABLE provider_requests (
 id TEXT PRIMARY KEY,
 job_id TEXT NOT NULL REFERENCES jobs(id),
 dispatch_id TEXT NOT NULL,
 response_json TEXT NOT NULL DEFAULT '',
 cost_usd REAL CHECK(cost_usd >= 0),
 created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX provider_requests_dispatch ON provider_requests(job_id,dispatch_id);
INSERT INTO provider_requests(id,job_id,dispatch_id,response_json,cost_usd,created_at)
SELECT 'decision:'||id,job_id,'legacy',response_json,
 CASE WHEN json_type(response_json,'$.usage.cost') IN ('integer','real') AND json_extract(response_json,'$.usage.cost')>=0 THEN json_extract(response_json,'$.usage.cost') END,
 created_at FROM decisions;
-- Old chat results contain analysis JSON, not billing receipts. Their cost is unknown.
INSERT INTO provider_requests(id,job_id,dispatch_id,response_json,created_at)
SELECT 'result:'||id,job_id,'legacy','',created_at FROM results WHERE author='model';
DROP VIEW provider_usage;
ALTER TABLE binaries DROP COLUMN budget_usd;
ALTER TABLE binaries DROP COLUMN spent_usd;
ALTER TABLE binaries DROP COLUMN reserved_usd;
ALTER TABLE jobs DROP COLUMN reserved_usd;
ALTER TABLE jobs DROP COLUMN accounted_usd;
ALTER TABLE investigations DROP COLUMN budget_usd;
ALTER TABLE results DROP COLUMN cost_usd;
ALTER TABLE results ADD COLUMN cost_usd REAL;
ALTER TABLE decisions DROP COLUMN cost_usd;
ALTER TABLE decisions ADD COLUMN cost_usd REAL;
UPDATE decisions SET cost_usd=(SELECT cost_usd FROM provider_requests WHERE id='decision:'||decisions.id);
CREATE VIEW provider_usage AS
 SELECT j.function_id,j.stage,
 COALESCE(json_extract(NULLIF(p.response_json,''),'$.model'),r.model,d.model,json_extract(NULLIF(j.input_json,''),'$.config.model'),'unknown') model,
 COALESCE(json_extract(NULLIF(p.response_json,''),'$.usage.prompt_tokens'),json_extract(NULLIF(p.response_json,''),'$.usage.input_tokens'),r.input_tokens,0) input_tokens,
 COALESCE(json_extract(NULLIF(p.response_json,''),'$.usage.completion_tokens'),json_extract(NULLIF(p.response_json,''),'$.usage.output_tokens'),r.output_tokens,0) output_tokens,
 p.cost_usd, NULL latency_ms,p.created_at
 FROM provider_requests p JOIN jobs j ON j.id=p.job_id
 LEFT JOIN results r ON p.id='result:'||r.id
 LEFT JOIN decisions d ON p.id='decision:'||d.id;
UPDATE jobs SET input_json=json_remove(input_json,'$.config.budget_usd','$.config.input_usd_per_million','$.config.output_usd_per_million','$.config.escalation_input_usd_per_million','$.config.escalation_output_usd_per_million','$.config.batch_price_multiplier','$.config.decisions.input_usd_per_million','$.config.decisions.output_usd_per_million') WHERE json_valid(input_json);
UPDATE analysis_runs SET config_json=json_remove(config_json,'$.budget_usd','$.input_usd_per_million','$.output_usd_per_million','$.escalation_input_usd_per_million','$.escalation_output_usd_per_million','$.batch_price_multiplier','$.decisions.input_usd_per_million','$.decisions.output_usd_per_million') WHERE json_valid(config_json);
