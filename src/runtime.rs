use crate::{db::Db, graph};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trace {
    pub version: u32,
    pub id: String,
    pub binary_sha256: String,
    pub scenario: String,
    /// Ghidra image base, not the process load address.
    pub image_base: u64,
    pub pointer_width: u8,
    pub collector: String,
    pub dropped_events: u64,
    pub events: Vec<Event>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Event {
    pub sequence: u64,
    #[serde(default)]
    pub timestamp_us: u64,
    pub thread: u64,
    /// Entry point relative to the module base. Never an arbitrary instruction address.
    pub function_rva: Option<u64>,
    #[serde(flatten)]
    pub observation: Observation,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Observation {
    VirtualDispatch {
        invocation: u64,
        allocation: String,
        object_offset: u64,
        receiver: u64,
        vtable_rva: u64,
        slot_offset: u64,
        site_rva: u64,
        target_rva: u64,
    },
    ThisAdjustment {
        invocation: u64,
        allocation: String,
        receiver_before: u64,
        receiver_after: u64,
        adjustment: i64,
        target_rva: u64,
    },
    Marker {
        label: String,
    },
    Region {
        allocation: String,
        address: u64,
        size: u64,
    },
    Block {
        block_rva: u64,
        hits: u64,
    },
    Coverage {
        hits: u64,
    },
    Call {
        target_rva: u64,
        site_rva: u64,
    },
    Argument {
        invocation: u64,
        index: u8,
        value: String,
    },
    Return {
        invocation: u64,
        value: String,
    },
    Allocation {
        allocation: String,
        address: u64,
        size: u64,
    },
    Free {
        allocation: String,
    },
    Memory {
        allocation: String,
        offset: u64,
        width: u64,
        write: bool,
        value: String,
        instruction_rva: u64,
    },
    Snapshot {
        allocation: String,
        offset: u64,
        bytes: String,
        #[serde(default)]
        invocation: Option<u64>,
        #[serde(default)]
        phase: Option<String>,
        #[serde(default)]
        argument_index: Option<u8>,
    },
}
impl Trace {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && matches!(self.pointer_width, 4 | 8),
            "Unsupported trace version or pointer width"
        );
        ensure!(
            !self.id.is_empty()
                && self.id.len() <= 128
                && !self.scenario.is_empty()
                && self.scenario.len() <= 256,
            "Invalid session identity"
        );
        ensure!(self.events.len() <= 200_000, "Trace exceeds 200000 events");
        let mut allocations = HashMap::new();
        let mut bases: HashMap<&String, u64> = HashMap::new();
        let mut dispatches = HashMap::new();
        let mut seen = std::collections::HashSet::new();
        let mut previous = None;
        for event in &self.events {
            ensure!(
                previous.is_none_or(|p| event.sequence > p),
                "Event sequences must increase"
            );
            previous = Some(event.sequence);
            if let Some(rva) = event.function_rva {
                self.image_base
                    .checked_add(rva)
                    .context("Code address overflow")?;
            }
            match &event.observation {
                Observation::VirtualDispatch {
                    invocation,
                    allocation,
                    object_offset,
                    receiver,
                    vtable_rva,
                    slot_offset,
                    site_rva,
                    target_rva,
                } => {
                    let size = allocations
                        .get(allocation)
                        .context("Dispatch outside object lifetime")?;
                    ensure!(
                        object_offset
                            .checked_add(self.pointer_width.into())
                            .is_some_and(|end| end <= *size)
                            && bases[allocation].checked_add(*object_offset) == Some(*receiver),
                        "Invalid dispatch receiver"
                    );
                    ensure!(
                        *slot_offset % u64::from(self.pointer_width) == 0
                            && *slot_offset < 128 * u64::from(self.pointer_width),
                        "Invalid virtual slot"
                    );
                    for rva in [vtable_rva, site_rva, target_rva] {
                        self.image_base
                            .checked_add(*rva)
                            .context("Dispatch address overflow")?;
                    }
                    ensure!(
                        dispatches
                            .insert(
                                (event.thread, *invocation),
                                (allocation, *receiver, *target_rva)
                            )
                            .is_none(),
                        "Duplicate dispatch invocation"
                    );
                }
                Observation::ThisAdjustment {
                    invocation,
                    allocation,
                    receiver_before,
                    receiver_after,
                    adjustment,
                    target_rva,
                } => {
                    let size = allocations
                        .get(allocation)
                        .context("Adjustment outside object lifetime")?;
                    ensure!(
                        dispatches.remove(&(event.thread, *invocation))
                            == Some((allocation, *receiver_before, *target_rva)),
                        "Adjustment has no matching dispatch"
                    );
                    ensure!(
                        i128::from(*receiver_after) - i128::from(*receiver_before)
                            == i128::from(*adjustment)
                            && *receiver_after >= bases[allocation]
                            && receiver_after
                                .checked_sub(bases[allocation])
                                .is_some_and(|offset| offset < *size),
                        "Invalid this adjustment"
                    );
                }
                Observation::Marker { label } => {
                    ensure!(!label.is_empty() && label.len() <= 256, "Invalid marker");
                }
                Observation::Region {
                    allocation,
                    address,
                    size,
                }
                | Observation::Allocation {
                    allocation,
                    address,
                    size,
                } => {
                    ensure!(
                        !allocation.is_empty()
                            && *size > 0
                            && address.checked_add(*size).is_some()
                            && seen.insert(allocation),
                        "Invalid or reused allocation identity"
                    );
                    allocations.insert(allocation, *size);
                    bases.insert(allocation, *address);
                }
                Observation::Free { allocation } => {
                    ensure!(
                        allocations.remove(allocation).is_some(),
                        "Free references an unknown or expired allocation"
                    );
                }
                Observation::Memory {
                    allocation,
                    offset,
                    width,
                    value,
                    ..
                } => {
                    let size = allocations
                        .get(allocation)
                        .context("Memory access outside allocation lifetime")?;
                    ensure!(
                        *width > 0
                            && *width <= 64
                            && offset.checked_add(*width).is_some_and(|end| end <= *size)
                            && value.len() <= 256,
                        "Invalid memory access bounds"
                    );
                }
                Observation::Snapshot {
                    allocation,
                    offset,
                    bytes,
                    phase,
                    ..
                } => {
                    ensure!(
                        phase
                            .as_deref()
                            .is_none_or(|p| ["entry", "return"].contains(&p)),
                        "Invalid snapshot phase"
                    );
                    let size = allocations
                        .get(allocation)
                        .context("Snapshot outside allocation lifetime")?;
                    let bytes =
                        hex::decode(bytes).context("Snapshot must contain hexadecimal bytes")?;
                    ensure!(
                        bytes.len() <= 4096
                            && offset
                                .checked_add(bytes.len() as u64)
                                .is_some_and(|end| end <= *size),
                        "Invalid snapshot bounds"
                    );
                }
                Observation::Argument { index, value, .. } => {
                    ensure!(*index < 64 && value.len() <= 256, "Invalid argument sample")
                }
                Observation::Return { value, .. } => {
                    ensure!(value.len() <= 256, "Invalid return sample")
                }
                Observation::Block { block_rva, hits } => {
                    self.image_base
                        .checked_add(*block_rva)
                        .context("Block address overflow")?;
                    ensure!(*hits > 0, "Block hit count must be positive");
                }
                Observation::Coverage { hits } => {
                    ensure!(*hits > 0, "Coverage hit count must be positive")
                }
                Observation::Call {
                    target_rva,
                    site_rva,
                } => {
                    self.image_base
                        .checked_add(*target_rva)
                        .context("Target address overflow")?;
                    self.image_base
                        .checked_add(*site_rva)
                        .context("Call site overflow")?;
                }
            }
        }
        Ok(())
    }
}

pub async fn import(db: &Db, binary: &str, path: &Path) -> Result<String> {
    ensure!(
        tokio::fs::metadata(path).await?.len() <= 32 * 1024 * 1024,
        "Trace exceeds 32 MiB"
    );
    let bytes = tokio::fs::read(path).await?;
    let trace: Trace = serde_json::from_slice(&bytes)?;
    trace.validate()?;
    let hash = hex::encode(Sha256::digest(&bytes));
    let mut tx = db.pool.begin_with("BEGIN IMMEDIATE").await?;
    let (sha, paused): (String, bool) =
        sqlx::query_as("SELECT sha256,paused FROM binaries WHERE id=?")
            .bind(binary)
            .fetch_one(&mut *tx)
            .await?;
    ensure!(
        sha == trace.binary_sha256,
        "Trace belongs to another binary build"
    );
    let metadata: Vec<String> = sqlx::query_scalar(
        "SELECT metadata_json FROM extractions WHERE binary_id=? ORDER BY rowid DESC",
    )
    .bind(binary)
    .fetch_all(&mut *tx)
    .await?;
    for metadata in metadata {
        let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
        if let Some(base) = metadata["image_base"].as_u64() {
            ensure!(
                base == trace.image_base
                    && metadata["pointer_width"].as_u64() == Some(u64::from(trace.pointer_width)),
                "Trace image base or pointer width differs from Ghidra"
            );
            break;
        }
    }
    if let Some((owner, old)) = sqlx::query_as::<_, (String, String)>(
        "SELECT binary_id,content_hash FROM runtime_sessions WHERE id=?",
    )
    .bind(&trace.id)
    .fetch_optional(&mut *tx)
    .await?
    {
        ensure!(
            owner == binary && old == hash,
            "Session ID already contains different evidence"
        );
        return Ok(trace.id);
    }
    let active:i64=sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE binary_id=? AND status IN ('running','batched','uncertain')").bind(binary).fetch_one(&mut *tx).await?;
    ensure!(
        paused && active == 0,
        "Pause the binary and resolve active jobs before importing runtime evidence"
    );
    let rows = sqlx::query("SELECT id,address FROM functions WHERE binary_id=?")
        .bind(binary)
        .fetch_all(&mut *tx)
        .await?;
    let mut functions = HashMap::new();
    for row in rows {
        let address: String = row.get("address");
        if let Ok(address) = u64::from_str_radix(address.trim_start_matches("0x"), 16) {
            functions.insert(address, row.get::<String, _>("id"));
        }
    }
    sqlx::query("INSERT INTO runtime_sessions(id,binary_id,scenario,sha256,content_hash,trace_json) VALUES(?,?,?,?,?,?)")
        .bind(&trace.id).bind(binary).bind(&trace.scenario).bind(&sha).bind(hash).bind(std::str::from_utf8(&bytes)?).execute(&mut *tx).await?;
    let mut evidence: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for event in &trace.events {
        let function = event
            .function_rva
            .and_then(|rva| functions.get(&(trace.image_base + rva)));
        let content = serde_json::to_string(event)?;
        let kind = serde_json::to_value(&event.observation)?["kind"]
            .as_str()
            .unwrap()
            .to_owned();
        sqlx::query("INSERT INTO runtime_observations(session_id,sequence,function_id,kind,content) VALUES(?,?,?,?,?)")
            .bind(&trace.id).bind(i64::try_from(event.sequence)?).bind(function).bind(kind).bind(&content).execute(&mut *tx).await?;
        if let Some(function) = function {
            // A bounded, representative prefix is evidence, not exhaustive execution history.
            let lines = evidence.entry(function.clone()).or_default();
            if lines.len() < 128 {
                lines.push(content);
            }
            if let Observation::Call { target_rva, .. }
            | Observation::VirtualDispatch { target_rva, .. } = event.observation
                && let Some(target) = functions.get(&(trace.image_base + target_rva))
            {
                sqlx::query("INSERT OR IGNORE INTO edges(caller,callee) VALUES(?,?)")
                    .bind(function)
                    .bind(target)
                    .execute(&mut *tx)
                    .await?;
            }
        }
    }
    let extraction = crate::knowledge::id();
    sqlx::query("INSERT INTO extractions(id,binary_id,metadata_json) VALUES(?,?,?)")
        .bind(&extraction).bind(binary).bind(serde_json::json!({"kind":"runtime","session":trace.id,"collector":trace.collector,"dropped_events":trace.dropped_events}).to_string()).execute(&mut *tx).await?;
    let allocation_events: HashMap<&str, String> = trace
        .events
        .iter()
        .filter_map(|event| {
            if let Observation::Allocation { allocation, .. }
            | Observation::Region { allocation, .. } = &event.observation
            {
                Some((
                    allocation.as_str(),
                    serde_json::to_string(event).expect("serializable event"),
                ))
            } else {
                None
            }
        })
        .collect();
    let markers: Vec<String> = trace
        .events
        .iter()
        .filter(|e| matches!(e.observation, Observation::Marker { .. }))
        .take(64)
        .map(serde_json::to_string)
        .collect::<Result<_, _>>()?;
    for (function, mut lines) in evidence {
        lines.splice(0..0, markers.clone());
        let allocation_ids: std::collections::BTreeSet<String> = lines
            .iter()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter_map(|v| v["allocation"].as_str().map(str::to_owned))
            .collect();
        let allocations: Vec<String> = allocation_ids
            .iter()
            .filter_map(|id| allocation_events.get(id.as_str()).cloned())
            .collect();
        lines.splice(0..0, allocations);
        let content = format!(
            "Runtime observations from scenario {:?}, session {}. Module RVAs use Ghidra image base {:#x}. Virtual dispatch records a receiver-vtable match, not a complete target set or proven class identity. Snapshots are samples, not proof of an instruction write. Region identity has unknown allocation lifetime. Times are microseconds since collector start; cross-thread ordering is observational, not causal. Samples are incomplete. Dropped events: {}.\n{}",
            trace.scenario,
            trace.id,
            trace.image_base,
            trace.dropped_events,
            lines.join("\n")
        );
        sqlx::query("INSERT INTO artifacts(id,extraction_id,function_id,kind,content,sha256) VALUES(?,?,?,'runtime',?,?)")
            .bind(crate::knowledge::id()).bind(&extraction).bind(&function).bind(&content).bind(hex::encode(Sha256::digest(content.as_bytes()))).execute(&mut *tx).await?;
    }
    // Preserve prior evidence, but force explicit reanalysis after the graph or observations change.
    sqlx::query("UPDATE results SET stale=1 WHERE function_id IN (SELECT id FROM functions WHERE binary_id=?)").bind(binary).execute(&mut *tx).await?;
    graph::rebuild(&mut tx, binary).await?;
    tx.commit().await?;
    Ok(trace.id)
}

pub async fn coverage(db: &Db, binary: &str) -> Result<serde_json::Value> {
    db.binary(binary).await?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM functions WHERE binary_id=? AND skip_reason=''")
            .bind(binary)
            .fetch_one(&db.pool)
            .await?;
    let observed:i64=sqlx::query_scalar("SELECT COUNT(DISTINCT o.function_id) FROM runtime_observations o JOIN runtime_sessions s ON s.id=o.session_id JOIN functions f ON f.id=o.function_id WHERE s.binary_id=? AND f.skip_reason=''").bind(binary).fetch_one(&db.pool).await?;
    let regions=sqlx::query("SELECT f.module,COUNT(*) unknown_functions FROM functions f LEFT JOIN results r ON r.id=f.current_result_id WHERE f.binary_id=? AND f.skip_reason='' AND (r.id IS NULL OR r.stale=1) AND NOT EXISTS(SELECT 1 FROM runtime_observations o WHERE o.function_id=f.id) GROUP BY f.module ORDER BY unknown_functions DESC,f.module").bind(binary).fetch_all(&db.pool).await?;
    Ok(
        serde_json::json!({"functions":total,"observed_functions":observed,"scenarios":sessions(db,binary).await?,"unobserved_unresolved_regions":regions.iter().map(|r|serde_json::json!({"module":r.get::<String,_>("module"),"functions":r.get::<i64,_>("unknown_functions")})).collect::<Vec<_>>(),"ranking":"Unobserved unresolved function count; not predicted scenario coverage"}),
    )
}

pub async fn capture_plan(db: &Db, binary: &str) -> Result<serde_json::Value> {
    let b = db.binary(binary).await?;
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT metadata_json FROM extractions WHERE binary_id=? ORDER BY rowid DESC",
    )
    .bind(binary)
    .fetch_all(&db.pool)
    .await?;
    let base = rows
        .iter()
        .filter_map(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .find_map(|v| v["image_base"].as_u64())
        .context("Export with image-base metadata before creating a capture plan")?;
    let all: Vec<(String, String)> =
        sqlx::query_as("SELECT address,type_context FROM functions WHERE binary_id=?")
            .bind(binary)
            .fetch_all(&db.pool)
            .await?;
    let mut thunk_targets = serde_json::Map::new();
    for (address, context) in all {
        let context: serde_json::Value = serde_json::from_str(&context).unwrap_or_default();
        if let Some(target) = context["cpp"]["thunk_target"]
            .as_str()
            .filter(|s| !s.is_empty())
            && let (Some(source), Some(target)) = (
                crate::cpp::address(&address)
                    .ok()
                    .and_then(|address| address.checked_sub(base)),
                crate::cpp::address(target)
                    .ok()
                    .and_then(|address| address.checked_sub(base)),
            )
        {
            thunk_targets.insert(source.to_string(), serde_json::json!(target));
        }
    }
    let rows=sqlx::query("SELECT address,size,name,disassembly FROM functions WHERE binary_id=? AND skip_reason='' ORDER BY address").bind(binary).fetch_all(&db.pool).await?;
    let mut functions = Vec::new();
    for row in rows {
        let address: String = row.get("address");
        let address = u64::from_str_radix(address.trim_start_matches("0x"), 16)?;
        if let Some(rva) = address.checked_sub(base) {
            let instructions: String = row.get("disassembly");
            let instruction_rvas: Vec<u64> = instructions
                .lines()
                .filter_map(|line| line.split_once(':'))
                .filter_map(|(address, _)| u64::from_str_radix(address.trim(), 16).ok())
                .filter_map(|address| address.checked_sub(base))
                .collect();
            functions.push(serde_json::json!({"rva":rva,"size":row.get::<i64,_>("size"),"name":row.get::<String,_>("name"),"arguments":0,"snapshot_bytes":0,"instruction_rvas":instruction_rvas}));
        }
    }
    Ok(
        serde_json::json!({"binary_sha256":b.sha256,"image_base":base,"max_events":100000,"samples_per_function":8,"allocations":true,"trace_calls":false,"trace_blocks":false,"thunk_targets":thunk_targets,"functions":functions}),
    )
}

pub async fn sessions(db: &Db, binary: &str) -> Result<serde_json::Value> {
    let rows=sqlx::query("SELECT s.id,s.scenario,s.created_at,COUNT(DISTINCT o.function_id) observed,COUNT(DISTINCT CASE WHEN NOT EXISTS(SELECT 1 FROM runtime_observations earlier JOIN runtime_sessions prior ON prior.id=earlier.session_id WHERE prior.binary_id=s.binary_id AND prior.rowid<s.rowid AND earlier.function_id=o.function_id) THEN o.function_id END) novel FROM runtime_sessions s LEFT JOIN runtime_observations o ON o.session_id=s.id WHERE s.binary_id=? GROUP BY s.id ORDER BY s.rowid").bind(binary).fetch_all(&db.pool).await?;
    Ok(serde_json::Value::Array(rows.iter().map(|r|serde_json::json!({"id":r.get::<String,_>("id"),"scenario":r.get::<String,_>("scenario"),"observed_functions":r.get::<i64,_>("observed"),"new_functions":r.get::<i64,_>("novel")})).collect()))
}
