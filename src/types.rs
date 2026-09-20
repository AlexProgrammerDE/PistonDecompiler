use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypeRef {
    Function {
        return_type: Box<TypeRef>,
        parameters: Vec<TypeRef>,
    },
    Primitive {
        #[schemars(regex(pattern = "^(void|bool|i8|u8|i16|u16|i32|u32|i64|u64|f32|f64)$"))]
        name: String,
    },
    Named {
        name: String,
    },
    Pointer {
        to: Box<TypeRef>,
    },
    Array {
        element: Box<TypeRef>,
        #[schemars(range(min = 1))]
        count: u32,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub name: String,
    pub offset: u32,
    pub data_type: TypeRef,
}
/// A materialized prefix is not evidence of the complete object's size.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LayoutExtent {
    #[default]
    Minimum,
    Exact {
        artifact_id: String,
        start_line: u32,
        end_line: u32,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Definition {
    Structure {
        name: String,
        #[schemars(range(min = 1))]
        size: u32,
        fields: Vec<Field>,
        #[serde(default)]
        extent: LayoutExtent,
    },
    Enumeration {
        name: String,
        #[schemars(range(min = 1))]
        size: u32,
        values: BTreeMap<String, i64>,
    },
}
impl Definition {
    pub fn name(&self) -> &str {
        match self {
            Self::Structure { name, .. } | Self::Enumeration { name, .. } => name,
        }
    }
    /// Combine views of an existing named layout only when they share an identical field.
    /// Names or matching offsets alone do not establish object identity.
    pub fn merged(&self, other: &Self) -> Result<Self> {
        if self == other {
            return Ok(self.clone());
        }
        let (
            Self::Structure {
                name,
                size,
                fields,
                extent,
            },
            Self::Structure {
                name: other_name,
                size: other_size,
                fields: other_fields,
                extent: other_extent,
            },
        ) = (self, other)
        else {
            anyhow::bail!("Conflicting type definitions");
        };
        ensure!(
            name == other_name && fields.iter().any(|f| other_fields.contains(f)),
            "Layouts have no shared field identity"
        );
        let merged_size = (*size).max(*other_size);
        ensure!(
            !matches!(extent, LayoutExtent::Exact { .. }) || *size == merged_size,
            "New fields exceed the complete layout"
        );
        ensure!(
            !matches!(other_extent, LayoutExtent::Exact { .. }) || *other_size == merged_size,
            "Existing fields exceed the complete layout"
        );
        let mut merged_fields = fields.clone();
        for field in other_fields {
            if merged_fields.contains(field) {
                continue;
            }
            ensure!(
                !merged_fields
                    .iter()
                    .any(|old| old.name == field.name || old.offset == field.offset),
                "Conflicting field interpretation"
            );
            merged_fields.push(field.clone());
        }
        merged_fields.sort_by_key(|field| field.offset);
        Ok(Self::Structure {
            name: name.clone(),
            size: merged_size,
            fields: merged_fields,
            extent: if matches!(extent, LayoutExtent::Exact { .. }) {
                extent.clone()
            } else {
                other_extent.clone()
            },
        })
    }
    pub fn size(&self) -> u32 {
        match self {
            Self::Structure { size, .. } | Self::Enumeration { size, .. } => *size,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Parameter {
    pub name: String,
    pub data_type: TypeRef,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub address: String,
    pub name: String,
    #[serde(default)]
    pub namespace: Vec<String>,
    pub return_type: TypeRef,
    pub parameters: Vec<Parameter>,
    /// Empty preserves the target's current calling convention.
    #[serde(default)]
    pub calling_convention: String,
    #[serde(default)]
    pub variadic: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypePlan {
    #[serde(default)]
    pub cpp: crate::cpp::CppPlan,
    #[serde(default)]
    pub definitions: Vec<Definition>,
    #[serde(default)]
    pub signatures: Vec<Signature>,
}
pub(crate) fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 160
        && name
            .bytes()
            .enumerate()
            .all(|(i, c)| c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()))
}
impl TypePlan {
    pub fn is_empty(&self) -> bool {
        self.definitions.is_empty() && self.signatures.is_empty() && self.cpp.is_empty()
    }
    pub fn validate(&self, pointer_width: u32) -> Result<()> {
        ensure!(matches!(pointer_width, 4 | 8), "Unsupported pointer width");
        ensure!(
            self.definitions.len() <= 128 && self.signatures.len() <= 128,
            "Type plan exceeds 128 definitions or signatures"
        );
        let mut definitions = HashMap::new();
        for definition in &self.definitions {
            ensure!(
                identifier(definition.name())
                    && definition.size() > 0
                    && definition.size() <= 1_048_576,
                "Invalid type name or size"
            );
            ensure!(
                definitions.insert(definition.name(), definition).is_none(),
                "Duplicate type name"
            );
        }
        for definition in &self.definitions {
            match definition {
                Definition::Structure {
                    name,
                    size,
                    fields,
                    extent,
                } => {
                    if let LayoutExtent::Exact {
                        artifact_id,
                        start_line,
                        end_line,
                    } = extent
                    {
                        ensure!(
                            !artifact_id.is_empty() && *start_line > 0 && end_line >= start_line,
                            "Complete layouts require linked binary size evidence"
                        );
                    }
                    ensure!(fields.len() <= 512, "Too many fields");
                    let mut occupied = Vec::new();
                    let mut names = HashSet::new();
                    for field in fields {
                        ensure!(
                            identifier(&field.name) && names.insert(&field.name),
                            "Invalid or duplicate field name"
                        );
                        let width = type_size(
                            &field.data_type,
                            &definitions,
                            pointer_width,
                            &mut vec![name.as_str()],
                            0,
                        )?;
                        let end = field
                            .offset
                            .checked_add(width)
                            .context("Field size overflow")?;
                        ensure!(width > 0 && end <= *size, "Field outside structure bounds");
                        ensure!(
                            occupied
                                .iter()
                                .all(|&(start, stop)| end <= start || field.offset >= stop),
                            "Overlapping structure fields"
                        );
                        occupied.push((field.offset, end));
                    }
                }
                Definition::Enumeration { size, values, .. } => {
                    ensure!(
                        matches!(*size, 1 | 2 | 4 | 8) && !values.is_empty() && values.len() <= 512,
                        "Invalid enum size or values"
                    );
                    for (name, value) in values {
                        ensure!(identifier(name), "Invalid enum member");
                        if *size < 8 {
                            let bits = size * 8;
                            ensure!(
                                *value >= -(1i64 << (bits - 1)) && *value < (1i64 << bits),
                                "Enum value does not fit"
                            );
                        }
                    }
                }
            }
        }
        let mut addresses = HashSet::new();
        for signature in &self.signatures {
            let address = u64::from_str_radix(signature.address.trim_start_matches("0x"), 16)
                .context("Invalid function address")?;
            ensure!(
                addresses.insert(address) && identifier(&signature.name),
                "Invalid or duplicate function signature"
            );
            ensure!(
                signature.namespace.len() <= 16
                    && signature.namespace.iter().all(|n| identifier(n)),
                "Invalid method namespace"
            );
            ensure!(
                signature.parameters.len() <= 64 && signature.calling_convention.len() <= 64,
                "Signature exceeds limits"
            );
            type_size(
                &signature.return_type,
                &definitions,
                pointer_width,
                &mut vec![],
                0,
            )?;
            let mut names = HashSet::new();
            for parameter in &signature.parameters {
                ensure!(
                    identifier(&parameter.name) && names.insert(&parameter.name),
                    "Invalid or duplicate parameter"
                );
                ensure!(
                    type_size(
                        &parameter.data_type,
                        &definitions,
                        pointer_width,
                        &mut vec![],
                        0
                    )? > 0,
                    "Void parameter"
                );
            }
        }
        self.cpp.validate(&definitions, pointer_width)?;
        Ok(())
    }
}
pub(crate) fn type_size<'a>(
    ty: &'a TypeRef,
    defs: &HashMap<&'a str, &'a Definition>,
    pointer: u32,
    stack: &mut Vec<&'a str>,
    depth: usize,
) -> Result<u32> {
    ensure!(depth < 32, "Type nesting exceeds 32 levels");
    Ok(match ty {
        TypeRef::Function { .. } => anyhow::bail!("A function type requires a pointer"),
        TypeRef::Primitive { name } => match name.as_str() {
            "void" => 0,
            "bool" | "i8" | "u8" => 1,
            "i16" | "u16" => 2,
            "i32" | "u32" | "f32" => 4,
            "i64" | "u64" | "f64" => 8,
            _ => anyhow::bail!("Unknown primitive {name}"),
        },
        TypeRef::Named { name } => {
            let definition = defs
                .get(name.as_str())
                .with_context(|| format!("Unresolved named type {name}"))?;
            ensure!(!stack.contains(&name.as_str()), "By-value type cycle");
            stack.push(name);
            if let Definition::Structure { fields, extent, .. } = definition {
                ensure!(
                    !matches!(extent, LayoutExtent::Minimum),
                    "A partial layout cannot be embedded, returned by value, or used as an array stride"
                );
                for field in fields {
                    type_size(&field.data_type, defs, pointer, stack, depth + 1)?;
                }
            }
            stack.pop();
            definition.size()
        }
        TypeRef::Pointer { to } => {
            validate_reference(to, defs, depth + 1)?;
            validate_sized_reference(to, defs, pointer, depth + 1)?;
            pointer
        }
        TypeRef::Array { element, count } => {
            ensure!(*count > 0, "Empty array");
            let width = type_size(element, defs, pointer, stack, depth + 1)?;
            ensure!(width > 0, "Void array element");
            width.checked_mul(*count).context("Array size overflow")?
        }
    })
}
fn validate_sized_reference(
    ty: &TypeRef,
    defs: &HashMap<&str, &Definition>,
    pointer: u32,
    depth: usize,
) -> Result<()> {
    ensure!(depth < 32, "Type nesting exceeds 32 levels");
    match ty {
        TypeRef::Pointer { to } => validate_sized_reference(to, defs, pointer, depth + 1)?,
        TypeRef::Array { .. } => {
            type_size(ty, defs, pointer, &mut vec![], depth + 1)?;
        }
        TypeRef::Function {
            return_type,
            parameters,
        } => {
            type_size(return_type, defs, pointer, &mut vec![], depth + 1)?;
            for parameter in parameters {
                type_size(parameter, defs, pointer, &mut vec![], depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_reference(ty: &TypeRef, defs: &HashMap<&str, &Definition>, depth: usize) -> Result<()> {
    ensure!(depth < 32, "Type nesting exceeds 32 levels");
    match ty {
        TypeRef::Function {
            return_type,
            parameters,
        } => {
            ensure!(
                parameters.len() <= 64,
                "Too many function pointer parameters"
            );
            validate_reference(return_type, defs, depth + 1)?;
            for parameter in parameters {
                ensure!(
                    !matches!(parameter,TypeRef::Primitive{name} if name=="void"),
                    "Void function pointer parameter"
                );
                validate_reference(parameter, defs, depth + 1)?;
            }
        }
        TypeRef::Named { name } => ensure!(
            defs.contains_key(name.as_str()),
            "Unresolved pointed-to type {name}"
        ),
        TypeRef::Pointer { to } => validate_reference(to, defs, depth + 1)?,
        TypeRef::Array { element, count } => {
            ensure!(*count > 0, "Empty array");
            validate_reference(element, defs, depth + 1)?;
        }
        TypeRef::Primitive { name } => ensure!(
            [
                "void", "bool", "i8", "u8", "i16", "u16", "i32", "u32", "f32", "i64", "u64", "f64"
            ]
            .contains(&name.as_str()),
            "Unknown primitive"
        ),
    }
    Ok(())
}

pub async fn preview(
    db: &crate::db::Db,
    config: &crate::config::Config,
    result: &str,
) -> Result<serde_json::Value> {
    preview_many(db, config, &[result.to_owned()]).await
}
pub async fn preview_many(
    db: &crate::db::Db,
    config: &crate::config::Config,
    results: &[String],
) -> Result<serde_json::Value> {
    use sqlx::Row;
    ensure!(!results.is_empty(), "No type proposals selected");
    let mut binary = None;
    let mut definitions = BTreeMap::new();
    let mut signatures = BTreeMap::new();
    let mut sources = Vec::new();
    let mut cpp = crate::cpp::CppPlan::default();
    for result in results {
        let row=sqlx::query("SELECT r.*,f.binary_id,f.current_result_id FROM results r JOIN functions f ON f.id=r.function_id WHERE r.id=?").bind(result).fetch_one(&db.pool).await?;
        ensure!(
            !row.get::<bool, _>("stale")
                && row.get::<Option<String>, _>("current_result_id").as_deref()
                    == Some(result.as_str()),
            "Result is stale or superseded"
        );
        let owner: String = row.get("binary_id");
        ensure!(
            binary.as_ref().is_none_or(|b| b == &owner),
            "Type proposals span multiple binaries"
        );
        binary = Some(owner);
        let analysis: crate::ai::Analysis =
            serde_json::from_str(&row.get::<String, _>("raw_json"))?;
        let audit: serde_json::Value =
            serde_json::from_str(&row.get::<String, _>("automation_json"))?;
        let plan: TypePlan = audit
            .get("accepted_plan")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()?
            .unwrap_or(analysis.type_plan);
        cpp.merge(plan.cpp)?;
        for definition in plan.definitions {
            let merged = match definitions.get(definition.name()) {
                Some(old) => Definition::merged(old, &definition)?,
                None => definition,
            };
            definitions.insert(merged.name().to_owned(), merged);
        }
        for signature in plan.signatures {
            if let Some(old) = signatures.insert(signature.address.clone(), signature.clone()) {
                ensure!(old == signature, "Conflicting signatures cannot be merged");
            }
        }
        sources.push(serde_json::json!({"id":result,"revision":row.get::<i64,_>("revision")}));
    }
    let binary = binary.unwrap();
    let type_plan = TypePlan {
        cpp,
        definitions: definitions.into_values().collect(),
        signatures: signatures.into_values().collect(),
    };
    ensure!(
        !type_plan.is_empty(),
        "Results contain no structured type proposal"
    );
    ensure!(
        type_plan.validate(8).is_ok() || type_plan.validate(4).is_ok(),
        "Merged type plan violates layout constraints"
    );
    let id = crate::knowledge::id();
    let plan = serde_json::to_string(&type_plan)?;
    let folder = tokio::fs::canonicalize(config.data_dir.join("binaries").join(&binary)).await?;
    let input = folder.join(format!("types-{id}.json"));
    let report = folder.join(format!("types-{id}-preview.json"));
    tokio::fs::write(&input, &plan).await?;
    crate::ghidra::headless(
        config,
        &binary,
        &[
            "-process".into(),
            "program.bin".into(),
            "-readOnly".into(),
            "-noanalysis".into(),
            "-postScript".into(),
            "PistonTypes.java".into(),
            "preview".into(),
            id.clone(),
            input.to_string_lossy().into_owned(),
            "unused".into(),
            report.to_string_lossy().into_owned(),
        ],
        None,
    )
    .await?;
    let preview: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(report).await.with_context(|| {
            format!(
                "Ghidra produced no operation report; inspect {}",
                folder.join("ghidra/headless.log").display()
            )
        })?)?;
    ensure!(
        preview["status"] == "validated",
        "Native type trial rejected: {}",
        preview["error"]
            .as_str()
            .unwrap_or("missing validation result")
    );
    let pointer = preview["expected"]["pointer_width"]
        .as_u64()
        .context("Missing Ghidra pointer width")?;
    type_plan.validate(u32::try_from(pointer)?)?;
    sqlx::query("INSERT INTO type_operations(id,binary_id,result_id,revision,plan_json,expected_json,sources_json,status) VALUES(?,?,?,?,?,?,?,?)")
        .bind(&id).bind(&binary).bind(&results[0]).bind(sources[0]["revision"].as_i64().unwrap()).bind(&plan).bind(preview["expected"].to_string()).bind(serde_json::to_string(&sources)?).bind(if preview["unchanged"] == true { "unchanged" } else { "preview" }).execute(&db.pool).await?;
    Ok(
        serde_json::json!({"id":id,"plan":type_plan,"expected":preview["expected"],"unchanged":preview["unchanged"]}),
    )
}

pub async fn apply(db: &crate::db::Db, config: &crate::config::Config, id: &str) -> Result<()> {
    use sqlx::Row;
    let mut tx = db.pool.begin().await?;
    let row = sqlx::query("SELECT * FROM type_operations WHERE id=?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let binary: String = row.get("binary_id");
    let valid:bool=sqlx::query_scalar("SELECT NOT r.stale AND r.revision=o.revision AND f.current_result_id=r.id FROM type_operations o JOIN results r ON r.id=o.result_id JOIN functions f ON f.id=r.function_id WHERE o.id=?").bind(id).fetch_one(&mut *tx).await?;
    ensure!(
        valid || row.get::<String, _>("status") == "uncertain",
        "Type proposal changed since preview"
    );
    if row.get::<String, _>("status") != "uncertain" {
        let sources: Vec<serde_json::Value> =
            serde_json::from_str(&row.get::<String, _>("sources_json"))?;
        for source in sources {
            let valid:bool=sqlx::query_scalar("SELECT NOT r.stale AND r.revision=? AND f.current_result_id=r.id FROM results r JOIN functions f ON f.id=r.function_id WHERE r.id=?")
                .bind(source["revision"].as_i64().context("Source revision missing")?).bind(source["id"].as_str().context("Source ID missing")?).fetch_one(&mut *tx).await?;
            ensure!(valid, "A source proposal changed since preview");
        }
    }
    let busy:i64=sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM jobs WHERE binary_id=? AND status IN ('running','batched','uncertain'))+(SELECT COUNT(*) FROM apply_operations WHERE binary_id=? AND status IN ('applying','uncertain'))+(SELECT COUNT(*) FROM type_operations WHERE binary_id=? AND id<>? AND status IN ('applying','uncertain'))").bind(&binary).bind(&binary).bind(&binary).bind(id).fetch_one(&mut *tx).await?;
    ensure!(busy == 0, "Another operation owns this binary");
    let paused: bool =
        sqlx::query_scalar("SELECT paused OR recovery_writer FROM binaries WHERE id=?")
            .bind(&binary)
            .fetch_one(&mut *tx)
            .await?;
    ensure!(paused, "Pause analysis before type writeback");
    let changed=sqlx::query("UPDATE type_operations SET status='applying',error='' WHERE id=? AND status IN ('preview','uncertain')").bind(id).execute(&mut *tx).await?.rows_affected();
    ensure!(changed == 1, "Type operation is not ready to apply");
    tx.commit().await?;
    let outcome = async {
        let folder =
            tokio::fs::canonicalize(config.data_dir.join("binaries").join(&binary)).await?;
        let input = folder.join(format!("types-{id}.json"));
        let expected = folder.join(format!("types-{id}-expected.json"));
        let report = folder.join(format!("types-{id}-applied.json"));
        tokio::fs::write(&input, row.get::<String, _>("plan_json")).await?;
        tokio::fs::write(&expected, row.get::<String, _>("expected_json")).await?;
        if report.exists() {
            tokio::fs::remove_file(&report).await?;
        }
        crate::ghidra::headless(
            config,
            &binary,
            &[
                "-process".into(),
                "program.bin".into(),
                "-noanalysis".into(),
                "-postScript".into(),
                "PistonTypes.java".into(),
                "apply".into(),
                id.into(),
                input.to_string_lossy().into_owned(),
                expected.to_string_lossy().into_owned(),
                report.to_string_lossy().into_owned(),
            ],
            None,
        )
        .await?;
        let report: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(report).await.with_context(|| {
                format!(
                    "Ghidra produced no operation report; inspect {}",
                    folder.join("ghidra/headless.log").display()
                )
            })?)?;
        ensure!(
            report["status"] == "applied",
            "Ghidra did not confirm type application"
        );
        crate::ghidra::refresh(db, config, &binary).await?;
        anyhow::Ok(())
    }
    .await;
    match outcome {
        Ok(()) => {
            sqlx::query("UPDATE type_operations SET status='applied' WHERE id=?")
                .bind(id)
                .execute(&db.pool)
                .await?;
            Ok(())
        }
        Err(error) => {
            sqlx::query("UPDATE type_operations SET status='uncertain',error=? WHERE id=?")
                .bind(format!("{error:#}"))
                .bind(id)
                .execute(&db.pool)
                .await?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod native_tests;
