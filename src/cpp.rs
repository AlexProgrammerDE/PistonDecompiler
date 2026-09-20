//! Evidence-backed C++ layouts and decompiler variable refinements.
use crate::types::{Definition, TypeRef};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CppPlan {
    #[serde(default)]
    pub classes: Vec<ClassLayout>,
    #[serde(default)]
    pub vtables: Vec<VtableBinding>,
    #[serde(default)]
    pub locals: Vec<LocalRefinement>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassLayout {
    pub name: String,
    pub bases: Vec<BaseSubobject>,
    pub vptrs: Vec<Vptr>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BaseSubobject {
    pub name: String,
    pub offset: u32,
    pub virtual_base: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Vptr {
    pub offset: u32,
    pub table_type: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VtableBinding {
    pub address: String,
    pub table_type: String,
    /// Exact pointer bytes must resolve to these targets before writeback.
    pub targets: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalRefinement {
    pub function: String,
    pub storage: String,
    pub first_use: String,
    pub expected_name: String,
    pub name: String,
    pub data_type: TypeRef,
}
impl CppPlan {
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() && self.vtables.is_empty() && self.locals.is_empty()
    }
    pub fn validate(&self, definitions: &HashMap<&str, &Definition>, pointer: u32) -> Result<()> {
        ensure!(
            self.classes.len() <= 128 && self.vtables.len() <= 128 && self.locals.len() <= 256,
            "C++ plan exceeds limits"
        );
        let structure = |name: &str| -> Result<(u32, &Vec<crate::types::Field>)> {
            match definitions.get(name) {
                Some(Definition::Structure { size, fields, .. }) => Ok((*size, fields)),
                _ => anyhow::bail!("C++ layout requires a structure definition: {name}"),
            }
        };
        let mut classes = HashSet::new();
        for class in &self.classes {
            ensure!(classes.insert(&class.name), "Duplicate class layout");
            let (size, fields) = structure(&class.name)?;
            ensure!(
                class.bases.len() <= 64 && class.vptrs.len() <= 64,
                "Too many subobjects"
            );
            let mut bases = HashSet::new();
            for base in &class.bases {
                let (base_size, _) = structure(&base.name)?;
                ensure!(
                    bases.insert((&base.name, base.offset))
                        && base
                            .offset
                            .checked_add(base_size)
                            .is_some_and(|end| end <= size),
                    "Invalid base subobject bounds"
                );
                ensure!(
                    fields.iter().any(|f| f.offset == base.offset
                        && f.data_type
                            == TypeRef::Named {
                                name: base.name.clone()
                            }),
                    "Base must be represented by an explicit embedded field"
                );
            }
            let mut offsets = HashSet::new();
            for vptr in &class.vptrs {
                structure(&vptr.table_type)?;
                ensure!(
                    offsets.insert(vptr.offset)
                        && vptr
                            .offset
                            .checked_add(pointer)
                            .is_some_and(|end| end <= size),
                    "Invalid vptr offset"
                );
                // A vptr can belong to an embedded base subobject.
                ensure!(
                    has_vptr(&class.name, vptr.offset, &vptr.table_type, definitions, 0),
                    "Vptr must match a pointer field in the class or a base"
                );
            }
        }
        let mut addresses = HashSet::new();
        for table in &self.vtables {
            ensure!(
                addresses.insert(address(&table.address)?)
                    && !table.targets.is_empty()
                    && table.targets.len() <= 128,
                "Invalid or duplicate vtable binding"
            );
            let (size, fields) = structure(&table.table_type)?;
            ensure!(
                size as usize == table.targets.len() * pointer as usize,
                "Vtable size differs from observed slots"
            );
            for (index, target) in table.targets.iter().enumerate() {
                address(target)?;
                ensure!(fields.iter().any(|f|f.offset==index as u32*pointer && matches!(&f.data_type,TypeRef::Pointer{to} if matches!(**to,TypeRef::Function{..}))),"Every vtable slot needs a function pointer field");
            }
        }
        let mut locals = HashSet::new();
        for local in &self.locals {
            address(&local.function)?;
            if !local.first_use.is_empty() {
                address(&local.first_use)?;
            }
            ensure!(
                locals.insert((&local.function, &local.storage, &local.first_use))
                    && !local.storage.is_empty()
                    && local.storage.len() <= 256
                    && crate::types::identifier(&local.name)
                    && !local.expected_name.is_empty()
                    && local.expected_name.len() <= 256,
                "Invalid local variable identity"
            );
            ensure!(
                crate::types::type_size(&local.data_type, definitions, pointer, &mut vec![], 0)?
                    > 0,
                "Void local variable"
            );
        }
        Ok(())
    }
    pub fn merge(&mut self, other: Self) -> Result<()> {
        for class in other.classes {
            if let Some(old) = self.classes.iter().find(|c| c.name == class.name) {
                ensure!(old == &class, "Conflicting class layouts");
            } else {
                self.classes.push(class);
            }
        }
        for table in other.vtables {
            if let Some(old) = self
                .vtables
                .iter()
                .find(|t| address(&t.address).ok() == address(&table.address).ok())
            {
                ensure!(old == &table, "Conflicting vtable bindings");
            } else {
                self.vtables.push(table);
            }
        }
        for local in other.locals {
            if let Some(old) = self.locals.iter().find(|l| {
                l.function == local.function
                    && l.storage == local.storage
                    && l.first_use == local.first_use
            }) {
                ensure!(old == &local, "Conflicting local refinements");
            } else {
                self.locals.push(local);
            }
        }
        Ok(())
    }
}
fn has_vptr(
    name: &str,
    offset: u32,
    table: &str,
    definitions: &HashMap<&str, &Definition>,
    depth: usize,
) -> bool {
    if depth >= 32 {
        return false;
    }
    let Some(Definition::Structure { fields, .. }) = definitions.get(name) else {
        return false;
    };
    fields.iter().any(|field| match &field.data_type {
        TypeRef::Pointer { to } => {
            field.offset == offset && matches!(&**to,TypeRef::Named{name} if name==table)
        }
        TypeRef::Named { name } if field.offset <= offset => {
            has_vptr(name, offset - field.offset, table, definitions, depth + 1)
        }
        _ => false,
    })
}
pub fn address(value: &str) -> Result<u64> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).context("Invalid C++ evidence address")
}
