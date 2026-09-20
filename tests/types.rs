use piston_decompiler::types::*;
fn primitive() -> TypeRef {
    TypeRef::Primitive { name: "u32".into() }
}
fn plan(fields: Vec<Field>) -> TypePlan {
    TypePlan {
        definitions: vec![Definition::Structure {
            name: "Player".into(),
            extent: Default::default(),
            size: 16,
            fields,
        }],
        signatures: vec![],
        ..Default::default()
    }
}
#[test]
fn rejects_overlaps_unknown_references_and_by_value_cycles() {
    let field = Field {
        name: "health".into(),
        offset: 0,
        data_type: primitive(),
    };
    plan(vec![field.clone()]).validate(8).unwrap();
    assert!(
        plan(vec![
            field.clone(),
            Field {
                name: "other".into(),
                offset: 2,
                data_type: primitive()
            }
        ])
        .validate(8)
        .is_err()
    );
    assert!(
        plan(vec![Field {
            offset: 14,
            ..field.clone()
        }])
        .validate(8)
        .is_err()
    );
    assert!(
        plan(vec![Field {
            data_type: TypeRef::Named {
                name: "Player".into()
            },
            ..field.clone()
        }])
        .validate(8)
        .is_err()
    );
    plan(vec![Field {
        data_type: TypeRef::Pointer {
            to: Box::new(TypeRef::Named {
                name: "Player".into(),
            }),
        },
        ..field.clone()
    }])
    .validate(8)
    .unwrap();
    assert!(
        plan(vec![Field {
            data_type: TypeRef::Pointer {
                to: Box::new(TypeRef::Named {
                    name: "Missing".into()
                })
            },
            ..field
        }])
        .validate(8)
        .is_err()
    );
}

#[test]
fn partial_views_merge_without_claiming_complete_size_or_losing_fields() {
    let field = |name: &str, offset| Field {
        name: name.into(),
        offset,
        data_type: primitive(),
    };
    let mut left = plan(vec![field("first", 0)]);
    let mut right = plan(vec![field("first", 0), field("last", 12)]);
    if let Definition::Structure { size, .. } = &mut left.definitions[0] {
        *size = 4;
    }
    let merged = left.definitions[0].merged(&right.definitions[0]).unwrap();
    right.definitions[0] = merged.clone();
    right.validate(8).unwrap();
    assert_eq!(merged.size(), 16);
    assert!(
        matches!(merged, Definition::Structure { extent: LayoutExtent::Minimum, ref fields, .. } if fields.len()==2)
    );
    if let Definition::Structure { extent, .. } = &mut left.definitions[0] {
        *extent = LayoutExtent::Exact {
            artifact_id: "binary-artifact".into(),
            start_line: 1,
            end_line: 1,
        };
    }
    assert!(left.definitions[0].merged(&right.definitions[0]).is_err());
    assert!(
        plan(vec![field("unrelated", 0)]).definitions[0]
            .merged(&right.definitions[0])
            .is_err()
    );
}

#[test]
fn partial_layouts_are_pointer_views_not_array_strides_or_by_value_objects() {
    let mut p = plan(vec![]);
    let named = TypeRef::Named {
        name: "Player".into(),
    };
    p.signatures.push(Signature {
        address: "1000".into(),
        name: "inspect".into(),
        namespace: vec![],
        return_type: TypeRef::Primitive {
            name: "void".into(),
        },
        parameters: vec![Parameter {
            name: "object".into(),
            data_type: TypeRef::Pointer {
                to: Box::new(named.clone()),
            },
        }],
        calling_convention: String::new(),
        variadic: false,
    });
    p.validate(8).unwrap();
    p.signatures[0].parameters[0].data_type = TypeRef::Pointer {
        to: Box::new(TypeRef::Array {
            element: Box::new(named.clone()),
            count: 2,
        }),
    };
    assert!(p.validate(8).is_err());
    p.signatures[0].parameters[0].data_type = named;
    assert!(p.validate(8).is_err());
    if let Definition::Structure { extent, .. } = &mut p.definitions[0] {
        *extent = LayoutExtent::Exact {
            artifact_id: "binary-artifact".into(),
            start_line: 1,
            end_line: 1,
        };
    }
    p.validate(8).unwrap();
}
