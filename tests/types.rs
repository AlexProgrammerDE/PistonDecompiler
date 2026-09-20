use piston_decompiler::types::*;
fn primitive() -> TypeRef {
    TypeRef::Primitive { name: "u32".into() }
}
fn plan(fields: Vec<Field>) -> TypePlan {
    TypePlan {
        definitions: vec![Definition::Structure {
            name: "Player".into(),
            size: 16,
            fields,
        }],
        signatures: vec![],
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
