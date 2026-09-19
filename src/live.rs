//! Bounded graph snapshots and resumable, durable event streaming.
use crate::{db::Db, proto, server::Service};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::{Stream, stream};
use sqlx::Row;
use std::{convert::Infallible, time::Duration};

pub async fn events(
    State(service): State<Service>,
    Path(binary): Path<String>,
    headers: HeaderMap,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let cursor = headers
        .get("last-event-id")
        .and_then(|s| s.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    let stream = stream::unfold(
        (service, binary, cursor),
        |(service, binary, mut cursor)| async move {
            loop {
                let rows=sqlx::query("SELECT id,created_at,level,message FROM events WHERE binary_id=? AND id>? ORDER BY id LIMIT 100").bind(&binary).bind(cursor).fetch_all(&service.db.pool).await;
                match rows {
                    Ok(rows) if !rows.is_empty() => {
                        let events: Vec<_> = rows
                            .iter()
                            .map(|r| proto::Event {
                                id: r.get("id"),
                                created_at: r.get("created_at"),
                                level: r.get("level"),
                                message: r.get("message"),
                            })
                            .collect();
                        cursor = events.last().unwrap().id;
                        let event = Event::default()
                            .id(cursor.to_string())
                            .json_data(events)
                            .unwrap();
                        return Some((Ok(event), (service, binary, cursor)));
                    }
                    Err(error) => {
                        tracing::warn!(%error,"Live event read failed");
                        return None;
                    }
                    _ => {}
                }
                tokio::select! {_ = service.shutdown.cancelled()=>return None,_ = tokio::time::sleep(Duration::from_secs(1))=>{}}
            }
        },
    );
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}
pub async fn graph(db: &Db, binary: &str) -> anyhow::Result<proto::Graph> {
    let query = proto::FunctionQuery {
        binary_id: binary.into(),
        limit: 200,
        ..Default::default()
    };
    let (functions, rows) = tokio::try_join!(db.functions(&query), async {
        Ok::<_,anyhow::Error>(sqlx::query("SELECT caller,callee FROM edges WHERE caller IN (SELECT id FROM functions WHERE binary_id=? ORDER BY address LIMIT 200) AND callee IN (SELECT id FROM functions WHERE binary_id=? ORDER BY address LIMIT 200) LIMIT 2000").bind(binary).bind(binary).fetch_all(&db.pool).await?)
    })?;
    Ok(proto::Graph {
        nodes: functions.functions,
        edges: rows
            .iter()
            .map(|r| proto::GraphEdge {
                caller: r.get("caller"),
                callee: r.get("callee"),
            })
            .collect(),
        total: functions.total,
    })
}
