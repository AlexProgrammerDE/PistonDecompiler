pub mod ai;
pub mod batch;
pub mod config;
pub mod db;
pub mod ghidra;
pub mod graph;
pub mod pipeline;
pub mod server;
pub mod proto {
    tonic::include_proto!("piston.v1");
}
