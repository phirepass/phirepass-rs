use crate::http::AppState;
use log::Level::Debug;
use log::{debug, info, warn};
use phirepass_common::stats::Stats;
use serde_json::json;
use std::time::{Duration, SystemTime};

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(120);

fn cleanup_dangling_connections(state: &AppState) {
    debug!("cleaning up dangling connections");

    let now = SystemTime::now();

    // Clean up stale web connections
    let mut removed_count = 0;
    state.connections.retain(|_, conn| {
        match now.duration_since(conn.last_heartbeat) {
            Ok(elapsed) => {
                if elapsed > CONNECTION_TIMEOUT {
                    warn!(
                        "removing stale web connection from {} (inactive for {:.1?})",
                        conn.ip, elapsed
                    );
                    removed_count += 1;
                    false // Remove this connection
                } else {
                    true // Keep this connection
                }
            }
            Err(_) => true, // Keep if time went backwards
        }
    });

    if removed_count > 0 {
        info!(
            "cleanup: removed {} stale web connections (active: {})",
            removed_count,
            state.connections.len()
        );
    }

    let mut removed_count = 0;
    state.nodes.retain(|_, node| {
        match now.duration_since(node.node.last_heartbeat) {
            Ok(elapsed) => {
                if elapsed > CONNECTION_TIMEOUT {
                    warn!(
                        "removing stale node from {} (inactive for {:.1?})",
                        node.node.ip, elapsed
                    );
                    removed_count += 1;
                    false // Remove this node
                } else {
                    true // Keep this node
                }
            }
            Err(_) => true, // Keep if time went backwards
        }
    });

    if removed_count > 0 {
        info!(
            "cleanup: removed {} stale node connections (active: {})",
            removed_count,
            state.nodes.len()
        );
    }
}

pub(crate) async fn refresh_connections_task(state: &AppState) {
    debug!("refreshing connections tasks");

    cleanup_dangling_connections(state);

    let mut refreshed = 0;
    for entry in state.connections.iter() {
        let (cid, conn_info) = entry.pair();
        if let Err(err) = state
            .memory_db
            .refresh_connection(cid, conn_info.ip, &state.server)
            .await
        {
            warn!("failed to refresh connection {cid} in redis: {err}");
        } else {
            refreshed += 1;
        }
    }

    debug!("refreshed {} connections", refreshed);
}

pub(crate) async fn keep_server_alive_task(state: &AppState) {
    debug!("keeping server alive");

    let Ok(payload) = state.server.get_encoded() else {
        warn!("failed to encode server payload");
        return;
    };

    let stats = json!({
        "nodes": state.nodes.len(),
        "connections": state.connections.len(),
        "sessions": state.tunnel_sessions.len(),
    })
    .to_string();

    if let Err(err) = state
        .memory_db
        .save_server(state.id.as_ref(), payload.as_str(), &stats)
        .await
    {
        warn!("failed to save server info: {}", err);
    }
}

pub(crate) fn print_server_stats_task(state: &AppState) {
    info!("printing server[id={}] stats", state.server.id);

    info!("\tactive web connections: {}", state.connections.len());
    info!("\tactive nodes connections: {}", state.nodes.len());

    if log::log_enabled!(Debug) {
        // Stats::refresh() calls blocking syscalls (sysinfo, netstat). Use
        // block_in_place so the async runtime's worker threads are not installed.
        match tokio::task::block_in_place(Stats::refresh) {
            Some(stats) => info!("server[id={}] stats\n{}", state.server.id, stats.log_line()),
            None => warn!("stats: unable to read process metrics"),
        }
    }
}
