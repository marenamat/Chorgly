// chorgly-backend: HTTP + WebSocket server
//
// Serves the static webapp from CHORGLY_STATIC_DIR (default: ./docs) and
// the WebSocket endpoint at /ws.
//
// Port:       CHORGLY_PORT      (default: 8080)
// Data dir:   CHORGLY_DATA      or first CLI arg (default: ./data)
// Static dir: CHORGLY_STATIC_DIR (default: ./docs)

mod state;
mod session;
mod persist;

use std::net::SocketAddr;
use std::sync::Arc;
use axum::{
  Router,
  extract::{State, WebSocketUpgrade},
  extract::ws::WebSocket,
  response::IntoResponse,
  routing::get,
};
use tower_http::services::ServeDir;
use anyhow::Result;

use state::SharedState;

#[tokio::main]
async fn main() -> Result<()> {
  // Data directory: env var, then first CLI arg, then default.
  let data_dir = std::env::var("CHORGLY_DATA")
    .unwrap_or_else(|_| std::env::args().nth(1).unwrap_or_else(|| "data".to_string()));

  // Static files directory (the built webapp).
  let static_dir = std::env::var("CHORGLY_STATIC_DIR")
    .unwrap_or_else(|_| "docs".to_string());

  let port: u16 = std::env::var("CHORGLY_PORT")
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or(8080);

  eprintln!("chorgly-backend data dir: {data_dir}");
  eprintln!("chorgly-backend static dir: {static_dir}");
  eprintln!("chorgly-backend port: {port}");

  let state = Arc::new(SharedState::load_or_default(data_dir).await?);

  // Spawn hourly persistence.
  {
    let s = Arc::clone(&state);
    tokio::spawn(async move {
      persist::flush_loop(s).await;
    });
  }

  let app = Router::new()
    // WebSocket endpoint.
    .route("/ws", get(ws_handler))
    // Static files fallback — serves the webapp.
    .fallback_service(ServeDir::new(static_dir))
    .with_state(state);

  // Bind on all interfaces, IPv6 (dual-stack on Linux covers IPv4 too).
  let addr: SocketAddr = format!("[::]:{port}").parse()?;
  eprintln!("chorgly-backend listening on {addr}");

  let listener = tokio::net::TcpListener::bind(addr).await?;
  axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
  Ok(())
}

/// HTTP upgrade handler — hands the socket to session::run.
async fn ws_handler(
  ws: WebSocketUpgrade,
  State(state): State<Arc<SharedState>>,
  axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
  ws.on_upgrade(move |socket: WebSocket| session::run(socket, peer, state))
}
