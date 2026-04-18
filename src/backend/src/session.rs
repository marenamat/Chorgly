// One WebSocket session per connected client.
// Messages are CBOR-encoded ClientMsg / ServerMsg.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};

use chorgly_core::{ClientMsg, ServerMsg, User};
use crate::state::SharedState;

// Per-client rate limit: max 30 messages per second.
const MAX_MSG_PER_SEC: u32 = 30;

pub async fn run(ws: WebSocket, peer: SocketAddr, state: Arc<SharedState>) {
  if let Err(e) = handle(ws, peer, state).await {
    eprintln!("session {peer} error: {e}");
  }
}

async fn handle(
  ws: WebSocket,
  peer: SocketAddr,
  state: Arc<SharedState>,
) -> anyhow::Result<()> {
  let (mut sink, mut stream) = ws.split();
  let mut broadcast_rx = state.broadcast.subscribe();

  // Rate-limit state.
  let mut msg_count: u32 = 0;
  let mut window_start = std::time::Instant::now();

  let mut authed_user: Option<User> = None;

  loop {
    tokio::select! {
      // Forward broadcast messages to this client (only when authed).
      bcast = broadcast_rx.recv() => {
        if authed_user.is_some() {
          if let Ok(msg) = bcast {
            let bytes = cbor_encode(&msg)?;
            sink.send(Message::Binary(bytes.into())).await?;
          }
        }
      }

      // Handle incoming client message.
      incoming = stream.next() => {
        let raw = match incoming {
          Some(Ok(Message::Binary(b))) => b,
          Some(Ok(Message::Close(_))) | None => break,
          Some(Ok(_)) => continue, // ignore text/ping/pong frames
          Some(Err(e)) => return Err(e.into()),
        };

        // Rate limiting.
        let now = std::time::Instant::now();
        if now.duration_since(window_start).as_secs() >= 1 {
          window_start = now;
          msg_count = 0;
        }
        msg_count += 1;
        if msg_count > MAX_MSG_PER_SEC {
          eprintln!("rate limit exceeded for {peer}");
          let err = cbor_encode(&ServerMsg::Error { reason: "rate limit exceeded".into() })?;
          sink.send(Message::Binary(err.into())).await?;
          break;
        }

        let client_msg: ClientMsg = match ciborium::de::from_reader(raw.as_ref()) {
          Ok(m) => m,
          Err(e) => {
            let err = cbor_encode(&ServerMsg::Error { reason: format!("bad message: {e}") })?;
            sink.send(Message::Binary(err.into())).await?;
            continue;
          }
        };

        let reply = dispatch(&client_msg, &mut authed_user, &state, peer).await;
        let bytes = cbor_encode(&reply)?;
        sink.send(Message::Binary(bytes.into())).await?;
      }
    }
  }

  Ok(())
}

/// Map a ClientMsg to the ServerMsg reply.
async fn dispatch(
  msg: &ClientMsg,
  authed: &mut Option<User>,
  state: &SharedState,
  peer: SocketAddr,
) -> ServerMsg {
  // Auth must come first.
  if let ClientMsg::Auth { token } = msg {
    match state.auth_user(token).await {
      Some(user) => {
        eprintln!("{peer} authed as {}", user.name);
        *authed = Some(user.clone());
        return ServerMsg::AuthOk { user };
      }
      None => return ServerMsg::AuthFail { reason: "invalid or expired token".into() },
    }
  }

  // Everything else requires authentication.
  let user = match authed {
    Some(u) => u.clone(),
    None => return ServerMsg::Error { reason: "not authenticated".into() },
  };

  match msg {
    ClientMsg::Auth { .. } => unreachable!(),

    ClientMsg::ListAll => {
      let chores = state.list_chores(user.id).await;
      let events = state.list_events().await;
      ServerMsg::Snapshot { chores, events }
    }

    ClientMsg::AddChore {
      title, kind, visible_to, assignee, can_complete, depends_on, depends_on_events
    } => {
      let chore = state.add_chore(
        title.clone(),
        kind.clone(),
        visible_to.clone(),
        *assignee,
        can_complete.clone(),
        depends_on.clone(),
        depends_on_events.clone(),
        user.id,
      ).await;
      ServerMsg::ChoreAdded(chore)
    }

    ClientMsg::CompleteChore { chore_id } => {
      match state.complete_chore(*chore_id, user.id).await {
        Ok(chore) => ServerMsg::ChoreUpdated(chore),
        Err(e) => ServerMsg::Error { reason: e },
      }
    }

    ClientMsg::DeleteChore { chore_id } => {
      match state.delete_chore(*chore_id, user.id).await {
        Ok(()) => ServerMsg::ChoreDeleted { chore_id: *chore_id },
        Err(e) => ServerMsg::Error { reason: e },
      }
    }

    ClientMsg::AddEvent { name, description } => {
      let event = state.add_event(name.clone(), description.clone(), user.id).await;
      ServerMsg::EventAdded(event)
    }

    ClientMsg::TriggerEvent { event_id } => {
      match state.trigger_event(*event_id, user.id).await {
        Ok(event) => ServerMsg::EventUpdated(event),
        Err(e) => ServerMsg::Error { reason: e },
      }
    }

    ClientMsg::DeleteEvent { event_id } => {
      match state.delete_event(*event_id, user.id).await {
        Ok(()) => ServerMsg::EventDeleted { event_id: *event_id },
        Err(e) => ServerMsg::Error { reason: e },
      }
    }
  }
}

fn cbor_encode(msg: &ServerMsg) -> anyhow::Result<Vec<u8>> {
  let mut buf = Vec::new();
  ciborium::ser::into_writer(msg, &mut buf)?;
  Ok(buf)
}
