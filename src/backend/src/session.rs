// One WebSocket session per connected client.
// Messages are CBOR-encoded ClientMsg / ServerMsg.
//
// Auth state machine:
//   Unauthenticated
//     → (RequestChallenge with valid init_token) → PendingChallenge
//   PendingChallenge
//     → (ConfirmKey with valid signature)        → Authenticated
//   Authenticated
//     → (Signed with valid key + signature)      → (stays Authenticated)
//     → (Signed with ReKey payload)              → (stays Authenticated, old key retiring)

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use rand::Rng;

use p256::pkcs8::DecodePublicKey;
use chorgly_core::{ClientMsg, ServerMsg, SignedPayload, User, UserId};
use crate::state::SharedState;

// Per-client rate limit: max 30 messages per second.
const MAX_MSG_PER_SEC: u32 = 30;

/// Per-session authentication state.
enum AuthState {
  Unauthenticated,
  PendingChallenge {
    challenge: Vec<u8>,    // 32 random bytes sent to the client
    pubkey_spki: Vec<u8>,  // client's claimed public key
    user_id: UserId,
    init_token: String,    // must be consumed after AuthOk
  },
  Authenticated {
    user: User,
    key_id: String,        // key_id of the currently active signing key
  },
}

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

  let mut msg_count: u32 = 0;
  let mut window_start = std::time::Instant::now();

  let mut auth = AuthState::Unauthenticated;

  loop {
    tokio::select! {
      // Forward broadcast messages to this client (only when authed).
      bcast = broadcast_rx.recv() => {
        if matches!(auth, AuthState::Authenticated { .. }) {
          if let Ok(msg) = bcast {
            let bytes = cbor_encode(&msg)?;
            sink.send(Message::Binary(bytes.into())).await?;
          }
        }
      }

      incoming = stream.next() => {
        let raw = match incoming {
          Some(Ok(Message::Binary(b))) => b,
          Some(Ok(Message::Close(_))) | None => break,
          Some(Ok(_)) => continue,
          Some(Err(e)) => return Err(anyhow::Error::from(e)),
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

        let client_msg: ClientMsg = match ciborium::de::from_reader(&raw[..]) {
          Ok(m) => m,
          Err(e) => {
            let err = cbor_encode(&ServerMsg::Error { reason: format!("bad message: {e}") })?;
            sink.send(Message::Binary(err.into())).await?;
            continue;
          }
        };

        match dispatch(client_msg, &mut auth, &state, peer).await {
          DispatchResult::Reply(msg) => {
            sink.send(Message::Binary(cbor_encode(&msg)?.into())).await?;
          }
          DispatchResult::AuthOk { msg, user_id, .. } => {
            // Send AuthOk first; only then consume init_token so a dropped connection
            // before delivery doesn't burn the token.
            sink.send(Message::Binary(cbor_encode(&msg)?.into())).await?;
            state.consume_init_token(user_id).await;
          }
          DispatchResult::None => {}
        }
      }
    }
  }

  Ok(())
}

enum DispatchResult {
  Reply(ServerMsg),
  AuthOk { msg: ServerMsg, user_id: UserId },
  None,
}

async fn dispatch(
  msg: ClientMsg,
  auth: &mut AuthState,
  state: &SharedState,
  peer: SocketAddr,
) -> DispatchResult {
  match msg {

    // --- key registration: step 1 ---
    ClientMsg::RequestChallenge { init_token, pubkey_spki } => {
      let Some(user) = state.check_init_token(&init_token).await else {
        return DispatchResult::Reply(ServerMsg::AuthFail {
          reason: "invalid or already-used init token".into(),
        });
      };

      if p256::PublicKey::from_public_key_der(&pubkey_spki).is_err() {
        return DispatchResult::Reply(ServerMsg::AuthFail {
          reason: "invalid public key".into(),
        });
      }

      let challenge: Vec<u8> = rand::thread_rng().gen::<[u8; 32]>().into();

      *auth = AuthState::PendingChallenge {
        challenge: challenge.clone(),
        pubkey_spki,
        user_id: user.id,
        init_token,
      };

      DispatchResult::Reply(ServerMsg::Challenge { token: challenge })
    }

    // --- key registration: step 3 ---
    ClientMsg::ConfirmKey { signature } => {
      let AuthState::PendingChallenge { challenge, pubkey_spki, user_id, init_token } =
        std::mem::replace(auth, AuthState::Unauthenticated)
      else {
        return DispatchResult::Reply(ServerMsg::AuthFail {
          reason: "no pending challenge".into(),
        });
      };

      // Signed data: challenge (32 bytes) || pubkey_spki bytes.
      let mut signed_data = challenge.clone();
      signed_data.extend_from_slice(&pubkey_spki);

      if !SharedState::verify_sig(&pubkey_spki, &signed_data, &signature) {
        return DispatchResult::Reply(ServerMsg::AuthFail {
          reason: "signature verification failed".into(),
        });
      }

      let user = state.register_pubkey(user_id, pubkey_spki.clone()).await;
      let key_id = crate::state::spki_key_id(&pubkey_spki);
      eprintln!("{peer} registered key {key_id:.12}… as {}", user.name);
      *auth = AuthState::Authenticated { user: user.clone(), key_id };

      DispatchResult::AuthOk {
        msg: ServerMsg::AuthOk { user },
        user_id,
      }
    }

    // --- signed authenticated message ---
    ClientMsg::Signed { key_id, payload, signature, rekey_sig } => {
      let Some((user, spki)) = state.user_by_key_id(&key_id).await else {
        return DispatchResult::Reply(ServerMsg::AuthFail {
          reason: "unknown or expired key".into(),
        });
      };

      if !SharedState::verify_sig(&spki, &payload, &signature) {
        return DispatchResult::Reply(ServerMsg::AuthFail {
          reason: "signature verification failed".into(),
        });
      }

      // If this key is active and there are retiring keys, remove them now.
      {
        let has_retiring = {
          let db = state.db.read().await;
          db.users.get(&user.id)
            .map(|u| u.pubkeys.iter().any(|k| k.retiring))
            .unwrap_or(false)
        };
        if has_retiring {
          state.retire_old_keys(user.id, &key_id).await;
        }
      }

      *auth = AuthState::Authenticated { user: user.clone(), key_id: key_id.clone() };

      let inner: SignedPayload = match ciborium::de::from_reader(&payload[..]) {
        Ok(m) => m,
        Err(e) => return DispatchResult::Reply(ServerMsg::Error {
          reason: format!("bad payload: {e}"),
        }),
      };

      let reply = dispatch_signed(inner, rekey_sig, payload, &key_id, user, state).await;
      DispatchResult::Reply(reply)
    }
  }
}

async fn dispatch_signed(
  payload: SignedPayload,
  rekey_sig: Option<Vec<u8>>,
  raw_payload: Vec<u8>,  // original CBOR bytes, used for rekey_sig verification
  key_id: &str,
  user: User,
  state: &SharedState,
) -> ServerMsg {
  match payload {

    SignedPayload::ListAll => {
      let chores = state.list_chores(user.id).await;
      let events = state.list_events().await;
      ServerMsg::Snapshot { chores, events }
    }

    SignedPayload::AddChore {
      title, kind, visible_to, assignee, can_complete, depends_on, depends_on_events
    } => {
      let chore = state.add_chore(
        title, kind, visible_to, assignee, can_complete, depends_on, depends_on_events, user.id,
      ).await;
      ServerMsg::ChoreAdded(chore)
    }

    SignedPayload::CompleteChore { chore_id } => {
      match state.complete_chore(chore_id, user.id).await {
        Ok(chore) => ServerMsg::ChoreUpdated(chore),
        Err(e) => ServerMsg::Error { reason: e },
      }
    }

    SignedPayload::DeleteChore { chore_id } => {
      match state.delete_chore(chore_id, user.id).await {
        Ok(()) => ServerMsg::ChoreDeleted { chore_id },
        Err(e) => ServerMsg::Error { reason: e },
      }
    }

    SignedPayload::AddEvent { name, description } => {
      let event = state.add_event(name, description, user.id).await;
      ServerMsg::EventAdded(event)
    }

    SignedPayload::TriggerEvent { event_id } => {
      match state.trigger_event(event_id, user.id).await {
        Ok(event) => ServerMsg::EventUpdated(event),
        Err(e) => ServerMsg::Error { reason: e },
      }
    }

    SignedPayload::DeleteEvent { event_id } => {
      match state.delete_event(event_id, user.id).await {
        Ok(()) => ServerMsg::EventDeleted { event_id },
        Err(e) => ServerMsg::Error { reason: e },
      }
    }

    SignedPayload::ReKey { new_pubkey_spki } => {
      // rekey_sig must be present: the new key signs the same raw payload bytes.
      let Some(new_sig) = rekey_sig else {
        return ServerMsg::Error { reason: "ReKey requires rekey_sig".into() };
      };

      if !SharedState::verify_sig(&new_pubkey_spki, &raw_payload, &new_sig) {
        return ServerMsg::Error { reason: "new key signature verification failed".into() };
      }

      match state.apply_rekey(user.id, key_id, new_pubkey_spki).await {
        Ok(updated_user) => ServerMsg::AuthOk { user: updated_user },
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
