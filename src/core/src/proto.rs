// WebSocket message types shared between backend and frontend.
// All messages are serialised as CBOR over the wire.
//
// Auth flow (first-time key registration):
//   Client → RequestChallenge { init_token, pubkey_spki }
//   Server → Challenge { token }
//   Client → ConfirmKey { signature }  (signs challenge || pubkey_spki)
//   Server → AuthOk { user }           (init_token consumed)
//
// Authenticated flow (all subsequent messages):
//   Client → Signed { key_id, payload, signature [, rekey_sig] }
//   Server → (any ServerMsg)
//
// Re-key flow (client at ≥ 1/4 of key validity time):
//   Client sends Signed whose payload is SignedPayload::ReKey { new_pubkey_spki }.
//   The Signed.signature is from the OLD key; Signed.rekey_sig is from the NEW key.
//   Both sign the same payload bytes.
//   Server accepts the new key; marks old key as retiring.
//   On the next Signed message from the NEW key, the old key is removed.

use serde::{Deserialize, Serialize};

use crate::{Chore, ChoreId, ChoreKind, ExternalEvent, User, UserId};
use crate::event::EventId;

// ---------- client → server ----------

#[derive(Debug, Serialize, Deserialize)]
pub enum ClientMsg {
  // --- unauthenticated: key registration ---

  /// Step 1: client wants to register its public key using an admin-issued init_token.
  /// pubkey_spki is the DER-encoded SubjectPublicKeyInfo of the client's P-256 key.
  RequestChallenge { init_token: String, pubkey_spki: Vec<u8> },

  /// Step 3: client proves possession of its private key.
  /// signature is ECDSA-P256-SHA256 over (challenge_bytes || pubkey_spki_bytes),
  /// where challenge_bytes are the 32 bytes from the Challenge server message,
  /// and pubkey_spki_bytes are the bytes sent in RequestChallenge.
  /// Both values are concatenated directly (challenge is always 32 bytes).
  ConfirmKey { signature: Vec<u8> },

  // --- authenticated: signed message envelope ---

  /// All post-auth messages. payload is CBOR-encoded SignedPayload.
  /// signature is ECDSA-P256-SHA256 over the payload bytes, using the key identified by key_id.
  /// rekey_sig is only present when payload is SignedPayload::ReKey; it is the new key's
  /// ECDSA-P256-SHA256 signature over the same payload bytes.
  Signed {
    key_id: String,
    payload: Vec<u8>,
    signature: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rekey_sig: Option<Vec<u8>>,
  },
}

/// The inner payload of a Signed message (CBOR-serialised separately).
#[derive(Debug, Serialize, Deserialize)]
pub enum SignedPayload {
  /// Request a full snapshot of the chore and event lists.
  ListAll,

  /// Add a new chore. Server assigns the ID and timestamps.
  AddChore {
    title: String,
    kind: ChoreKind,
    /// Who can see this chore. None = everyone.
    visible_to: Option<Vec<UserId>>,
    /// Primary assignee. None = no specific assignee.
    assignee: Option<UserId>,
    /// Who may mark this chore done. None = everyone.
    can_complete: Option<Vec<UserId>>,
    depends_on: Vec<ChoreId>,
    depends_on_events: Vec<EventId>,
  },

  /// Mark a chore as done by the authenticated user.
  CompleteChore { chore_id: ChoreId },

  /// Delete a chore (only creator may do this).
  DeleteChore { chore_id: ChoreId },

  // --- external events ---

  /// Declare a new external event that users must watch for.
  AddEvent { name: String, description: String },

  /// Mark an external event as having occurred.
  TriggerEvent { event_id: EventId },

  /// Remove an external event.
  DeleteEvent { event_id: EventId },

  // --- re-keying ---

  /// Register a new P-256 key to replace the current one.
  /// new_pubkey_spki is the DER-encoded SPKI of the new key.
  /// The Signed wrapper's rekey_sig field must contain the new key's signature
  /// over the same payload bytes as the old key's signature.
  ReKey { new_pubkey_spki: Vec<u8> },
}

// ---------- server → client ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMsg {
  /// Step 2 of key registration: server sends a 32-byte random challenge.
  Challenge { token: Vec<u8> },

  /// Key registration succeeded; init_token consumed.
  AuthOk { user: User },
  /// Key registration or message auth failed.
  AuthFail { reason: String },

  /// Full snapshot sent after ListAll.
  Snapshot { chores: Vec<Chore>, events: Vec<ExternalEvent> },

  /// Incremental updates broadcast to all connected clients.
  ChoreAdded(Chore),
  ChoreUpdated(Chore),
  ChoreDeleted { chore_id: ChoreId },

  EventAdded(ExternalEvent),
  EventUpdated(ExternalEvent),
  EventDeleted { event_id: EventId },

  /// Generic error in response to a bad client message.
  Error { reason: String },
}
