use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type UserId = Uuid;

/// A registered P-256 public key for one user.
/// The key_id is hex(SHA-256(spki_bytes)) — a stable fingerprint used to
/// identify which key signed an incoming message.
/// Keys expire after a fixed validity period. When a re-key is in progress,
/// the old key is marked `retiring`; it will be dropped when the first
/// message signed with the new key arrives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
  /// Hex-encoded SHA-256 fingerprint of spki_bytes.
  pub key_id: String,
  /// DER-encoded SubjectPublicKeyInfo bytes of the P-256 public key.
  pub spki_bytes: Vec<u8>,
  pub added_at: DateTime<Utc>,
  pub expires_at: DateTime<Utc>,
  /// True once the client has registered a successor key via ReKey.
  /// Cleared (key removed) when the first message signed by the new key arrives.
  pub retiring: bool,
}

impl PublicKey {
  pub fn valid_at(&self, now: DateTime<Utc>) -> bool {
    now < self.expires_at
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
  pub id: UserId,
  pub name: String,
  /// One-time admin link token; consumed on first successful key registration.
  #[serde(default)]
  pub init_token: Option<String>,
  /// Active public keys (usually one; two during re-key transition).
  #[serde(default)]
  pub pubkeys: Vec<PublicKey>,
}
