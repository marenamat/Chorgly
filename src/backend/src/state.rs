// Shared mutable state behind a tokio RwLock.
// All business logic lives here so sessions can call it with the lock held.

use std::path::PathBuf;
use tokio::sync::{RwLock, broadcast};
use anyhow::Result;
use chrono::{Duration, Utc};
use uuid::Uuid;

use p256::pkcs8::DecodePublicKey;
use p256::ecdsa::{VerifyingKey, Signature, signature::Verifier};
use sha2::{Sha256, Digest};

use chorgly_core::{
  Chore, ChoreId, ChoreKind, Completion, Database, ExternalEvent, PublicKey, ServerMsg, User, UserId,
};
use chorgly_core::event::EventId;

pub type Tx = broadcast::Sender<ServerMsg>;

/// How long a registered key is valid.
const KEY_VALIDITY_DAYS: i64 = 7;

pub struct SharedState {
  pub db: RwLock<Database>,
  pub broadcast: Tx,
  pub data_dir: PathBuf,
}

impl SharedState {
  /// Load DB from `<data_dir>/db.cbor` or start with an empty one.
  pub async fn load_or_default(data_dir: impl Into<PathBuf>) -> Result<Self> {
    let data_dir = data_dir.into();
    std::fs::create_dir_all(&data_dir)?;

    let db_path = data_dir.join("db.cbor");
    let db = if db_path.exists() {
      let bytes = std::fs::read(&db_path)?;
      Database::from_cbor(&bytes)
        .unwrap_or_else(|e| { eprintln!("Corrupt DB, starting fresh: {e}"); Database::default() })
    } else {
      Database::default()
    };

    let (broadcast, _) = broadcast::channel(256);
    Ok(Self { db: RwLock::new(db), broadcast, data_dir })
  }

  // ------ auth ------

  /// Verify an init_token and return the matching user (read-only, no side effects).
  pub async fn check_init_token(&self, token: &str) -> Option<User> {
    let db = self.db.read().await;
    db.user_by_init_token(token).cloned()
  }

  /// Consume the init_token for a user. Call only after AuthOk is delivered.
  pub async fn consume_init_token(&self, user_id: UserId) {
    let mut db = self.db.write().await;
    db.consume_init_token(user_id);
  }

  /// Register the new pubkey for a user. Called after ConfirmKey verification.
  /// Returns the updated User.
  pub async fn register_pubkey(&self, user_id: UserId, spki_bytes: Vec<u8>) -> User {
    let key_id = spki_key_id(&spki_bytes);
    let now = Utc::now();
    let key = PublicKey {
      key_id,
      spki_bytes,
      added_at: now,
      expires_at: now + Duration::days(KEY_VALIDITY_DAYS),
      retiring: false,
    };
    let mut db = self.db.write().await;
    let user = db.users.get_mut(&user_id).expect("user must exist");
    user.pubkeys.push(key);
    user.clone()
  }

  /// Look up a user by key_id (read-only). Returns (user, pubkey_spki) if found and not expired.
  pub async fn user_by_key_id(&self, key_id: &str) -> Option<(User, Vec<u8>)> {
    let now = Utc::now();
    let db = self.db.read().await;
    let user = db.user_by_key_id(key_id)?;
    let key = user.pubkeys.iter().find(|k| k.key_id == key_id && k.valid_at(now))?;
    Some((user.clone(), key.spki_bytes.clone()))
  }

  /// Accept a ReKey: add new_spki for user, mark old key as retiring.
  /// Returns the updated User, or an error string.
  pub async fn apply_rekey(
    &self,
    user_id: UserId,
    old_key_id: &str,
    new_spki_bytes: Vec<u8>,
  ) -> Result<User, String> {
    let new_key_id = spki_key_id(&new_spki_bytes);
    let now = Utc::now();
    let mut db = self.db.write().await;
    let user = db.users.get_mut(&user_id).ok_or("user not found")?;

    if user.pubkeys.iter().any(|k| k.key_id == new_key_id) {
      return Err("new key already registered".into());
    }

    for k in &mut user.pubkeys {
      if k.key_id == old_key_id {
        k.retiring = true;
      }
    }

    user.pubkeys.push(PublicKey {
      key_id: new_key_id,
      spki_bytes: new_spki_bytes,
      added_at: now,
      expires_at: now + Duration::days(KEY_VALIDITY_DAYS),
      retiring: false,
    });

    Ok(user.clone())
  }

  /// Remove all retiring keys except active_key_id. Called when the new key sends its first message.
  pub async fn retire_old_keys(&self, user_id: UserId, active_key_id: &str) {
    let mut db = self.db.write().await;
    if let Some(user) = db.users.get_mut(&user_id) {
      user.pubkeys.retain(|k| !k.retiring || k.key_id == active_key_id);
    }
  }

  // ------ crypto ------

  /// Verify ECDSA-P256-SHA256 signature over data using the given SPKI public key.
  /// sig_bytes must be in IEEE P1363 format (64 bytes: r || s).
  pub fn verify_sig(spki_bytes: &[u8], data: &[u8], sig_bytes: &[u8]) -> bool {
    let Ok(pk) = p256::PublicKey::from_public_key_der(spki_bytes) else { return false; };
    let vk = VerifyingKey::from(pk);
    let Ok(sig) = Signature::from_bytes(sig_bytes.into()) else { return false; };
    vk.verify(data, &sig).is_ok()
  }

  // ------ chores ------

  pub async fn list_chores(&self, user_id: UserId) -> Vec<Chore> {
    self.db.read().await.chores.values()
      .filter(|c| c.visible_to_user(user_id))
      .cloned()
      .collect()
  }

  pub async fn add_chore(
    &self,
    title: String,
    kind: ChoreKind,
    visible_to: Option<Vec<UserId>>,
    assignee: Option<UserId>,
    can_complete: Option<Vec<UserId>>,
    depends_on: Vec<ChoreId>,
    depends_on_events: Vec<EventId>,
    created_by: UserId,
  ) -> Chore {
    let chore = Chore {
      id: Uuid::new_v4(),
      title,
      kind,
      visible_to,
      assignee,
      can_complete,
      depends_on,
      depends_on_events,
      created_at: Utc::now(),
      created_by,
      completions: vec![],
    };
    {
      let mut db = self.db.write().await;
      db.chores.insert(chore.id, chore.clone());
    }
    let _ = self.broadcast.send(ServerMsg::ChoreAdded(chore.clone()));
    chore
  }

  pub async fn complete_chore(
    &self,
    chore_id: ChoreId,
    by: UserId,
  ) -> Result<Chore, String> {
    let mut db = self.db.write().await;
    let chore = db.chores.get(&chore_id).ok_or("chore not found")?.clone();

    if !chore.completable_by(by) {
      return Err("you are not allowed to complete this chore".into());
    }

    if chore.is_blocked(&db.chores, &db.events) {
      return Err("chore is blocked by unmet dependencies".into());
    }

    let chore = db.chores.get_mut(&chore_id).unwrap();
    chore.completions.push(Completion {
      completed_at: Utc::now(),
      completed_by: by,
    });
    let updated = chore.clone();
    drop(db);
    let _ = self.broadcast.send(ServerMsg::ChoreUpdated(updated.clone()));
    Ok(updated)
  }

  pub async fn delete_chore(
    &self,
    chore_id: ChoreId,
    by: UserId,
  ) -> Result<(), String> {
    let mut db = self.db.write().await;
    let chore = db.chores.get(&chore_id).ok_or("chore not found")?;
    if chore.created_by != by {
      return Err("only the creator may delete this chore".into());
    }
    db.chores.remove(&chore_id);
    drop(db);
    let _ = self.broadcast.send(ServerMsg::ChoreDeleted { chore_id });
    Ok(())
  }

  // ------ external events ------

  pub async fn list_events(&self) -> Vec<ExternalEvent> {
    self.db.read().await.events.values().cloned().collect()
  }

  pub async fn add_event(
    &self,
    name: String,
    description: String,
    created_by: UserId,
  ) -> ExternalEvent {
    let event = ExternalEvent {
      id: Uuid::new_v4(),
      name,
      description,
      triggered: false,
      triggered_at: None,
      triggered_by: None,
      created_at: Utc::now(),
      created_by,
    };
    {
      let mut db = self.db.write().await;
      db.events.insert(event.id, event.clone());
    }
    let _ = self.broadcast.send(ServerMsg::EventAdded(event.clone()));
    event
  }

  pub async fn trigger_event(
    &self,
    event_id: EventId,
    by: UserId,
  ) -> Result<ExternalEvent, String> {
    let mut db = self.db.write().await;
    let event = db.events.get_mut(&event_id).ok_or("event not found")?;
    event.triggered = true;
    event.triggered_at = Some(Utc::now());
    event.triggered_by = Some(by);
    let updated = event.clone();
    drop(db);
    let _ = self.broadcast.send(ServerMsg::EventUpdated(updated.clone()));
    Ok(updated)
  }

  pub async fn delete_event(
    &self,
    event_id: EventId,
    by: UserId,
  ) -> Result<(), String> {
    let mut db = self.db.write().await;
    let event = db.events.get(&event_id).ok_or("event not found")?;
    if event.created_by != by {
      return Err("only the creator may delete this event".into());
    }
    db.events.remove(&event_id);
    drop(db);
    let _ = self.broadcast.send(ServerMsg::EventDeleted { event_id });
    Ok(())
  }
}

/// Compute the key_id (hex SHA-256 fingerprint) of a SPKI public key.
pub fn spki_key_id(spki_bytes: &[u8]) -> String {
  hex::encode(Sha256::digest(spki_bytes))
}
