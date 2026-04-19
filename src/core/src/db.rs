// In-memory database backed by CBOR files.
// Flushed to disk (and then committed to a git repo) at most once per hour.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::{Chore, ChoreId, User, UserId};
use crate::event::{EventId, ExternalEvent};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Database {
  pub users: HashMap<UserId, User>,
  pub chores: HashMap<ChoreId, Chore>,
  pub events: HashMap<EventId, ExternalEvent>,
}

impl Database {
  /// Serialise the whole DB to a CBOR byte vector.
  pub fn to_cbor(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(self, &mut buf)?;
    Ok(buf)
  }

  /// Deserialise a DB from CBOR bytes.
  pub fn from_cbor(bytes: &[u8]) -> Result<Self, ciborium::de::Error<std::io::Error>> {
    ciborium::de::from_reader(bytes)
  }

  /// Look up a user by their init token (if unused).
  pub fn user_by_init_token(&self, token: &str) -> Option<&User> {
    self.users.values().find(|u| u.init_token.as_deref() == Some(token))
  }

  /// Consume the init_token of a user (called after successful key registration).
  pub fn consume_init_token(&mut self, user_id: UserId) {
    if let Some(u) = self.users.get_mut(&user_id) {
      u.init_token = None;
    }
  }

  /// Look up a user who has a pubkey with the given key_id (not expired, any retiring status).
  pub fn user_by_key_id(&self, key_id: &str) -> Option<&User> {
    self.users.values().find(|u| u.pubkeys.iter().any(|k| k.key_id == key_id))
  }
}
