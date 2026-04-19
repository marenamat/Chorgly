// Shared mutable state behind a tokio RwLock.
// All business logic lives here so sessions can call it with the lock held.

use std::path::PathBuf;
use tokio::sync::{RwLock, broadcast};
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

use chorgly_core::{
  Chore, ChoreId, ChoreKind, Completion, Database, ExternalEvent, ServerMsg, User, UserId,
};
use chorgly_core::event::EventId;

pub type Tx = broadcast::Sender<ServerMsg>;

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

  /// Authenticate a user by token (session or init).
  /// If the token matches an unused init_token, it is consumed (write lock).
  pub async fn auth_user(&self, token: &str) -> Option<User> {
    let now = Utc::now();

    // Fast path: valid session token (read lock only).
    {
      let db = self.db.read().await;
      if let Some(user) = db.user_by_token(token).filter(|u| u.token_valid_at(now)) {
        return Some(user.clone());
      }
    }

    // Slow path: init token — consume it on success (write lock).
    let mut db = self.db.write().await;
    let user = db.user_by_init_token(token).cloned()?;
    db.consume_init_token(user.id);
    Some(user)
  }

  // ------ chores ------

  /// List chores visible to the given user (Q4: visible_to filter).
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

    // Check can_complete permission (Q4).
    if !chore.completable_by(by) {
      return Err("you are not allowed to complete this chore".into());
    }

    // Check that all dependencies are satisfied (Q3: includes event deps).
    if chore.is_blocked(&db.chores, &db.events) {
      return Err("chore is blocked by unmet dependencies".into());
    }

    // Record the completion. One completion resets the timer for all (Q5).
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

    // Only the creator may delete.
    if chore.created_by != by {
      return Err("only the creator may delete this chore".into());
    }
    db.chores.remove(&chore_id);
    drop(db);
    let _ = self.broadcast.send(ServerMsg::ChoreDeleted { chore_id });
    Ok(())
  }

  // ------ external events (Q3) ------

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
