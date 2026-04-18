// Client-side application state (mirrors the server's view).
// Kept in Rust so we can do typed operations; exposed to JS via wasm-bindgen.

use std::collections::HashMap;
use wasm_bindgen::prelude::*;
use chorgly_core::{Chore, ChoreId, ExternalEvent, User, UserId};
use chorgly_core::event::EventId;

#[wasm_bindgen]
pub struct AppState {
  pub(crate) current_user: Option<User>,
  pub(crate) chores: HashMap<ChoreId, Chore>,
  pub(crate) events: HashMap<EventId, ExternalEvent>,
}

#[wasm_bindgen]
impl AppState {
  #[wasm_bindgen(constructor)]
  pub fn new() -> Self {
    Self {
      current_user: None,
      chores: HashMap::new(),
      events: HashMap::new(),
    }
  }

  /// Returns true if the user is authenticated.
  pub fn is_authed(&self) -> bool {
    self.current_user.is_some()
  }

  /// Returns the current user's ID as a string, or empty string if not authed.
  pub fn current_user_id(&self) -> String {
    self.current_user.as_ref()
      .map(|u| u.id.to_string())
      .unwrap_or_default()
  }

  /// Apply a server message (already decoded via decode_server_msg).
  /// Returns the name of the event fired so JS can re-render selectively.
  pub fn apply(&mut self, msg: JsValue) -> Result<String, JsValue> {
    let msg: chorgly_core::ServerMsg = serde_wasm_bindgen::from_value(msg)
      .map_err(|e| JsValue::from_str(&e.to_string()))?;

    use chorgly_core::ServerMsg::*;
    let event = match msg {
      AuthOk { user } => {
        self.current_user = Some(user);
        "auth_ok"
      }
      AuthFail { .. } => "auth_fail",
      Snapshot { chores, events } => {
        self.chores.clear();
        for c in chores { self.chores.insert(c.id, c); }
        self.events.clear();
        for e in events { self.events.insert(e.id, e); }
        "snapshot"
      }
      ChoreAdded(c) | ChoreUpdated(c) => {
        self.chores.insert(c.id, c);
        "chore_changed"
      }
      ChoreDeleted { chore_id } => {
        self.chores.remove(&chore_id);
        "chore_deleted"
      }
      EventAdded(e) | EventUpdated(e) => {
        self.events.insert(e.id, e);
        "event_changed"
      }
      EventDeleted { event_id } => {
        self.events.remove(&event_id);
        "event_deleted"
      }
      Error { .. } => "error",
    };
    Ok(event.to_string())
  }

  /// Return chores visible to the current user, sorted by due date, as a JS value.
  pub fn pending_chores_json(&self) -> Result<JsValue, JsValue> {
    let now = js_sys::Date::now(); // ms since epoch
    let now_dt = chrono::DateTime::from_timestamp_millis(now as i64)
      .unwrap_or_else(chrono::Utc::now);

    let user_id: Option<UserId> = self.current_user.as_ref().map(|u| u.id);

    let mut pending: Vec<&Chore> = self.chores.values()
      .filter(|c| user_id.map_or(true, |uid| c.visible_to_user(uid)))
      .filter(|c| c.next_due(now_dt).is_some())
      .collect();
    pending.sort_by_key(|c| c.next_due(now_dt));

    serde_wasm_bindgen::to_value(&pending)
      .map_err(|e| JsValue::from_str(&e.to_string()))
  }

  /// True if the chore with the given UUID string is blocked by unmet dependencies.
  /// Uses the actual chore/event state rather than just checking dep-list length.
  pub fn is_chore_blocked(&self, chore_id: &str) -> bool {
    let Ok(id) = chore_id.parse::<uuid::Uuid>() else { return false };
    let Some(chore) = self.chores.get(&id) else { return false };
    chore.is_blocked(&self.chores, &self.events)
  }

  /// Return untriggered external events as a JS value.
  pub fn pending_events_json(&self) -> Result<JsValue, JsValue> {
    let mut events: Vec<&ExternalEvent> = self.events.values()
      .filter(|e| !e.triggered)
      .collect();
    // Sort by creation time.
    events.sort_by_key(|e| e.created_at);

    serde_wasm_bindgen::to_value(&events)
      .map_err(|e| JsValue::from_str(&e.to_string()))
  }
}
