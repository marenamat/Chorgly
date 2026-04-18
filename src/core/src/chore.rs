use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{UserId, event::{EventId, ExternalEvent}};

pub type ChoreId = Uuid;

/// How and when a chore recurs (or doesn't).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChoreKind {
  /// Done once; disappears from the pending list after completion.
  OneTime,

  /// Becomes pending again N seconds after last completion.
  RecurringAfterCompletion { delay_secs: u64 },

  /// Becomes pending on a fixed cron schedule (UTC).
  /// Prototype uses a simple "HH:MM weekday/daily/weekly" string;
  /// full cron syntax TBD once the design is clarified.
  RecurringScheduled { schedule: String },

  /// Must be done before the deadline.
  WithDeadline { deadline: DateTime<Utc> },
}

/// A single recorded completion of a chore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Completion {
  pub completed_at: DateTime<Utc>,
  pub completed_by: UserId,
}

/// A chore in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chore {
  pub id: ChoreId,
  pub title: String,
  pub kind: ChoreKind,

  // --- permission fields (Q4) ---
  /// Who can see this chore. None = everyone.
  pub visible_to: Option<Vec<UserId>>,

  /// Primary assignee. None = no specific assignee.
  pub assignee: Option<UserId>,

  /// Who may mark this chore done. None = everyone.
  pub can_complete: Option<Vec<UserId>>,

  // --- dependency fields ---
  /// Other chores that must be completed before this one is actionable.
  pub depends_on: Vec<ChoreId>,

  /// External events that must be triggered before this one is actionable (Q3).
  pub depends_on_events: Vec<EventId>,

  pub created_at: DateTime<Utc>,
  pub created_by: UserId,

  /// Full completion history (most-recent last).
  pub completions: Vec<Completion>,
}

impl Chore {
  /// Most-recent completion, if any.
  pub fn last_completion(&self) -> Option<&Completion> {
    self.completions.last()
  }

  /// True if `user` can see this chore.
  pub fn visible_to_user(&self, user: UserId) -> bool {
    match &self.visible_to {
      None => true,
      Some(list) => list.contains(&user),
    }
  }

  /// True if `user` is allowed to complete this chore.
  pub fn completable_by(&self, user: UserId) -> bool {
    match &self.can_complete {
      None => true,
      Some(list) => list.contains(&user),
    }
  }

  /// Compute when this chore is next due, given the current time.
  /// Returns None if the chore has no pending work.
  pub fn next_due(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    match &self.kind {
      ChoreKind::OneTime => {
        if self.completions.is_empty() { Some(now) } else { None }
      }

      ChoreKind::RecurringAfterCompletion { delay_secs } => {
        match self.last_completion() {
          None => Some(now), // never done → due immediately
          Some(c) => {
            let due = c.completed_at + chrono::Duration::seconds(*delay_secs as i64);
            Some(due) // always return the due date (may be past or future)
          }
        }
      }

      // Scheduled recurrence: proper cron parsing is future work.
      ChoreKind::RecurringScheduled { .. } => Some(now),

      ChoreKind::WithDeadline { deadline } => {
        if *deadline > now && self.completions.is_empty() {
          Some(*deadline)
        } else {
          None
        }
      }
    }
  }

  /// True if this chore is blocked by unmet chore or event dependencies.
  /// Note: for a recurring chore, completed_at is what matters —
  /// a dep is satisfied if it has any completion, regardless of recurrence.
  pub fn is_blocked(
    &self,
    all_chores: &HashMap<ChoreId, Chore>,
    all_events: &HashMap<EventId, ExternalEvent>,
  ) -> bool {
    // Check chore dependencies: each dep must have at least one completion.
    let completed_chores: HashSet<ChoreId> = all_chores.values()
      .filter(|c| !c.completions.is_empty())
      .map(|c| c.id)
      .collect();
    let chore_blocked = self.depends_on.iter().any(|dep| !completed_chores.contains(dep));

    // Check event dependencies: each dep must be triggered.
    let event_blocked = self.depends_on_events.iter()
      .any(|eid| !all_events.get(eid).map_or(false, |e| e.triggered));

    chore_blocked || event_blocked
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::HashMap;
  use chrono::Utc;
  use uuid::Uuid;
  use crate::event::ExternalEvent;

  fn chore_with_completions(id: Uuid, n: usize) -> Chore {
    let creator = Uuid::new_v4();
    Chore {
      id,
      title: "test chore".into(),
      kind: ChoreKind::OneTime,
      visible_to: None,
      assignee: None,
      can_complete: None,
      depends_on: vec![],
      depends_on_events: vec![],
      created_at: Utc::now(),
      created_by: creator,
      completions: (0..n).map(|_| Completion {
        completed_at: Utc::now(),
        completed_by: creator,
      }).collect(),
    }
  }

  fn untriggered_event(id: EventId) -> ExternalEvent {
    let creator = Uuid::new_v4();
    ExternalEvent {
      id,
      name: "test event".into(),
      description: String::new(),
      triggered: false,
      triggered_at: None,
      triggered_by: None,
      created_at: Utc::now(),
      created_by: creator,
    }
  }

  fn triggered_event(id: EventId) -> ExternalEvent {
    let creator = Uuid::new_v4();
    ExternalEvent {
      id,
      name: "test event".into(),
      description: String::new(),
      triggered: true,
      triggered_at: Some(Utc::now()),
      triggered_by: Some(creator),
      created_at: Utc::now(),
      created_by: creator,
    }
  }

  // next_due tests

  #[test]
  fn one_time_pending_without_completion() {
    let c = chore_with_completions(Uuid::new_v4(), 0);
    assert!(c.next_due(Utc::now()).is_some());
  }

  #[test]
  fn one_time_done_after_completion() {
    let c = chore_with_completions(Uuid::new_v4(), 1);
    assert!(c.next_due(Utc::now()).is_none());
  }

  #[test]
  fn recurring_after_completion_always_has_due_date() {
    let mut c = chore_with_completions(Uuid::new_v4(), 0);
    c.kind = ChoreKind::RecurringAfterCompletion { delay_secs: 3600 };
    assert!(c.next_due(Utc::now()).is_some()); // never done → due now
    c.completions.push(Completion { completed_at: Utc::now(), completed_by: Uuid::new_v4() });
    assert!(c.next_due(Utc::now()).is_some()); // done → due in 1h, but date still present
  }

  // is_blocked tests

  #[test]
  fn not_blocked_with_no_deps() {
    let c = chore_with_completions(Uuid::new_v4(), 0);
    assert!(!c.is_blocked(&HashMap::new(), &HashMap::new()));
  }

  #[test]
  fn blocked_by_incomplete_chore_dep() {
    let dep_id = Uuid::new_v4();
    let dep = chore_with_completions(dep_id, 0); // not completed
    let mut c = chore_with_completions(Uuid::new_v4(), 0);
    c.depends_on = vec![dep_id];
    let mut chores = HashMap::new();
    chores.insert(dep_id, dep);
    assert!(c.is_blocked(&chores, &HashMap::new()));
  }

  #[test]
  fn unblocked_when_chore_dep_completed() {
    let dep_id = Uuid::new_v4();
    let dep = chore_with_completions(dep_id, 1); // completed
    let mut c = chore_with_completions(Uuid::new_v4(), 0);
    c.depends_on = vec![dep_id];
    let mut chores = HashMap::new();
    chores.insert(dep_id, dep);
    assert!(!c.is_blocked(&chores, &HashMap::new()));
  }

  #[test]
  fn blocked_by_untriggered_event_dep() {
    let eid = Uuid::new_v4();
    let event = untriggered_event(eid);
    let mut c = chore_with_completions(Uuid::new_v4(), 0);
    c.depends_on_events = vec![eid];
    let mut events = HashMap::new();
    events.insert(eid, event);
    assert!(c.is_blocked(&HashMap::new(), &events));
  }

  #[test]
  fn unblocked_when_event_dep_triggered() {
    let eid = Uuid::new_v4();
    let event = triggered_event(eid);
    let mut c = chore_with_completions(Uuid::new_v4(), 0);
    c.depends_on_events = vec![eid];
    let mut events = HashMap::new();
    events.insert(eid, event);
    assert!(!c.is_blocked(&HashMap::new(), &events));
  }

  // visibility / permission tests

  #[test]
  fn visible_to_none_means_everyone_can_see() {
    let c = chore_with_completions(Uuid::new_v4(), 0);
    assert!(c.visible_to_user(Uuid::new_v4()));
  }

  #[test]
  fn visible_to_list_restricts_visibility() {
    let uid = Uuid::new_v4();
    let other = Uuid::new_v4();
    let mut c = chore_with_completions(Uuid::new_v4(), 0);
    c.visible_to = Some(vec![uid]);
    assert!(c.visible_to_user(uid));
    assert!(!c.visible_to_user(other));
  }

  #[test]
  fn can_complete_none_means_anyone() {
    let c = chore_with_completions(Uuid::new_v4(), 0);
    assert!(c.completable_by(Uuid::new_v4()));
  }

  #[test]
  fn can_complete_list_restricts_completion() {
    let uid = Uuid::new_v4();
    let other = Uuid::new_v4();
    let mut c = chore_with_completions(Uuid::new_v4(), 0);
    c.can_complete = Some(vec![uid]);
    assert!(c.completable_by(uid));
    assert!(!c.completable_by(other));
  }
}
