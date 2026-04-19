// chorgly-admin: terminal tool for user management
//
// Usage:
//   chorgly-admin <data-dir> add-user <name>
//   chorgly-admin <data-dir> reset-token <user-id|name>
//   chorgly-admin <data-dir> list-users
//   chorgly-admin <data-dir> delete-user <user-id|name>

use std::path::{Path, PathBuf};
use anyhow::{bail, Result};
use chrono::{Duration, Utc};
use uuid::Uuid;
use rand::Rng;

use chorgly_core::{Database, User, UserId};

fn main() -> Result<()> {
  let args: Vec<String> = std::env::args().collect();
  if args.len() < 3 {
    eprintln!("Usage: chorgly-admin <data-dir> <command> [args...]");
    eprintln!("Commands: add-user <name> | reset-token <name-or-id> | list-users | delete-user <name-or-id>");
    std::process::exit(1);
  }

  let data_dir = PathBuf::from(&args[1]);
  let cmd = &args[2];

  let mut db = load_db(&data_dir)?;

  match cmd.as_str() {
    "add-user" => {
      let name = args.get(3).map(|s| s.as_str()).unwrap_or_else(|| { eprintln!("name required"); std::process::exit(1); });
      let (user, init_token) = add_user(&mut db, name.to_string());
      save_db(&data_dir, &db)?;
      println!("Created user: {} ({})", user.name, user.id);
      println!("Init token: {init_token}");
      println!("Login URL: https://YOUR_HOST/app.html?token={init_token}");
    }

    "reset-token" => {
      let who = args.get(3).map(|s| s.as_str()).unwrap_or_else(|| { eprintln!("name or id required"); std::process::exit(1); });
      let (user, new_token) = reset_token(&mut db, who)?;
      save_db(&data_dir, &db)?;
      println!("Token reset for: {} ({})", user.name, user.id);
      println!("New token: {new_token}");
      println!("Login URL: https://YOUR_HOST/app.html?token={new_token}");
    }

    "list-users" => {
      let now = Utc::now();
      for u in db.users.values() {
        let valid = if u.token_valid_at(now) { "valid" } else { "EXPIRED" };
        println!("{} | {} | token {} | expires {}", u.id, u.name, valid, u.token_expires_at.format("%Y-%m-%d"));
      }
    }

    "delete-user" => {
      let who = args.get(3).map(|s| s.as_str()).unwrap_or_else(|| { eprintln!("name or id required"); std::process::exit(1); });
      let id = find_user_id(&db, who)?;
      db.users.remove(&id);
      save_db(&data_dir, &db)?;
      println!("Deleted user {who}");
    }

    _ => bail!("unknown command: {cmd}"),
  }

  Ok(())
}

// ---- helpers ----

fn load_db(data_dir: &Path) -> Result<Database> {
  let path = data_dir.join("db.cbor");
  if !path.exists() {
    return Ok(Database::default());
  }
  let bytes = std::fs::read(path)?;
  Ok(Database::from_cbor(&bytes)?)
}

fn save_db(data_dir: &Path, db: &Database) -> Result<()> {
  std::fs::create_dir_all(data_dir)?;
  let bytes = db.to_cbor()?;
  std::fs::write(data_dir.join("db.cbor"), bytes)?;
  Ok(())
}

fn generate_token() -> String {
  let bytes: [u8; 32] = rand::thread_rng().gen();
  hex::encode(bytes)
}

fn add_user(db: &mut Database, name: String) -> (User, String) {
  let session_token = generate_token();
  let init_token = generate_token();
  let now = Utc::now();
  let user = User {
    id: Uuid::new_v4(),
    name,
    token: session_token,
    token_issued_at: now,
    token_expires_at: now + Duration::days(7),
    // init_token is for the first-login URL link; consumed on first successful auth
    init_token: Some(init_token.clone()),
  };
  db.users.insert(user.id, user.clone());
  (user, init_token)
}

fn reset_token(db: &mut Database, who: &str) -> Result<(User, String)> {
  let id = find_user_id(db, who)?;
  let token = generate_token();
  let now = Utc::now();
  let user = db.users.get_mut(&id).unwrap();
  user.token = token.clone();
  user.token_issued_at = now;
  user.token_expires_at = now + Duration::days(7);
  Ok((user.clone(), token))
}

fn find_user_id(db: &Database, who: &str) -> Result<UserId> {
  // Try as UUID first.
  if let Ok(id) = who.parse::<Uuid>() {
    if db.users.contains_key(&id) {
      return Ok(id);
    }
  }
  // Fall back to name match.
  db.users.values()
    .find(|u| u.name == who)
    .map(|u| u.id)
    .ok_or_else(|| anyhow::anyhow!("user not found: {who}"))
}
