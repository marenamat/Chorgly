// chorgly-admin: terminal tool for user management
//
// Users authenticate via EC key pairs (P-256). The admin tool only manages
// init_tokens (one-time URL links). Key registration happens in the browser.
//
// Usage:
//   chorgly-admin <data-dir> add-user <name>
//   chorgly-admin <data-dir> reset-init-token <user-id|name>
//   chorgly-admin <data-dir> revoke-keys <user-id|name>
//   chorgly-admin <data-dir> list-users
//   chorgly-admin <data-dir> delete-user <user-id|name>

use std::path::{Path, PathBuf};
use anyhow::{bail, Result};
use uuid::Uuid;
use rand::Rng;

use chorgly_core::{Database, User, UserId};

fn main() -> Result<()> {
  let args: Vec<String> = std::env::args().collect();
  if args.len() < 3 {
    eprintln!("Usage: chorgly-admin <data-dir> <command> [args...]");
    eprintln!("Commands:");
    eprintln!("  add-user <name>               — create a new user, print init URL");
    eprintln!("  reset-init-token <name-or-id> — issue a new init_token (re-registration link)");
    eprintln!("  revoke-keys <name-or-id>      — remove all registered pubkeys (force re-registration)");
    eprintln!("  list-users                    — list users and their key status");
    eprintln!("  delete-user <name-or-id>      — delete a user");
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
      println!("Init token:   {init_token}");
      println!("Login URL:    https://YOUR_HOST/app.html?token={init_token}");
      println!("(The user visits this URL once to register their browser's key pair.)");
    }

    "reset-init-token" => {
      let who = args.get(3).map(|s| s.as_str()).unwrap_or_else(|| { eprintln!("name or id required"); std::process::exit(1); });
      let (user, init_token) = reset_init_token(&mut db, who)?;
      save_db(&data_dir, &db)?;
      println!("New init token for: {} ({})", user.name, user.id);
      println!("Init token:   {init_token}");
      println!("Login URL:    https://YOUR_HOST/app.html?token={init_token}");
    }

    "revoke-keys" => {
      let who = args.get(3).map(|s| s.as_str()).unwrap_or_else(|| { eprintln!("name or id required"); std::process::exit(1); });
      let (user, init_token) = revoke_keys(&mut db, who)?;
      save_db(&data_dir, &db)?;
      println!("All keys revoked for: {} ({})", user.name, user.id);
      println!("New init token: {init_token}");
      println!("Login URL:    https://YOUR_HOST/app.html?token={init_token}");
    }

    "list-users" => {
      for u in db.users.values() {
        let key_count = u.pubkeys.len();
        let init = if u.init_token.is_some() { " [init_token pending]" } else { "" };
        println!("{} | {} | {} key(s){}", u.id, u.name, key_count, init);
        for k in &u.pubkeys {
          let retiring = if k.retiring { " [retiring]" } else { "" };
          println!("  key {} expires {}{}", &k.key_id[..12], k.expires_at.format("%Y-%m-%d"), retiring);
        }
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

fn generate_init_token() -> String {
  let bytes: [u8; 32] = rand::thread_rng().gen();
  hex::encode(bytes)
}

fn add_user(db: &mut Database, name: String) -> (User, String) {
  let init_token = generate_init_token();
  let user = User {
    id: Uuid::new_v4(),
    name,
    init_token: Some(init_token.clone()),
    pubkeys: vec![],
  };
  db.users.insert(user.id, user.clone());
  (user, init_token)
}

fn reset_init_token(db: &mut Database, who: &str) -> Result<(User, String)> {
  let id = find_user_id(db, who)?;
  let token = generate_init_token();
  let user = db.users.get_mut(&id).unwrap();
  user.init_token = Some(token.clone());
  Ok((user.clone(), token))
}

fn revoke_keys(db: &mut Database, who: &str) -> Result<(User, String)> {
  let id = find_user_id(db, who)?;
  let token = generate_init_token();
  let user = db.users.get_mut(&id).unwrap();
  user.pubkeys.clear();
  user.init_token = Some(token.clone());
  Ok((user.clone(), token))
}

fn find_user_id(db: &Database, who: &str) -> Result<UserId> {
  if let Ok(id) = who.parse::<Uuid>() {
    if db.users.contains_key(&id) {
      return Ok(id);
    }
  }
  db.users.values()
    .find(|u| u.name == who)
    .map(|u| u.id)
    .ok_or_else(|| anyhow::anyhow!("user not found: {who}"))
}
