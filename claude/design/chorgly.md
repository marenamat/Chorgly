Create a chore organizer among multiple people. It should keep track of various chores which have to be done. There are multiple categories:

- one-time
- recurring after some time of last completion
- recurring at specific time
- with deadlines

Some chores have dependencies on other chores or external events.

Some chores are limited to certain users.

**Backend**

CBOR-backed storage, complete chore database in memory. Once an hour, dump into a special git repo and commit if changes happened. The data repo path is configurable; initialize the repo if absent. The default path is `./data`.

**Frontend**

Web app and android app. One codebase preferred (PWA is the preferred Android approach — near-zero extra work). Default interface: listing of pending chores, button to add my chore, button to add common chore. Do not ask for details, all chores are by default "remind me in 30 minutes". Will fix later.

On first registration, the admin-issued init_token is passed as a URL query parameter (`?token=<value>`). The app reads it, generates an EC key pair (P-256), registers the key via the challenge-response protocol, then redirects to the clean URL. On subsequent visits the stored private key (PKCS#8, base64 in localStorage) is used to sign all messages.

**Auth**

Create users by a terminal script on the server. No passwords; authentication uses P-256 ECDSA keys generated in the browser and stored in localStorage. The admin script issues one-time init_tokens (URL links) for first-time key registration. Keys are valid for 7 days; the client re-keys automatically when 1/4 of the validity period has elapsed. The server holds only the public key. Key registration protocol:

1. Client generates a P-256 key pair. Private key stored in localStorage (PKCS#8, base64).
2. Client sends `RequestChallenge { init_token, pubkey_spki }` to the server.
3. Server verifies init_token, sends back a 32-byte random `Challenge { token }`.
4. Client signs `challenge_bytes || pubkey_spki_bytes` with its private key and sends `ConfirmKey { signature }`.
5. Server verifies the signature, stores the public key, invalidates the init_token, sends `AuthOk`.

After registration, all WebSocket messages are sent as `Signed { key_id, payload, signature }` where `payload` is CBOR-encoded `SignedPayload` and `signature` is ECDSA-P256-SHA256 over the payload bytes.

Re-key flow (triggered client-side at ≥ 1/4 of key validity elapsed):

1. Client generates a new key pair.
2. Client sends `Signed { key_id: old_id, payload: ReKey { new_pubkey_spki }, signature: old_sig, rekey_sig: new_sig }`. Both signatures cover the same payload bytes.
3. Server verifies both, stores the new key (marks old as retiring).
4. On the next message signed with the new key, the old key is removed.

Admin script commands: `add-user`, `reset-init-token`, `revoke-keys`, `list-users`, `delete-user`.

**Chore permissions**

Every chore has three permission fields:
- `visible_to`: who can see the chore (None = everyone)
- `assignee`: single primary assignee (None = no specific assignee)
- `can_complete`: who can tick the chore off (None = everyone)

Defaults for common chores: `visible_to=None`, `assignee=None`, `can_complete=None` (all).
Defaults for personal chores: `visible_to=[me]`, `assignee=me`, `can_complete=[me]`.
All three fields can be changed by the creator.

**Recurring chores with multiple assignees**

Completing a recurring chore resets the timer for everyone — one completion from any user resets the whole group. A future issue may add a variant where N individual per-user sub-chores must each be completed separately.

**External events**

A list of named external events is maintained. Each event is either untriggered (pending) or triggered. The user explicitly ticks off that an event has happened. Chores may declare `depends_on_events: Vec<EventId>`; they stay blocked until all referenced events are triggered. Future work may add automated watchers (website scrapers, etc.).
