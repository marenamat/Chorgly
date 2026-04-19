#!/usr/bin/env python3
# Generates tests/testdata/db.cbor with known users for integration tests.
#
# Users created:
#   alice — has a registered P-256 key; private key written to tokens.yaml
#   carol — has an unused init_token (no key registered yet)
#   dave  — used for the "token survives dropped connection before AuthOk" test;
#           has an unused init_token
#
# Requires: pip install cbor2 pyyaml cryptography

import cbor2
import uuid
import os
import datetime
import yaml
import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)

OUTDIR = os.path.join(os.path.dirname(__file__), "testdata")
os.makedirs(OUTDIR, exist_ok=True)

now = datetime.datetime.now(datetime.timezone.utc)

KEY_VALIDITY_DAYS = 7

# --- EC key generation ---

def gen_key():
    """Generate a P-256 key pair and return (private_key, spki_bytes, key_id)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    spki = priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    key_id = hashlib.sha256(spki).hexdigest()
    return priv, spki, key_id


def ts(dt):
    # ciborium serialises DateTime<Utc> as an RFC3339 string
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --- user IDs ---
alice_uid = uuid.UUID("00000000-0000-0000-0000-000000000001")
carol_uid = uuid.UUID("00000000-0000-0000-0000-000000000003")
dave_uid  = uuid.UUID("00000000-0000-0000-0000-000000000004")

# --- init tokens ---
carol_init_token = "carol-init-token-" + "0" * 47
dave_init_token  = "dave-init-token-" + "0" * 48

# --- alice's key pair (pre-registered in the DB) ---
alice_priv, alice_spki, alice_key_id = gen_key()

alice_pubkey = {
    "key_id":     alice_key_id,
    "spki_bytes": alice_spki,
    "added_at":   ts(now - datetime.timedelta(hours=1)),
    "expires_at": ts(now + datetime.timedelta(days=KEY_VALIDITY_DAYS)),
    "retiring":   False,
}

users = {
    alice_uid.bytes: {
        "id":         alice_uid.bytes,
        "name":       "alice",
        "init_token": None,
        "pubkeys":    [alice_pubkey],
    },
    carol_uid.bytes: {
        "id":         carol_uid.bytes,
        "name":       "carol",
        "init_token": carol_init_token,
        "pubkeys":    [],
    },
    dave_uid.bytes: {
        "id":         dave_uid.bytes,
        "name":       "dave",
        "init_token": dave_init_token,
        "pubkeys":    [],
    },
}

db = {"users": users, "chores": {}, "events": {}}

with open(os.path.join(OUTDIR, "db.cbor"), "wb") as f:
    cbor2.dump(db, f)

# Write alice's private key as hex-encoded PKCS#8 DER, plus the init tokens.
alice_priv_der = alice_priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())

tokens = {
    "alice_key_id":    alice_key_id,
    "alice_spki_hex":  alice_spki.hex(),
    "alice_privkey_hex": alice_priv_der.hex(),
    "carol_init_token": carol_init_token,
    "dave_init_token":  dave_init_token,
}
with open(os.path.join(OUTDIR, "tokens.yaml"), "w") as f:
    yaml.dump(tokens, f)

print(f"Generated {OUTDIR}/db.cbor and tokens.yaml")
print(f"  alice key_id: {alice_key_id[:16]}...")
print(f"  carol init_token: {carol_init_token[:20]}...")
