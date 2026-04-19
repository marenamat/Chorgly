#!/usr/bin/env python3
# Integration tests for WebSocket authentication (EC key / challenge-response).
#
# Expects a running chorgly backend at WS_URL (default ws://[::1]:8080/ws).
# Reads key material from tests/testdata/tokens.yaml.
#
# Test cases (issue #5):
#   1. Signed message rejected without prior registration
#   2. RequestChallenge rejected with wrong init_token
#   3. ConfirmKey rejected with bad signature
#   4. Full registration flow succeeds (carol: RequestChallenge → Challenge → ConfirmKey → AuthOk)
#   5. Registered key: Signed ListAll → Snapshot (alice, who is pre-registered in testdata)
#   6. Signed with wrong key_id → AuthFail
#   7. Signed with bad signature → AuthFail
#   8. ListAll denied when not authenticated (Signed with unknown key)
#   9. init_token survives dropped connection before AuthOk (dave)
#  10. init_token denied after successful registration (carol, from test 4)

import asyncio
import hashlib
import os
import struct
import sys

import cbor2
import yaml
import websockets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    load_der_private_key,
)

WS_URL = os.environ.get("WS_URL", "ws://[::1]:8080/ws")
TESTDATA_DIR = os.path.join(os.path.dirname(__file__), "testdata")


def load_tokens():
    with open(os.path.join(TESTDATA_DIR, "tokens.yaml")) as f:
        return yaml.safe_load(f)


def cbor_encode(msg) -> bytes:
    return cbor2.dumps(msg)


def cbor_decode(data: bytes):
    return cbor2.loads(data)


# ---- EC helpers ----

def der_sig_to_p1363(der_sig: bytes) -> bytes:
    """Convert DER-encoded ECDSA signature to IEEE P1363 (r||s, each 32 bytes)."""
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def sign_p256(privkey, data: bytes) -> bytes:
    """Sign data with P-256 ECDSA SHA-256. Returns IEEE P1363 signature."""
    der = privkey.sign(data, ec.ECDSA(hashes.SHA256()))
    return der_sig_to_p1363(der)


def spki_key_id(spki_bytes: bytes) -> str:
    return hashlib.sha256(spki_bytes).hexdigest()


def gen_key():
    priv = ec.generate_private_key(ec.SECP256R1())
    spki = priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return priv, spki


# ---- protocol helpers ----

def enc_request_challenge(init_token: str, pubkey_spki: bytes) -> bytes:
    return cbor_encode({"RequestChallenge": {"init_token": init_token, "pubkey_spki": pubkey_spki}})


def enc_confirm_key(signature: bytes) -> bytes:
    return cbor_encode({"ConfirmKey": {"signature": signature}})


def enc_signed_payload(payload_dict) -> bytes:
    return cbor_encode(payload_dict)


def enc_signed_msg(key_id: str, payload: bytes, signature: bytes) -> bytes:
    return cbor_encode({"Signed": {
        "key_id": key_id,
        "payload": payload,
        "signature": signature,
    }})


def enc_rekey_msg(key_id: str, payload: bytes, old_sig: bytes, new_sig: bytes) -> bytes:
    return cbor_encode({"Signed": {
        "key_id": key_id,
        "payload": payload,
        "signature": old_sig,
        "rekey_sig": new_sig,
    }})


async def do_registration(ws, init_token: str, privkey, spki: bytes):
    """Run the full RequestChallenge → ConfirmKey flow. Returns True on AuthOk."""
    await ws.send(enc_request_challenge(init_token, spki))
    raw = await ws.recv()
    resp = cbor_decode(raw)
    if "Challenge" not in resp:
        return False, resp

    challenge = bytes(resp["Challenge"]["token"])
    signed_data = challenge + spki
    sig = sign_p256(privkey, signed_data)

    await ws.send(enc_confirm_key(sig))
    raw = await ws.recv()
    resp2 = cbor_decode(raw)
    return "AuthOk" in resp2, resp2


async def do_signed_list_all(ws, privkey, key_id: str):
    """Send a signed ListAll and return the response."""
    payload = enc_signed_payload("ListAll")
    sig = sign_p256(privkey, payload)
    await ws.send(enc_signed_msg(key_id, payload, sig))
    raw = await ws.recv()
    return cbor_decode(raw)


# ---- test runner ----

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
failures = []


def check(name: str, cond: bool, detail: str = ""):
    if cond:
        print(f"  {PASS}  {name}")
    else:
        print(f"  {FAIL}  {name}" + (f": {detail}" if detail else ""))
        failures.append(name)


# carol_spki and carol_privkey are set during test 4 and reused in test 10.
carol_spki_saved = None
carol_privkey_saved = None


async def run_tests():
    global carol_spki_saved, carol_privkey_saved

    tokens = load_tokens()
    alice_key_id    = tokens["alice_key_id"]
    alice_spki      = bytes.fromhex(tokens["alice_spki_hex"])
    alice_privkey   = load_der_private_key(bytes.fromhex(tokens["alice_privkey_hex"]))
    carol_init      = tokens["carol_init_token"]
    dave_init       = tokens["dave_init_token"]

    print(f"Connecting to {WS_URL}")

    # 1. Signed message rejected without prior registration (unknown key_id).
    async with websockets.connect(WS_URL) as ws:
        fake_priv, fake_spki = gen_key()
        resp = await do_signed_list_all(ws, fake_priv, spki_key_id(fake_spki))
        check("signed msg rejected without registration", "AuthFail" in resp, repr(resp))

    # 2. RequestChallenge rejected with wrong init_token.
    async with websockets.connect(WS_URL) as ws:
        _, spki = gen_key()
        await ws.send(enc_request_challenge("completely-wrong-init-token", spki))
        raw = await ws.recv()
        resp = cbor_decode(raw)
        check("RequestChallenge rejected with wrong init_token", "AuthFail" in resp, repr(resp))

    # 3. ConfirmKey rejected with bad signature (wrong private key signs the challenge).
    async with websockets.connect(WS_URL) as ws:
        carol_priv, carol_spki = gen_key()
        wrong_priv, _ = gen_key()  # a different key — signature will be invalid

        await ws.send(enc_request_challenge(carol_init, carol_spki))
        raw = await ws.recv()
        resp = cbor_decode(raw)
        if "Challenge" not in resp:
            check("ConfirmKey bad-sig (precondition: got Challenge)", False, repr(resp))
        else:
            challenge = bytes(resp["Challenge"]["token"])
            signed_data = challenge + carol_spki
            bad_sig = sign_p256(wrong_priv, signed_data)  # wrong key

            await ws.send(enc_confirm_key(bad_sig))
            raw = await ws.recv()
            resp2 = cbor_decode(raw)
            check("ConfirmKey rejected with bad signature", "AuthFail" in resp2, repr(resp2))

    # 4. Full registration flow succeeds (carol gets a fresh init_token each run via test 3
    #    which didn't consume it — carol's init_token is still valid).
    async with websockets.connect(WS_URL) as ws:
        carol_privkey, carol_spki = gen_key()
        carol_spki_saved = carol_spki
        carol_privkey_saved = carol_privkey

        ok, resp = await do_registration(ws, carol_init, carol_privkey, carol_spki)
        check("full registration flow succeeds (carol)", ok, repr(resp))

    # 5. Registered key: alice can send Signed ListAll → Snapshot.
    async with websockets.connect(WS_URL) as ws:
        resp = await do_signed_list_all(ws, alice_privkey, alice_key_id)
        check("signed ListAll succeeds for pre-registered key (alice)", "Snapshot" in resp, repr(resp))

    # 6. Signed with wrong key_id → AuthFail.
    async with websockets.connect(WS_URL) as ws:
        fake_key_id = "0" * 64  # 32 zero bytes, hex-encoded — doesn't exist
        payload = enc_signed_payload("ListAll")
        sig = sign_p256(alice_privkey, payload)
        await ws.send(enc_signed_msg(fake_key_id, payload, sig))
        raw = await ws.recv()
        resp = cbor_decode(raw)
        check("Signed with unknown key_id → AuthFail", "AuthFail" in resp, repr(resp))

    # 7. Signed with bad signature (alice's key_id but wrong private key).
    async with websockets.connect(WS_URL) as ws:
        wrong_priv, _ = gen_key()
        payload = enc_signed_payload("ListAll")
        bad_sig = sign_p256(wrong_priv, payload)
        await ws.send(enc_signed_msg(alice_key_id, payload, bad_sig))
        raw = await ws.recv()
        resp = cbor_decode(raw)
        check("Signed with bad signature → AuthFail", "AuthFail" in resp, repr(resp))

    # 8. ListAll denied when key is unknown (check Error, not AuthFail, is returned
    #    for a Signed with an unknown key).
    async with websockets.connect(WS_URL) as ws:
        unk_priv, unk_spki = gen_key()
        resp = await do_signed_list_all(ws, unk_priv, spki_key_id(unk_spki))
        check("ListAll denied for unknown key", "AuthFail" in resp, repr(resp))

    # 9. init_token survives a dropped connection before AuthOk (dave).
    #    First attempt: send RequestChallenge, get Challenge, then close without ConfirmKey.
    async with websockets.connect(WS_URL) as ws:
        dave_priv, dave_spki = gen_key()
        await ws.send(enc_request_challenge(dave_init, dave_spki))
        raw = await ws.recv()
        resp = cbor_decode(raw)
        check("dave: RequestChallenge gets Challenge (precondition)", "Challenge" in resp, repr(resp))
        # Close the connection before ConfirmKey — init_token must NOT be consumed.

    # Second attempt: dave can still register using the same init_token.
    async with websockets.connect(WS_URL) as ws:
        dave_priv2, dave_spki2 = gen_key()
        ok, resp = await do_registration(ws, dave_init, dave_priv2, dave_spki2)
        check("init_token still valid after dropped connection (dave)", ok, repr(resp))

    # 10. carol's init_token denied after successful registration (test 4 consumed it).
    async with websockets.connect(WS_URL) as ws:
        _, fresh_spki = gen_key()
        await ws.send(enc_request_challenge(carol_init, fresh_spki))
        raw = await ws.recv()
        resp = cbor_decode(raw)
        check("init_token denied after successful registration (carol)", "AuthFail" in resp, repr(resp))

    return len(failures) == 0


def main():
    ok = asyncio.run(run_tests())
    if failures:
        print(f"\n{len(failures)} test(s) failed: {', '.join(failures)}")
        sys.exit(1)
    else:
        print("\nAll tests passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
