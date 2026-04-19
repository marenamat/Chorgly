// chorgly-frontend: WASM module
// Exposes JS-callable functions for the UI glue layer.
//
// Auth flow (called from app.js):
//   1. encode_request_challenge(init_token, pubkey_spki) → bytes to send
//   2. Server replies with Challenge { token }; decode via decode_server_msg
//   3. JS signs (challenge_bytes || pubkey_spki_bytes) with Web Crypto
//   4. encode_confirm_key(signature) → bytes to send
//   5. Server replies with AuthOk
//
// Authenticated flow:
//   1. encode_signed_payload(json) → payload_bytes
//   2. JS signs payload_bytes with Web Crypto
//   3. encode_signed_msg(key_id, payload_bytes, sig_bytes) → bytes to send
//      (for ReKey: encode_rekey_msg(key_id, payload_bytes, old_sig, new_sig))

use wasm_bindgen::prelude::*;
use chorgly_core::{ClientMsg, ServerMsg, SignedPayload};

mod state;
mod render;

pub use state::AppState;

/// Decode a CBOR byte array from the server into a JS value.
#[wasm_bindgen]
pub fn decode_server_msg(bytes: &[u8]) -> Result<JsValue, JsValue> {
  let msg: ServerMsg = ciborium::de::from_reader(bytes)
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
  serde_wasm_bindgen::to_value(&msg)
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Encode a RequestChallenge message (step 1 of key registration).
/// pubkey_spki is the DER SubjectPublicKeyInfo bytes of the client's P-256 key.
#[wasm_bindgen]
pub fn encode_request_challenge(init_token: &str, pubkey_spki: &[u8]) -> Result<Vec<u8>, JsValue> {
  cbor_encode(&ClientMsg::RequestChallenge {
    init_token: init_token.to_string(),
    pubkey_spki: pubkey_spki.to_vec(),
  })
}

/// Encode a ConfirmKey message (step 3 of key registration).
/// signature is the IEEE P1363 (r||s, 64 bytes) ECDSA-P256-SHA256 signature
/// over (challenge_bytes || pubkey_spki_bytes).
#[wasm_bindgen]
pub fn encode_confirm_key(signature: &[u8]) -> Result<Vec<u8>, JsValue> {
  cbor_encode(&ClientMsg::ConfirmKey { signature: signature.to_vec() })
}

/// Encode a SignedPayload to CBOR bytes (to be signed by the JS layer via Web Crypto).
/// json must be a JSON-encoded SignedPayload variant, e.g. `"ListAll"` or
/// `{"AddChore": {"title": "...", ...}}`.
#[wasm_bindgen]
pub fn encode_signed_payload(json: &str) -> Result<Vec<u8>, JsValue> {
  let payload: SignedPayload = serde_json::from_str(json)
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
  let mut buf = Vec::new();
  ciborium::ser::into_writer(&payload, &mut buf)
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
  Ok(buf)
}

/// Wrap a signed payload in a ClientMsg::Signed and encode to CBOR.
/// payload is the CBOR bytes produced by encode_signed_payload.
/// signature is the IEEE P1363 ECDSA-P256-SHA256 signature over payload.
#[wasm_bindgen]
pub fn encode_signed_msg(key_id: &str, payload: &[u8], signature: &[u8]) -> Result<Vec<u8>, JsValue> {
  cbor_encode(&ClientMsg::Signed {
    key_id: key_id.to_string(),
    payload: payload.to_vec(),
    signature: signature.to_vec(),
    rekey_sig: None,
  })
}

/// Like encode_signed_msg but includes a rekey_sig for the ReKey payload.
/// old_sig is the current key's signature; new_sig is the new key's signature.
/// Both sign the same payload bytes.
#[wasm_bindgen]
pub fn encode_rekey_msg(
  key_id: &str,
  payload: &[u8],
  old_sig: &[u8],
  new_sig: &[u8],
) -> Result<Vec<u8>, JsValue> {
  cbor_encode(&ClientMsg::Signed {
    key_id: key_id.to_string(),
    payload: payload.to_vec(),
    signature: old_sig.to_vec(),
    rekey_sig: Some(new_sig.to_vec()),
  })
}

fn cbor_encode(msg: &ClientMsg) -> Result<Vec<u8>, JsValue> {
  let mut buf = Vec::new();
  ciborium::ser::into_writer(msg, &mut buf)
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
  Ok(buf)
}
