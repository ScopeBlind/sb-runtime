//! Ed25519-signed, JCS-canonical, hash-chained receipts for sandboxed
//! agent decisions.
//!
//! Every decision emitted by `sb-runtime` — allow, deny, request_approval,
//! exec — is a signed receipt carrying the decision, action, policy evaluated,
//! sequence number, and SHA-256 of the prior receipt's canonical bytes.
//! Any third party can verify a chain offline with `@veritasacta/verify`.
//!
//! ## Example
//! ```
//! use sb_receipt::{Keypair, ReceiptBuilder, Decision};
//! let kp = Keypair::generate();
//! let receipt = ReceiptBuilder::new()
//!     .decision(Decision::Allow)
//!     .action("exec", "/usr/bin/cat")
//!     .policy("dev-safe@v1")
//!     .sequence(1)
//!     .prev_hash_genesis()
//!     .build_and_sign(&kp)
//!     .unwrap();
//! assert!(receipt.verify(kp.verifying_key()).is_ok());
//! ```

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

// ─── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("ed25519 signature error: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),
    #[error("canonicalization error: {0}")]
    Canonicalization(String),
    #[error("serde_json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("receipt schema error: {0}")]
    Schema(String),
    #[error("chain linkage error: {0}")]
    Chain(String),
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
}

// ─── Decision ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    RequestApproval,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::RequestApproval => "request_approval",
        }
    }
}

// ─── Keypair ──────────────────────────────────────────────────────────────────

/// An Ed25519 keypair used to sign receipts.
///
/// For production, keys should be loaded from disk, HSM, or secure hardware.
/// `generate()` is provided for tests and ephemeral sandboxes.
pub struct Keypair {
    signing: SigningKey,
}

impl Keypair {
    /// Generate a fresh keypair from the OS RNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        Self {
            signing: SigningKey::generate(&mut rng),
        }
    }

    /// Construct a keypair from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// Construct a keypair from a hex-encoded 32-byte seed.
    pub fn from_seed_hex(hex_str: &str) -> Result<Self, ReceiptError> {
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != 32 {
            return Err(ReceiptError::Schema(format!(
                "seed must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Self::from_seed(&seed))
    }

    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn to_pubkey_hex(&self) -> String {
        hex::encode(self.verifying_key().to_bytes())
    }
}

// ─── Receipt ──────────────────────────────────────────────────────────────────

/// A signed receipt. The `payload` carries the decision data; `signature` is
/// Ed25519 over the canonical JSON bytes of the payload; `pubkey` lets a
/// verifier check without consulting a registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub payload: Payload,
    pub signature: String, // hex
    pub pubkey: String,    // hex
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    /// Always `"scopeblind.receipt.v1"`.
    #[serde(rename = "type")]
    pub type_: String,
    pub decision: String,
    pub action: ActionRef,
    pub policy_id: Option<String>,
    pub sequence: u64,
    pub prev_hash: String,
    pub timestamp: String,
    /// Optional free-form context fields.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRef {
    /// e.g. "exec", "open", "connect".
    pub kind: String,
    /// e.g. the command path for `exec`, the target path for `open`.
    pub target: String,
}

impl Receipt {
    /// Verify the signature against the payload's canonical JSON bytes
    /// and the embedded public key. Does *not* walk the chain — see
    /// [`verify_chain`] for that.
    pub fn verify(&self, expected_pubkey: VerifyingKey) -> Result<(), ReceiptError> {
        // Confirm the embedded pubkey matches expected
        let embedded = hex::decode(&self.pubkey)?;
        if embedded != expected_pubkey.to_bytes() {
            return Err(ReceiptError::Schema(
                "embedded pubkey does not match expected".into(),
            ));
        }
        let sig_bytes = hex::decode(&self.signature)?;
        if sig_bytes.len() != 64 {
            return Err(ReceiptError::Schema(format!(
                "signature must be 64 bytes, got {}",
                sig_bytes.len()
            )));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        let canonical = jcs_canonical(&serde_json::to_value(&self.payload)?)?;
        expected_pubkey.verify(canonical.as_bytes(), &sig)?;
        Ok(())
    }

    /// Compute SHA-256 of this receipt's canonical payload bytes, prefixed
    /// with `sha256:` as Acta / Sigstore convention. This is what a *next*
    /// receipt should carry in its `prev_hash` field.
    pub fn hash_for_next(&self) -> Result<String, ReceiptError> {
        let canonical = jcs_canonical(&serde_json::to_value(&self.payload)?)?;
        let digest = Sha256::digest(canonical.as_bytes());
        Ok(format!("sha256:{}", hex::encode(digest)))
    }
}

/// Walk a chain of receipts verifying signatures + sequence + prev_hash
/// linkage. Returns `Ok(())` on success; the first break stops verification.
pub fn verify_chain(
    receipts: &[Receipt],
    expected_pubkey: VerifyingKey,
) -> Result<(), ReceiptError> {
    let mut expected_prev = "genesis".to_string();
    for (i, r) in receipts.iter().enumerate() {
        r.verify(expected_pubkey)?;
        if r.payload.sequence != (i as u64) + 1 {
            return Err(ReceiptError::Chain(format!(
                "sequence {} at index {} expected {}",
                r.payload.sequence,
                i,
                i + 1
            )));
        }
        if r.payload.prev_hash != expected_prev {
            return Err(ReceiptError::Chain(format!(
                "prev_hash mismatch at index {}: expected {}, got {}",
                i, expected_prev, r.payload.prev_hash
            )));
        }
        expected_prev = r.hash_for_next()?;
    }
    Ok(())
}

// ─── ReceiptBuilder ───────────────────────────────────────────────────────────

/// Fluent builder for [`Receipt`].
#[derive(Default)]
pub struct ReceiptBuilder {
    decision: Option<Decision>,
    action_kind: Option<String>,
    action_target: Option<String>,
    policy_id: Option<String>,
    sequence: Option<u64>,
    prev_hash: Option<String>,
    timestamp: Option<String>,
    context: BTreeMap<String, Value>,
}

impl ReceiptBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn decision(mut self, d: Decision) -> Self {
        self.decision = Some(d);
        self
    }

    #[must_use]
    pub fn action(mut self, kind: impl Into<String>, target: impl Into<String>) -> Self {
        self.action_kind = Some(kind.into());
        self.action_target = Some(target.into());
        self
    }

    #[must_use]
    pub fn policy(mut self, policy_id: impl Into<String>) -> Self {
        self.policy_id = Some(policy_id.into());
        self
    }

    #[must_use]
    pub fn sequence(mut self, n: u64) -> Self {
        self.sequence = Some(n);
        self
    }

    #[must_use]
    pub fn prev_hash_genesis(self) -> Self {
        self.prev_hash("genesis")
    }

    #[must_use]
    pub fn prev_hash(mut self, prev: impl Into<String>) -> Self {
        self.prev_hash = Some(prev.into());
        self
    }

    #[must_use]
    pub fn timestamp(mut self, ts: impl Into<String>) -> Self {
        self.timestamp = Some(ts.into());
        self
    }

    #[must_use]
    pub fn context(mut self, key: impl Into<String>, value: Value) -> Self {
        self.context.insert(key.into(), value);
        self
    }

    pub fn build_and_sign(self, keypair: &Keypair) -> Result<Receipt, ReceiptError> {
        let decision = self
            .decision
            .ok_or_else(|| ReceiptError::Schema("decision is required".into()))?;
        let action_kind = self
            .action_kind
            .ok_or_else(|| ReceiptError::Schema("action.kind is required".into()))?;
        let action_target = self
            .action_target
            .ok_or_else(|| ReceiptError::Schema("action.target is required".into()))?;
        let sequence = self
            .sequence
            .ok_or_else(|| ReceiptError::Schema("sequence is required".into()))?;
        let prev_hash = self
            .prev_hash
            .ok_or_else(|| ReceiptError::Schema("prev_hash is required".into()))?;
        let timestamp = self.timestamp.unwrap_or_else(now_rfc3339);

        let payload = Payload {
            type_: "scopeblind.receipt.v1".into(),
            decision: decision.as_str().into(),
            action: ActionRef {
                kind: action_kind,
                target: action_target,
            },
            policy_id: self.policy_id,
            sequence,
            prev_hash,
            timestamp,
            context: self.context,
        };

        let canonical = jcs_canonical(&serde_json::to_value(&payload)?)?;
        let sig = keypair.signing.sign(canonical.as_bytes());
        Ok(Receipt {
            payload,
            signature: hex::encode(sig.to_bytes()),
            pubkey: keypair.to_pubkey_hex(),
        })
    }
}

// ─── JCS canonicalization (RFC 8785, minimal implementation) ─────────────────

/// Produce the canonical JSON string of `v` per RFC 8785.
/// Object keys are sorted; no whitespace; numbers use `serde_json`'s
/// default shortest-float form (sufficient for our use — we never emit
/// IEEE edge cases in receipts).
pub fn jcs_canonical(v: &Value) -> Result<String, ReceiptError> {
    let mut out = String::new();
    jcs_write(v, &mut out)?;
    Ok(out)
}

fn jcs_write(v: &Value, out: &mut String) -> Result<(), ReceiptError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            out.push_str(&serde_json::to_string(s)?);
        }
        Value::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_write(e, out)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k)?);
                out.push(':');
                #[allow(clippy::expect_used)]
                jcs_write(m.get(k).expect("key present by construction"), out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Lightweight RFC3339 formatter — avoids chrono as a dep.
    #[allow(clippy::expect_used)]
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH");
    let secs = since.as_secs() as i64;
    format_unix_secs(secs)
}

fn format_unix_secs(secs: i64) -> String {
    // Days since 1970-01-01
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (y, m, d) = days_to_date(days);
    let hour = secs_of_day / 3600;
    let min = (secs_of_day / 60) % 60;
    let sec = secs_of_day % 60;
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Convert days-since-epoch to (year, month, day) using the civil-from-days
/// algorithm by Howard Hinnant (public domain).
fn days_to_date(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = Keypair::generate();
        let r = ReceiptBuilder::new()
            .decision(Decision::Allow)
            .action("exec", "/usr/bin/cat")
            .policy("dev-safe@v1")
            .sequence(1)
            .prev_hash_genesis()
            .build_and_sign(&kp)
            .unwrap();
        r.verify(kp.verifying_key()).unwrap();
    }

    #[test]
    fn tamper_detected() {
        let kp = Keypair::generate();
        let mut r = ReceiptBuilder::new()
            .decision(Decision::Allow)
            .action("exec", "/usr/bin/cat")
            .policy("dev-safe@v1")
            .sequence(1)
            .prev_hash_genesis()
            .build_and_sign(&kp)
            .unwrap();
        // Flip the decision after signing
        r.payload.decision = "deny".into();
        assert!(r.verify(kp.verifying_key()).is_err());
    }

    #[test]
    fn chain_verification_links_correctly() {
        let kp = Keypair::generate();
        let r1 = ReceiptBuilder::new()
            .decision(Decision::Allow)
            .action("exec", "/usr/bin/cat")
            .policy("p")
            .sequence(1)
            .prev_hash_genesis()
            .build_and_sign(&kp)
            .unwrap();
        let r2 = ReceiptBuilder::new()
            .decision(Decision::Deny)
            .action("exec", "/usr/bin/rm")
            .policy("p")
            .sequence(2)
            .prev_hash(r1.hash_for_next().unwrap())
            .build_and_sign(&kp)
            .unwrap();
        verify_chain(&[r1, r2], kp.verifying_key()).unwrap();
    }

    #[test]
    fn chain_verification_rejects_broken_link() {
        let kp = Keypair::generate();
        let r1 = ReceiptBuilder::new()
            .decision(Decision::Allow)
            .action("exec", "a")
            .policy("p")
            .sequence(1)
            .prev_hash_genesis()
            .build_and_sign(&kp)
            .unwrap();
        let r2 = ReceiptBuilder::new()
            .decision(Decision::Allow)
            .action("exec", "b")
            .policy("p")
            .sequence(2)
            .prev_hash("sha256:0000000000000000")
            .build_and_sign(&kp)
            .unwrap();
        assert!(verify_chain(&[r1, r2], kp.verifying_key()).is_err());
    }

    #[test]
    fn jcs_sorts_keys_and_elides_whitespace() {
        let v = serde_json::json!({"b": 2, "a": 1});
        let c = jcs_canonical(&v).unwrap();
        assert_eq!(c, "{\"a\":1,\"b\":2}");
    }

    #[test]
    fn jcs_nested() {
        let v = serde_json::json!({"z": [1, {"b": 2, "a": 1}], "a": "x"});
        let c = jcs_canonical(&v).unwrap();
        assert_eq!(c, "{\"a\":\"x\",\"z\":[1,{\"a\":1,\"b\":2}]}");
    }

    #[test]
    fn seed_roundtrip() {
        let seed_hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let kp = Keypair::from_seed_hex(seed_hex).unwrap();
        let pk = kp.to_pubkey_hex();
        assert_eq!(pk.len(), 64);
    }

    #[test]
    fn rfc3339_format_is_well_formed() {
        let s = format_unix_secs(1_735_689_600); // 2025-01-01T00:00:00Z
        assert_eq!(s, "2025-01-01T00:00:00Z");
    }
}
