use chrono::Utc;
use ripemd::Ripemd160;
use secp256k1::{Message, Secp256k1, SecretKey};
use serde_json::json;
use sha2::{Digest, Sha256};

const CHAIN_ID: &str = "anet-p2p-testnet-2026-10-23"; // synthetic lab genesis; override with ANET_TX_CHAIN_ID
const AMOUNT_ANTS: u64 = 10_000;
const FEE_ANTS: u64 = 1_000;

fn address_from_secret(secret: &SecretKey) -> String {
    let secp = Secp256k1::new();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, secret);
    let mut hasher = Ripemd160::new();
    hasher.update(public_key.serialize());
    let hash = hex::encode_upper(hasher.finalize());
    format!("ANET{}", &hash[..36])
}

fn sign_digest(digest: &[u8; 32], secret: &SecretKey) -> String {
    let secp = Secp256k1::new();
    let message = Message::from_digest_slice(digest).expect("test signing digest");
    let signature = secp.sign_ecdsa_recoverable(&message, secret);
    let (recovery_id, compact) = signature.serialize_compact();
    let mut signature_bytes = Vec::from(compact);
    signature_bytes.push(recovery_id.to_i32() as u8);
    hex::encode(signature_bytes)
}

fn oracle_secret() -> SecretKey {
    // ANET_ORACLE_SECRET_HEX is held by the testnet coordinator only; the
    // fallback is a public constant that is fine for a single-machine lab but
    // must never be used for a shared testnet.
    match std::env::var("ANET_ORACLE_SECRET_HEX") {
        Ok(hex_secret) => SecretKey::from_slice(&hex::decode(hex_secret.trim()).expect("oracle secret hex"))
            .expect("oracle secret key"),
        Err(_) => SecretKey::from_slice(&[3u8; 32]).expect("public lab oracle key"),
    }
}

fn print_signed_session_snapshot(chain_id: &str, entries_json: &str) {
    let mut entries = serde_json::from_str::<Vec<serde_json::Value>>(entries_json)
        .expect("test session entries");
    let mut normalized = entries
        .iter()
        .map(|entry| {
            (
                entry["wallet"].as_str().expect("wallet").trim().to_uppercase(),
                entry["sessions"].as_u64().expect("sessions"),
            )
        })
        .collect::<Vec<_>>();
    normalized.sort_by(|left, right| left.0.cmp(&right.0));
    entries = normalized
        .iter()
        .map(|(wallet, sessions)| json!({"wallet": wallet, "sessions": sessions}))
        .collect();

    let as_of_ms = std::env::var("ANET_SESSION_AS_OF_MS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or_else(|| Utc::now().timestamp_millis() - 5_000);
    let body = normalized
        .iter()
        .map(|(wallet, sessions)| format!("{wallet}:{sessions}"))
        .collect::<Vec<_>>()
        .join(",");
    let preimage = format!("session-oracle-v1|{chain_id}|{as_of_ms}|{body}");
    let digest: [u8; 32] = Sha256::digest(preimage.as_bytes()).into();
    let oracle_secret = oracle_secret();
    let signer = address_from_secret(&oracle_secret);
    let snapshot = json!({
        "chain_id": chain_id,
        "as_of_ms": as_of_ms,
        "entries": entries,
        "signer": signer,
        "signature": sign_digest(&digest, &oracle_secret),
    });
    println!(
        "{}",
        serde_json::to_string(&json!({"oracle_address": signer, "snapshot": snapshot}))
            .expect("serialize signed test snapshot")
    );
}

fn main() {
    // Fixed, public test-only secrets. They must never be used on production.
    let sender_secret = SecretKey::from_slice(&[1u8; 32]).expect("test sender key");
    let recipient_secret = SecretKey::from_slice(&[2u8; 32]).expect("test recipient key");
    let sender = address_from_secret(&sender_secret);
    let recipient = std::env::var("ANET_TX_TO")
        .unwrap_or_else(|_| address_from_secret(&recipient_secret));
    let chain_id = std::env::var("ANET_TX_CHAIN_ID").unwrap_or_else(|_| CHAIN_ID.to_owned());
    if std::env::var_os("ANET_PRINT_ORACLE_ADDRESS").is_some() {
        println!("{}", address_from_secret(&oracle_secret()));
        return;
    }
    if let Ok(entries) = std::env::var("ANET_SESSION_SNAPSHOT_ENTRIES") {
        print_signed_session_snapshot(&chain_id, &entries);
        return;
    }
    let nonce = std::env::var("ANET_TX_NONCE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    let timestamp = Utc::now();
    let payload = std::env::var("ANET_TX_PAYLOAD")
        .ok()
        .map(|value| serde_json::from_str(&value).expect("test transaction payload"))
        .unwrap_or_else(|| json!({"memo": "isolated p2p failover test"}));
    let canonical_payload = serde_json::to_string(&payload).expect("canonical test payload");
    let preimage = format!(
        "v1|transfer|{}|{}|{}|{}|{}|{}|{}|{}",
        sender,
        recipient,
        AMOUNT_ANTS,
        FEE_ANTS,
        nonce,
        timestamp.timestamp_millis(),
        chain_id,
        canonical_payload,
    );
    let hash = Sha256::digest(preimage.as_bytes());
    let tx_hash = hex::encode(hash);
    let message = Message::from_digest_slice(&hash).expect("transaction digest");
    let signature = Secp256k1::new().sign_ecdsa_recoverable(&message, &sender_secret);
    let (recovery_id, compact) = signature.serialize_compact();
    let mut signature_bytes = Vec::from(compact);
    signature_bytes.push(recovery_id.to_i32() as u8);

    let output = json!({
        "chain_id": chain_id,
        "sender": sender,
        "recipient": recipient,
        "sender_secret_hex": hex::encode([1u8; 32]),
        "recipient_secret_hex": hex::encode([2u8; 32]),
        "transaction": {
            "tx_type": "transfer",
            "from": sender,
            "to": recipient,
            "amount_ants": AMOUNT_ANTS,
            "fee_ants": FEE_ANTS,
            "nonce": nonce,
            "timestamp": timestamp.to_rfc3339(),
            "chain_id": chain_id,
            "payload": payload,
            "signature": hex::encode(signature_bytes),
            "tx_hash": tx_hash,
        }
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output["transaction"])
            .expect("serialize test transaction")
    );
}
