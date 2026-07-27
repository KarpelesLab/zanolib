//! JSON-RPC and `.bin` transport for a Zano daemon.

use crate::error::{Error, Result};
use base64::Engine;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// Base URL of the public modchain Zano gateway, used when a [`Client`]'s
/// endpoint is empty.
pub const MODCHAIN_ZANO: &str = "https://rpc.modchain.net/chain/zano";

/// Maximum response size accepted from the daemon.
const MAX_RESPONSE: usize = 64 << 20;

/// A client for a Zano daemon.
///
/// `endpoint` is the daemon's base URL (e.g. `http://127.0.0.1:11211`);
/// JSON-RPC lives at `<base>/json_rpc` and binary methods at
/// `<base>/<method>.bin`. As a special case an empty endpoint targets the
/// public modchain gateway ([`MODCHAIN_ZANO`]), whose layout differs
/// (`<base>/rpc` and `<base>/raw/<method>.bin`).
pub struct Client {
    endpoint: String,
    asset_cache: Mutex<HashMap<String, AssetDescriptor>>,
}

impl Client {
    /// Builds a client for the given daemon base URL. Pass `""` for the public
    /// modchain gateway.
    pub fn new(endpoint: &str) -> Client {
        Client {
            endpoint: endpoint.to_string(),
            asset_cache: Mutex::new(HashMap::new()),
        }
    }

    /// The configured endpoint (empty means the modchain gateway).
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The JSON-RPC 2.0 endpoint URL.
    pub fn json_rpc_url(&self) -> String {
        if self.endpoint.is_empty() {
            return format!("{MODCHAIN_ZANO}/rpc");
        }
        format!("{}/json_rpc", self.endpoint.trim_end_matches('/'))
    }

    /// The binary endpoint URL for `method`.
    pub fn bin_url(&self, method: &str) -> String {
        if self.endpoint.is_empty() {
            return format!("{MODCHAIN_ZANO}/raw/{method}.bin");
        }
        format!("{}/{method}.bin", self.endpoint.trim_end_matches('/'))
    }

    fn post(&self, url: &str, content_type: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        let resp = rsurl::Request::new("POST", url)
            .map_err(|e| crate::err!("zano rpc: bad url {url}: {e}"))?
            .header("Content-Type", content_type)
            .body(body)
            .send()
            .map_err(|e| crate::err!("zano rpc: {url}: {e}"))?;
        if resp.body.len() > MAX_RESPONSE {
            return Err(Error::msg("zano rpc: response too large"));
        }
        if resp.status != 200 {
            return Err(crate::err!(
                "zano rpc: http {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }
        Ok(resp.body)
    }

    /// Performs one JSON-RPC call and deserializes the `result` field.
    pub fn call<P: Serialize, R: DeserializeOwned>(&self, method: &str, params: &P) -> Result<R> {
        let req = RpcRequest {
            jsonrpc: "2.0",
            id: 0,
            method,
            params,
        };
        let body = serde_json::to_vec(&req)?;
        let data = self.post(&self.json_rpc_url(), "application/json", body)?;

        let env: RpcResponse = serde_json::from_slice(&data)
            .map_err(|e| crate::err!("zano rpc {method}: decode envelope: {e}"))?;
        if let Some(err) = env.error {
            return Err(crate::err!(
                "zano rpc {method}: zano rpc error {}: {}",
                err.code,
                err.message
            ));
        }
        let result = env
            .result
            .ok_or_else(|| crate::err!("zano rpc {method}: no result in response"))?;
        serde_json::from_str(result.get())
            .map_err(|e| crate::err!("zano rpc {method}: decode result: {e}"))
    }

    /// Posts an epee-serialized request to a `.bin` endpoint.
    pub fn post_bin(&self, method: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        self.post(&self.bin_url(method), "application/octet-stream", body)
    }

    /// The current blockchain height (number of blocks).
    pub fn get_block_count(&self) -> Result<u64> {
        #[derive(Deserialize)]
        struct Res {
            count: u64,
        }
        let res: Res = self.call("getblockcount", &serde_json::json!({}))?;
        Ok(res.count)
    }

    /// Details for `count` blocks starting at height `start`. When `ignore_tx`
    /// is true the daemon omits transaction details.
    pub fn get_blocks_details(
        &self,
        start: u64,
        count: u64,
        ignore_tx: bool,
    ) -> Result<Vec<BlockDetails>> {
        #[derive(Serialize)]
        struct Params {
            height_start: u64,
            count: u64,
            ignore_transactions: bool,
        }
        #[derive(Deserialize)]
        struct Res {
            #[serde(default)]
            blocks: Vec<BlockDetails>,
        }
        let res: Res = self.call(
            "get_blocks_details",
            &Params {
                height_start: start,
                count,
                ignore_transactions: ignore_tx,
            },
        )?;
        Ok(res.blocks)
    }

    /// Fetches a transaction by hash and decodes its raw blob.
    pub fn get_tx_details(&self, tx_hash: &str) -> Result<TxDetails> {
        #[derive(Serialize)]
        struct Params<'a> {
            tx_hash: &'a str,
        }
        #[derive(Deserialize)]
        struct Res {
            tx_info: TxDetailsRaw,
        }
        #[derive(Deserialize)]
        struct TxDetailsRaw {
            #[serde(default)]
            id: String,
            #[serde(default)]
            keeper_block: u64,
            #[serde(default)]
            blob: String,
            #[serde(default)]
            outs: Vec<TxOutInfo>,
        }

        let res: Res = self.call("get_tx_details", &Params { tx_hash })?;
        let blob = base64::engine::general_purpose::STANDARD
            .decode(res.tx_info.blob.as_bytes())
            .map_err(|e| crate::err!("get_tx_details {tx_hash}: decode blob: {e}"))?;
        Ok(TxDetails {
            id: res.tx_info.id,
            keeper_block: res.tx_info.keeper_block,
            blob,
            outs: res.tx_info.outs,
        })
    }

    /// Broadcasts a fully-serialized transaction. Returns the daemon status
    /// string (`"OK"` on success).
    pub fn send_raw_tx(&self, raw: &[u8]) -> Result<String> {
        #[derive(Serialize)]
        struct Params {
            tx_as_base64: String,
        }
        #[derive(Deserialize)]
        struct Res {
            #[serde(default)]
            status: String,
        }
        let res: Res = self.call(
            "sendrawtransaction",
            &Params {
                tx_as_base64: base64::engine::general_purpose::STANDARD.encode(raw),
            },
        )?;
        Ok(res.status)
    }

    /// Looks up a confidential asset's descriptor by hex id, caching the result.
    pub fn get_asset_info(&self, asset_id_hex: &str) -> Result<AssetDescriptor> {
        if let Some(d) = self
            .asset_cache
            .lock()
            .expect("asset cache mutex")
            .get(asset_id_hex)
        {
            return Ok(d.clone());
        }

        #[derive(Serialize)]
        struct Params<'a> {
            asset_id: &'a str,
        }
        #[derive(Deserialize)]
        struct Res {
            asset_descriptor: AssetDescriptor,
        }
        let res: Res = self.call(
            "get_asset_info",
            &Params {
                asset_id: asset_id_hex,
            },
        )?;
        self.asset_cache
            .lock()
            .expect("asset cache mutex")
            .insert(asset_id_hex.to_string(), res.asset_descriptor.clone());
        Ok(res.asset_descriptor)
    }
}

#[derive(Serialize)]
struct RpcRequest<'a, P> {
    jsonrpc: &'a str,
    id: u32,
    method: &'a str,
    params: &'a P,
}

#[derive(Deserialize)]
struct RpcResponse {
    #[serde(default)]
    result: Option<Box<serde_json::value::RawValue>>,
    #[serde(default)]
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

/// A block's height and the transactions it contains.
#[derive(Clone, Debug, Deserialize)]
pub struct BlockDetails {
    /// Block height.
    #[serde(default)]
    pub height: u64,
    /// Transactions in this block.
    #[serde(default, rename = "transactions_details")]
    pub transactions: Vec<TxBrief>,
}

/// Identifies a transaction within a block.
#[derive(Clone, Debug, Deserialize)]
pub struct TxBrief {
    /// Transaction hash, hex.
    #[serde(default)]
    pub id: String,
}

/// The raw transaction blob plus the per-output global indices needed to spend
/// received outputs later.
#[derive(Clone, Debug)]
pub struct TxDetails {
    /// Transaction hash, hex.
    pub id: String,
    /// Height of the block holding this transaction.
    pub keeper_block: u64,
    /// The raw (binary) transaction.
    pub blob: Vec<u8>,
    /// The daemon's view of each output, in vout order.
    pub outs: Vec<TxOutInfo>,
}

/// The daemon's view of one transaction output.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct TxOutInfo {
    /// Chain-wide global output index.
    #[serde(default)]
    pub global_index: u64,
    /// Whether the output has been spent.
    #[serde(default)]
    pub is_spent: bool,
}

/// Describes a Zano confidential asset.
///
/// The native coin is not a registered asset and has no descriptor; see
/// [`ReceivedOutput::is_native`](crate::ReceivedOutput::is_native).
#[derive(Clone, Debug, Default, Deserialize)]
pub struct AssetDescriptor {
    /// Short ticker.
    #[serde(default)]
    pub ticker: String,
    /// Human-readable name.
    #[serde(default)]
    pub full_name: String,
    /// Number of decimals in the display representation.
    #[serde(default)]
    pub decimal_point: u8,
    /// Current supply, in atomic units.
    #[serde(default)]
    pub current_supply: u64,
    /// Maximum supply, in atomic units.
    #[serde(default)]
    pub total_max_supply: u64,
    /// Whether the supply is hidden.
    #[serde(default)]
    pub hidden_supply: bool,
    /// Owner key.
    #[serde(default)]
    pub owner: String,
    /// Owner's Ethereum public key, if any.
    #[serde(default)]
    pub owner_eth_pub_key: String,
    /// Free-form metadata.
    #[serde(default)]
    pub meta_info: String,
}

impl AssetDescriptor {
    /// Renders an atomic amount using this asset's `decimal_point`.
    pub fn format_amount(&self, atomic: u64) -> String {
        format_atomic(atomic, self.decimal_point)
    }
}

/// Renders an atomic amount with the given number of decimals
/// (e.g. `10000` with 4 decimals gives `"1.0000"`).
pub fn format_atomic(atomic: u64, decimals: u8) -> String {
    let s = atomic.to_string();
    if decimals == 0 {
        return s;
    }
    let d = decimals as usize;
    let s = if s.len() <= d {
        format!("{}{}", "0".repeat(d - s.len() + 1), s)
    } else {
        s
    };
    let split = s.len() - d;
    format!("{}.{}", &s[..split], &s[split..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_follow_the_endpoint_layout() {
        let direct = Client::new("http://127.0.0.1:11211");
        assert_eq!(direct.json_rpc_url(), "http://127.0.0.1:11211/json_rpc");
        assert_eq!(
            direct.bin_url("getrandom_outs3"),
            "http://127.0.0.1:11211/getrandom_outs3.bin"
        );

        // A trailing slash must not produce a double slash.
        let slash = Client::new("http://127.0.0.1:11211/");
        assert_eq!(slash.json_rpc_url(), "http://127.0.0.1:11211/json_rpc");
        assert_eq!(
            slash.bin_url("getrandom_outs3"),
            "http://127.0.0.1:11211/getrandom_outs3.bin"
        );

        // The empty endpoint targets the modchain gateway, which nests differently.
        let gw = Client::new("");
        assert_eq!(gw.json_rpc_url(), format!("{MODCHAIN_ZANO}/rpc"));
        assert_eq!(
            gw.bin_url("getrandom_outs3"),
            format!("{MODCHAIN_ZANO}/raw/getrandom_outs3.bin")
        );
    }

    #[test]
    fn format_atomic_pads_and_splits() {
        assert_eq!(format_atomic(10000, 4), "1.0000");
        assert_eq!(format_atomic(1, 4), "0.0001");
        assert_eq!(format_atomic(0, 4), "0.0000");
        assert_eq!(format_atomic(123456789, 8), "1.23456789");
        assert_eq!(format_atomic(42, 0), "42");
    }
}
