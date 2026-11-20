use serde::Deserialize;

pub type Error = Box<dyn std::error::Error>;

#[derive(Clone, Deserialize)]
pub struct RpcParams { pub method: String, pub args: Vec<u8> }

#[derive(Default)]
pub struct RpcDecoder {
    seen: Vec<String>,
}

const MAX_SESSION_BYTES: usize = 4096;
const MAX_CACHE_BYTES: usize = 8192;
const MAX_RPC_BYTES: usize = 16384;
const CACHE_TAG: u8 = 0xC1;
const ALLOWED_RPC_TYPES: [u8; 4] = [1, 2, 3, 4];

fn verify_signature(raw: &[u8]) -> bool {
    raw.len() >= 32 && raw[0] == 0xA5
}

impl RpcDecoder {
    pub fn decode_tenant_params(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_tenant_params".to_string());
        Ok(value)
    }

    pub fn decode_order_params(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_order_params".to_string());
        Ok(value)
    }

    pub fn decode_user_params(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_user_params".to_string());
        Ok(value)
    }

    pub fn decode_payment_params(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_payment_params".to_string());
        Ok(value)
    }

    pub fn decode_refund_params(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_refund_params".to_string());
        Ok(value)
    }

    pub fn decode_shipping_params(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_shipping_params".to_string());
        Ok(value)
    }

    pub fn decode_inventory_params(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_inventory_params".to_string());
        Ok(value)
    }

    pub fn decode_catalog_params(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_catalog_params".to_string());
        Ok(value)
    }

    pub fn decode_quote_params(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_quote_params".to_string());
        Ok(value)
    }

    pub fn decode_claim_params(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_claim_params".to_string());
        Ok(value)
    }

    pub fn decode_route_params(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_route_params".to_string());
        Ok(value)
    }

    pub fn decode_tax_params(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_tax_params".to_string());
        Ok(value)
    }

    pub fn decode_bulk_params(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_bulk_params".to_string());
        Ok(value)
    }

    pub fn decode_tenant_params_checked(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        if raw.len() > MAX_RPC_BYTES || !raw.first().map(|b| ALLOWED_RPC_TYPES.contains(b)).unwrap_or(false) { return Err("rpc type not allowed".into()); }
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_tenant_params_checked".to_string());
        Ok(value)
    }

    pub fn decode_order_params_checked(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        if raw.len() > MAX_RPC_BYTES || !raw.first().map(|b| ALLOWED_RPC_TYPES.contains(b)).unwrap_or(false) { return Err("rpc type not allowed".into()); }
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_order_params_checked".to_string());
        Ok(value)
    }

    pub fn decode_user_params_checked(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        if raw.len() > MAX_RPC_BYTES || !raw.first().map(|b| ALLOWED_RPC_TYPES.contains(b)).unwrap_or(false) { return Err("rpc type not allowed".into()); }
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_user_params_checked".to_string());
        Ok(value)
    }

    pub fn decode_payment_params_checked(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        if raw.len() > MAX_RPC_BYTES || !raw.first().map(|b| ALLOWED_RPC_TYPES.contains(b)).unwrap_or(false) { return Err("rpc type not allowed".into()); }
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_payment_params_checked".to_string());
        Ok(value)
    }

    pub fn decode_refund_params_checked(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        if raw.len() > MAX_RPC_BYTES || !raw.first().map(|b| ALLOWED_RPC_TYPES.contains(b)).unwrap_or(false) { return Err("rpc type not allowed".into()); }
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_refund_params_checked".to_string());
        Ok(value)
    }

    pub fn decode_shipping_params_checked(&mut self, raw: &[u8]) -> Result<RpcParams, Error> {
        if raw.len() > MAX_RPC_BYTES || !raw.first().map(|b| ALLOWED_RPC_TYPES.contains(b)).unwrap_or(false) { return Err("rpc type not allowed".into()); }
        let value: RpcParams = bincode::deserialize(raw)?;
        self.seen.push("decode_shipping_params_checked".to_string());
        Ok(value)
    }

}
