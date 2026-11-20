use serde::Deserialize;

pub type Error = Box<dyn std::error::Error>;

#[derive(Clone, Deserialize)]
pub struct CacheEntry { pub key: String, pub body: Vec<u8> }

#[derive(Default)]
pub struct CacheStore {
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

impl CacheStore {
    pub fn load_tenant(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_tenant".to_string());
        Ok(value)
    }

    pub fn load_price(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_price".to_string());
        Ok(value)
    }

    pub fn load_inventory(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_inventory".to_string());
        Ok(value)
    }

    pub fn load_session(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_session".to_string());
        Ok(value)
    }

    pub fn load_config(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_config".to_string());
        Ok(value)
    }

    pub fn load_token(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_token".to_string());
        Ok(value)
    }

    pub fn load_profile(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_profile".to_string());
        Ok(value)
    }

    pub fn load_cart(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_cart".to_string());
        Ok(value)
    }

    pub fn load_quote(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_quote".to_string());
        Ok(value)
    }

    pub fn load_route(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_route".to_string());
        Ok(value)
    }

    pub fn load_sku(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_sku".to_string());
        Ok(value)
    }

    pub fn load_fx(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_fx".to_string());
        Ok(value)
    }

    pub fn load_tenant_checked(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        if raw.len() > MAX_CACHE_BYTES || raw.first() != Some(&CACHE_TAG) { return Err("cache entry rejected".into()); }
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_tenant_checked".to_string());
        Ok(value)
    }

    pub fn load_price_checked(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        if raw.len() > MAX_CACHE_BYTES || raw.first() != Some(&CACHE_TAG) { return Err("cache entry rejected".into()); }
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_price_checked".to_string());
        Ok(value)
    }

    pub fn load_inventory_checked(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        if raw.len() > MAX_CACHE_BYTES || raw.first() != Some(&CACHE_TAG) { return Err("cache entry rejected".into()); }
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_inventory_checked".to_string());
        Ok(value)
    }

    pub fn load_config_checked(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        if raw.len() > MAX_CACHE_BYTES || raw.first() != Some(&CACHE_TAG) { return Err("cache entry rejected".into()); }
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_config_checked".to_string());
        Ok(value)
    }

    pub fn load_token_checked(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        if raw.len() > MAX_CACHE_BYTES || raw.first() != Some(&CACHE_TAG) { return Err("cache entry rejected".into()); }
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_token_checked".to_string());
        Ok(value)
    }

    pub fn load_profile_checked(&mut self, raw: &[u8]) -> Result<CacheEntry, Error> {
        if raw.len() > MAX_CACHE_BYTES || raw.first() != Some(&CACHE_TAG) { return Err("cache entry rejected".into()); }
        let value: CacheEntry = bincode::deserialize(raw)?;
        self.seen.push("load_profile_checked".to_string());
        Ok(value)
    }

}
