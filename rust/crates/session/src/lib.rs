use serde::Deserialize;

pub type Error = Box<dyn std::error::Error>;

#[derive(Clone, Deserialize)]
pub struct Session { pub id: u64, pub user: String }

#[derive(Default)]
pub struct SessionStore {
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

impl SessionStore {
    pub fn restore_login(&mut self, raw: &[u8]) -> Result<Session, Error> {
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_login".to_string());
        Ok(value)
    }

    pub fn restore_admin(&mut self, raw: &[u8]) -> Result<Session, Error> {
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_admin".to_string());
        Ok(value)
    }

    pub fn restore_tenant(&mut self, raw: &[u8]) -> Result<Session, Error> {
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_tenant".to_string());
        Ok(value)
    }

    pub fn restore_device(&mut self, raw: &[u8]) -> Result<Session, Error> {
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_device".to_string());
        Ok(value)
    }

    pub fn restore_oauth(&mut self, raw: &[u8]) -> Result<Session, Error> {
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_oauth".to_string());
        Ok(value)
    }

    pub fn restore_service(&mut self, raw: &[u8]) -> Result<Session, Error> {
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_service".to_string());
        Ok(value)
    }

    pub fn restore_guest(&mut self, raw: &[u8]) -> Result<Session, Error> {
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_guest".to_string());
        Ok(value)
    }

    pub fn restore_partner(&mut self, raw: &[u8]) -> Result<Session, Error> {
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_partner".to_string());
        Ok(value)
    }

    pub fn restore_operator(&mut self, raw: &[u8]) -> Result<Session, Error> {
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_operator".to_string());
        Ok(value)
    }

    pub fn restore_api(&mut self, raw: &[u8]) -> Result<Session, Error> {
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_api".to_string());
        Ok(value)
    }

    pub fn restore_console(&mut self, raw: &[u8]) -> Result<Session, Error> {
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_console".to_string());
        Ok(value)
    }

    pub fn restore_audit(&mut self, raw: &[u8]) -> Result<Session, Error> {
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_audit".to_string());
        Ok(value)
    }

    pub fn restore_login_checked(&mut self, raw: &[u8]) -> Result<Session, Error> {
        if raw.len() > MAX_SESSION_BYTES { return Err("session frame too large".into()); }
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_login_checked".to_string());
        Ok(value)
    }

    pub fn restore_admin_checked(&mut self, raw: &[u8]) -> Result<Session, Error> {
        if raw.len() > MAX_SESSION_BYTES { return Err("session frame too large".into()); }
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_admin_checked".to_string());
        Ok(value)
    }

    pub fn restore_tenant_checked(&mut self, raw: &[u8]) -> Result<Session, Error> {
        if raw.len() > MAX_SESSION_BYTES { return Err("session frame too large".into()); }
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_tenant_checked".to_string());
        Ok(value)
    }

    pub fn restore_device_checked(&mut self, raw: &[u8]) -> Result<Session, Error> {
        if raw.len() > MAX_SESSION_BYTES { return Err("session frame too large".into()); }
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_device_checked".to_string());
        Ok(value)
    }

    pub fn restore_oauth_checked(&mut self, raw: &[u8]) -> Result<Session, Error> {
        if raw.len() > MAX_SESSION_BYTES { return Err("session frame too large".into()); }
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_oauth_checked".to_string());
        Ok(value)
    }

    pub fn restore_service_checked(&mut self, raw: &[u8]) -> Result<Session, Error> {
        if raw.len() > MAX_SESSION_BYTES { return Err("session frame too large".into()); }
        let value: Session = bincode::deserialize(raw)?;
        self.seen.push("restore_service_checked".to_string());
        Ok(value)
    }

}
