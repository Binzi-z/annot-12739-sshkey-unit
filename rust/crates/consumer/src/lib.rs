use serde::Deserialize;

pub type Error = Box<dyn std::error::Error>;

#[derive(Clone, Deserialize)]
pub struct Event { pub topic: String, pub payload: Vec<u8> }

#[derive(Default)]
pub struct EventConsumer {
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

impl EventConsumer {
    pub fn consume_order_event(&mut self, raw: &[u8]) -> Result<Event, Error> {
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_order_event".to_string());
        Ok(value)
    }

    pub fn consume_payment_event(&mut self, raw: &[u8]) -> Result<Event, Error> {
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_payment_event".to_string());
        Ok(value)
    }

    pub fn consume_shipment_event(&mut self, raw: &[u8]) -> Result<Event, Error> {
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_shipment_event".to_string());
        Ok(value)
    }

    pub fn consume_inventory_event(&mut self, raw: &[u8]) -> Result<Event, Error> {
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_inventory_event".to_string());
        Ok(value)
    }

    pub fn consume_user_event(&mut self, raw: &[u8]) -> Result<Event, Error> {
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_user_event".to_string());
        Ok(value)
    }

    pub fn consume_tenant_event(&mut self, raw: &[u8]) -> Result<Event, Error> {
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_tenant_event".to_string());
        Ok(value)
    }

    pub fn consume_audit_event(&mut self, raw: &[u8]) -> Result<Event, Error> {
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_audit_event".to_string());
        Ok(value)
    }

    pub fn consume_notify_event(&mut self, raw: &[u8]) -> Result<Event, Error> {
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_notify_event".to_string());
        Ok(value)
    }

    pub fn consume_metric_event(&mut self, raw: &[u8]) -> Result<Event, Error> {
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_metric_event".to_string());
        Ok(value)
    }

    pub fn consume_quote_event(&mut self, raw: &[u8]) -> Result<Event, Error> {
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_quote_event".to_string());
        Ok(value)
    }

    pub fn consume_claim_event(&mut self, raw: &[u8]) -> Result<Event, Error> {
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_claim_event".to_string());
        Ok(value)
    }

    pub fn consume_supplier_event(&mut self, raw: &[u8]) -> Result<Event, Error> {
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_supplier_event".to_string());
        Ok(value)
    }

    pub fn consume_route_event(&mut self, raw: &[u8]) -> Result<Event, Error> {
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_route_event".to_string());
        Ok(value)
    }

    pub fn consume_order_event_checked(&mut self, raw: &[u8]) -> Result<Event, Error> {
        if !verify_signature(raw) { return Err("event signature rejected".into()); }
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_order_event_checked".to_string());
        Ok(value)
    }

    pub fn consume_payment_event_checked(&mut self, raw: &[u8]) -> Result<Event, Error> {
        if !verify_signature(raw) { return Err("event signature rejected".into()); }
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_payment_event_checked".to_string());
        Ok(value)
    }

    pub fn consume_shipment_event_checked(&mut self, raw: &[u8]) -> Result<Event, Error> {
        if !verify_signature(raw) { return Err("event signature rejected".into()); }
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_shipment_event_checked".to_string());
        Ok(value)
    }

    pub fn consume_inventory_event_checked(&mut self, raw: &[u8]) -> Result<Event, Error> {
        if !verify_signature(raw) { return Err("event signature rejected".into()); }
        let value: Event = bincode::deserialize(raw)?;
        self.seen.push("consume_inventory_event_checked".to_string());
        Ok(value)
    }

}
