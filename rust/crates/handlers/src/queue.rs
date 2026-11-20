use crate::util::{take_one, Error};
use mq::MessageSource;

use session::SessionStore;
use cache::CacheStore;

pub fn handle_queue_01(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = SessionStore::default();
    sink.restore_login(&raw)?;
    Ok(())
}

pub fn handle_queue_02(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = SessionStore::default();
    sink.restore_admin(&raw)?;
    Ok(())
}

pub fn handle_queue_03(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = SessionStore::default();
    sink.restore_tenant(&raw)?;
    Ok(())
}

pub fn handle_queue_04(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = SessionStore::default();
    sink.restore_device(&raw)?;
    Ok(())
}

pub fn handle_queue_05(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = SessionStore::default();
    sink.restore_oauth(&raw)?;
    Ok(())
}

pub fn handle_queue_06(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = SessionStore::default();
    sink.restore_service(&raw)?;
    Ok(())
}

pub fn handle_queue_07(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = SessionStore::default();
    sink.restore_guest(&raw)?;
    Ok(())
}

pub fn handle_queue_08(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = SessionStore::default();
    sink.restore_partner(&raw)?;
    Ok(())
}

pub fn handle_queue_09(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = SessionStore::default();
    sink.restore_operator(&raw)?;
    Ok(())
}

pub fn handle_queue_10(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = SessionStore::default();
    sink.restore_api(&raw)?;
    Ok(())
}

pub fn handle_queue_11(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = SessionStore::default();
    sink.restore_console(&raw)?;
    Ok(())
}

pub fn handle_queue_12(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = SessionStore::default();
    sink.restore_audit(&raw)?;
    Ok(())
}

pub fn handle_queue_13(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = CacheStore::default();
    sink.load_tenant(&raw)?;
    Ok(())
}

pub fn handle_queue_14(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = CacheStore::default();
    sink.load_price(&raw)?;
    Ok(())
}

pub fn handle_queue_15(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = CacheStore::default();
    sink.load_inventory(&raw)?;
    Ok(())
}

pub fn handle_queue_16(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = CacheStore::default();
    sink.load_session(&raw)?;
    Ok(())
}

pub fn handle_queue_17(source: &mut mq::MessageSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = CacheStore::default();
    sink.load_config(&raw)?;
    Ok(())
}
