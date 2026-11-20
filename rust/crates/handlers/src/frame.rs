use crate::util::{take_one, Error};
use wire::FrameSource;

use cache::CacheStore;
use rpc::RpcDecoder;

pub fn handle_frame_01(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = CacheStore::default();
    sink.load_token(&raw)?;
    Ok(())
}

pub fn handle_frame_02(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = CacheStore::default();
    sink.load_profile(&raw)?;
    Ok(())
}

pub fn handle_frame_03(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = CacheStore::default();
    sink.load_cart(&raw)?;
    Ok(())
}

pub fn handle_frame_04(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = CacheStore::default();
    sink.load_quote(&raw)?;
    Ok(())
}

pub fn handle_frame_05(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = CacheStore::default();
    sink.load_route(&raw)?;
    Ok(())
}

pub fn handle_frame_06(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = CacheStore::default();
    sink.load_sku(&raw)?;
    Ok(())
}

pub fn handle_frame_07(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = CacheStore::default();
    sink.load_fx(&raw)?;
    Ok(())
}

pub fn handle_frame_08(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = RpcDecoder::default();
    sink.decode_tenant_params(&raw)?;
    Ok(())
}

pub fn handle_frame_09(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = RpcDecoder::default();
    sink.decode_order_params(&raw)?;
    Ok(())
}

pub fn handle_frame_10(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = RpcDecoder::default();
    sink.decode_user_params(&raw)?;
    Ok(())
}

pub fn handle_frame_11(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = RpcDecoder::default();
    sink.decode_payment_params(&raw)?;
    Ok(())
}

pub fn handle_frame_12(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = RpcDecoder::default();
    sink.decode_refund_params(&raw)?;
    Ok(())
}

pub fn handle_frame_13(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = RpcDecoder::default();
    sink.decode_shipping_params(&raw)?;
    Ok(())
}

pub fn handle_frame_14(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = RpcDecoder::default();
    sink.decode_inventory_params(&raw)?;
    Ok(())
}

pub fn handle_frame_15(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = RpcDecoder::default();
    sink.decode_catalog_params(&raw)?;
    Ok(())
}

pub fn handle_frame_16(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = RpcDecoder::default();
    sink.decode_quote_params(&raw)?;
    Ok(())
}

pub fn handle_frame_17(source: &mut wire::FrameSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = RpcDecoder::default();
    sink.decode_claim_params(&raw)?;
    Ok(())
}
