use crate::util::{take_one, Error};
use ingest::FileSource;

use rpc::RpcDecoder;
use consumer::EventConsumer;

pub fn handle_file_01(source: &mut ingest::FileSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = RpcDecoder::default();
    sink.decode_route_params(&raw)?;
    Ok(())
}

pub fn handle_file_02(source: &mut ingest::FileSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = RpcDecoder::default();
    sink.decode_tax_params(&raw)?;
    Ok(())
}

pub fn handle_file_03(source: &mut ingest::FileSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = RpcDecoder::default();
    sink.decode_bulk_params(&raw)?;
    Ok(())
}

pub fn handle_file_04(source: &mut ingest::FileSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = EventConsumer::default();
    sink.consume_order_event(&raw)?;
    Ok(())
}

pub fn handle_file_05(source: &mut ingest::FileSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = EventConsumer::default();
    sink.consume_payment_event(&raw)?;
    Ok(())
}

pub fn handle_file_06(source: &mut ingest::FileSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = EventConsumer::default();
    sink.consume_shipment_event(&raw)?;
    Ok(())
}

pub fn handle_file_07(source: &mut ingest::FileSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = EventConsumer::default();
    sink.consume_inventory_event(&raw)?;
    Ok(())
}

pub fn handle_file_08(source: &mut ingest::FileSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = EventConsumer::default();
    sink.consume_user_event(&raw)?;
    Ok(())
}

pub fn handle_file_09(source: &mut ingest::FileSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = EventConsumer::default();
    sink.consume_tenant_event(&raw)?;
    Ok(())
}

pub fn handle_file_10(source: &mut ingest::FileSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = EventConsumer::default();
    sink.consume_audit_event(&raw)?;
    Ok(())
}

pub fn handle_file_11(source: &mut ingest::FileSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = EventConsumer::default();
    sink.consume_notify_event(&raw)?;
    Ok(())
}

pub fn handle_file_12(source: &mut ingest::FileSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = EventConsumer::default();
    sink.consume_metric_event(&raw)?;
    Ok(())
}

pub fn handle_file_13(source: &mut ingest::FileSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = EventConsumer::default();
    sink.consume_quote_event(&raw)?;
    Ok(())
}

pub fn handle_file_14(source: &mut ingest::FileSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = EventConsumer::default();
    sink.consume_claim_event(&raw)?;
    Ok(())
}

pub fn handle_file_15(source: &mut ingest::FileSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = EventConsumer::default();
    sink.consume_supplier_event(&raw)?;
    Ok(())
}

pub fn handle_file_16(source: &mut ingest::FileSource) -> Result<(), Error> {
    let raw = take_one(source)?;
    let mut sink = EventConsumer::default();
    sink.consume_route_event(&raw)?;
    Ok(())
}
