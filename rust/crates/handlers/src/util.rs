use ingest::ByteSource;

pub type Error = Box<dyn std::error::Error>;

/// 通过 trait object 取一帧：源的具体类型在这里被擦除，跨 crate 传播要靠函数摘要。
pub fn take_one(source: &mut dyn ByteSource) -> Result<Vec<u8>, Error> {
    source.next().ok_or_else(|| "unexpected end of stream".into())
}
