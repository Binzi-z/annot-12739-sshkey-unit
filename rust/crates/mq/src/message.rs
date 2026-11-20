use ingest::ByteSource;
use std::collections::VecDeque;

/// 队列消息源：消费端取到的原始 payload。
pub struct MessageSource {
    pending: VecDeque<Vec<u8>>,
}

impl MessageSource {
    pub fn new(payloads: Vec<Vec<u8>>) -> Self {
        Self { pending: payloads.into() }
    }
}

impl ByteSource for MessageSource {
    fn next(&mut self) -> Option<Vec<u8>> {
        self.pending.pop_front()
    }
}
