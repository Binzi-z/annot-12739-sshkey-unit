use ingest::ByteSource;
use std::collections::VecDeque;

/// 网络帧源：把 TCP 上读到的长度前缀帧拆成 payload。
pub struct FrameSource {
    frames: VecDeque<Vec<u8>>,
}

impl FrameSource {
    pub fn from_wire_bytes(mut buf: Vec<u8>) -> Self {
        let mut frames = VecDeque::new();
        while buf.len() >= 4 {
            let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if buf.len() < 4 + len {
                break;
            }
            frames.push_back(buf[4..4 + len].to_vec());
            buf.drain(..4 + len);
        }
        Self { frames }
    }
}

impl ByteSource for FrameSource {
    fn next(&mut self) -> Option<Vec<u8>> {
        self.frames.pop_front()
    }
}
