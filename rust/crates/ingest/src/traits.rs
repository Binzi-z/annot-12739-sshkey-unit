/// 链路源头抽象：队列消息、网络帧、文件都由它进入分析器。
pub trait ByteSource {
    fn next(&mut self) -> Option<Vec<u8>>;
}
