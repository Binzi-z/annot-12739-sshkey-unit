use crate::traits::ByteSource;
use std::path::PathBuf;

/// 文件源：从磁盘读出一段待反序列化的字节。
pub struct FileSource {
    paths: Vec<PathBuf>,
    index: usize,
}

impl FileSource {
    pub fn new(paths: Vec<PathBuf>) -> Self {
        Self { paths, index: 0 }
    }
}

impl ByteSource for FileSource {
    fn next(&mut self) -> Option<Vec<u8>> {
        let path = self.paths.get(self.index)?;
        self.index += 1;
        std::fs::read(path).ok()
    }
}
