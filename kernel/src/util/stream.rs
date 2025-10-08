pub enum StreamError {
    Unknown,
}

pub trait StreamOps {
    fn read(&self, buffer: &mut [u8]) -> Result<usize, StreamError>;
    fn write(&self, buffer: &[u8]) -> Result<usize, StreamError>;
}
