use alloc::sync::Arc;

use crate::fs::{File, VfsError};
use crate::interrupt::INTERRUPTS;
use crate::net::{SocketAddr, TcpError, TcpListener, TcpStream};
use crate::util::spinlock::SpinLock;

#[derive(Debug)]
pub enum SocketError {
    InvalidState,
    Tcp(TcpError),
}

impl From<TcpError> for SocketError {
    fn from(err: TcpError) -> Self {
        Self::Tcp(err)
    }
}

enum TcpSocketState {
    Init,
    Bound(SocketAddr),
    Listening(TcpListener),
    Stream(TcpStream),
}

pub struct TcpSocketFile {
    state: SpinLock<TcpSocketState>,
}

impl TcpSocketFile {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: SpinLock::new(TcpSocketState::Init),
        })
    }

    pub fn bind(&self, addr: SocketAddr) -> Result<(), SocketError> {
        let mut guard = self.state.lock();
        match &*guard {
            TcpSocketState::Init => {
                *guard = TcpSocketState::Bound(addr);
                Ok(())
            }
            _ => Err(SocketError::InvalidState),
        }
    }

    pub fn listen(&self) -> Result<(), SocketError> {
        let mut guard = self.state.lock();
        let addr = match &*guard {
            TcpSocketState::Bound(addr) => *addr,
            _ => return Err(SocketError::InvalidState),
        };
        let listener = TcpListener::bind(addr)?;
        *guard = TcpSocketState::Listening(listener);
        Ok(())
    }

    pub fn accept(&self) -> Result<(TcpStream, SocketAddr), SocketError> {
        loop {
            let mut guard = self.state.lock();
            match &mut *guard {
                TcpSocketState::Listening(listener) => {
                    if let Some((stream, remote)) = listener.try_accept()? {
                        return Ok((stream, remote));
                    }
                }
                _ => return Err(SocketError::InvalidState),
            }
            drop(guard);
            // Syscalls may run with interrupts disabled; enable them while waiting.
            INTERRUPTS.enable();
            core::hint::spin_loop();
        }
    }

    pub fn set_stream(&self, stream: TcpStream) -> Result<(), SocketError> {
        let mut guard = self.state.lock();
        match &*guard {
            TcpSocketState::Init => {
                *guard = TcpSocketState::Stream(stream);
                Ok(())
            }
            _ => Err(SocketError::InvalidState),
        }
    }
}

impl File for TcpSocketFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize, VfsError> {
        loop {
            let mut guard = self.state.lock();
            match &mut *guard {
                TcpSocketState::Stream(stream) => match stream.try_read(buf) {
                    Ok(Some(n)) => return Ok(n),
                    Ok(None) => {}
                    Err(_) => return Err(VfsError::UnderlyingDevice),
                },
                _ => return Err(VfsError::NotFile),
            }
            drop(guard);
            INTERRUPTS.enable();
            core::hint::spin_loop();
        }
    }

    fn write(&self, data: &[u8]) -> Result<usize, VfsError> {
        let mut offset = 0usize;
        while offset < data.len() {
            let mut guard = self.state.lock();
            match &mut *guard {
                TcpSocketState::Stream(stream) => match stream.try_write(&data[offset..]) {
                    Ok(Some(0)) => return Err(VfsError::UnderlyingDevice),
                    Ok(Some(n)) => offset += n,
                    Ok(None) => {}
                    Err(_) => return Err(VfsError::UnderlyingDevice),
                },
                _ => return Err(VfsError::NotFile),
            }
            drop(guard);
            if offset < data.len() {
                INTERRUPTS.enable();
                core::hint::spin_loop();
            }
        }
        Ok(data.len())
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl Drop for TcpSocketFile {
    fn drop(&mut self) {
        let mut guard = self.state.lock();
        if let TcpSocketState::Stream(stream) = &mut *guard {
            let _ = stream.close();
        }
    }
}
