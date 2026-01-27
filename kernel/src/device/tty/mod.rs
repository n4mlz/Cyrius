use alloc::collections::VecDeque;
use alloc::sync::Arc;

use crate::arch::Arch;
use crate::arch::api::ArchDevice;
use crate::device::char::CharDevice;
use crate::device::{Device, DeviceType};
use crate::println;
use crate::process::{ControllingTty, PROCESS_TABLE, ProcessHandle};
use crate::thread::SCHEDULER;
use crate::util::lazylock::LazyLock;
use crate::util::spinlock::SpinLock;
use crate::util::stream::{ControlError, ControlOps, ControlRequest, ReadOps, WriteOps};

const TTY_BUFFER_LIMIT: usize = 4096;

const IOCTL_TCGETS: u64 = 0x5401;
const IOCTL_TCSETS: u64 = 0x5402;
const IOCTL_TCSETSW: u64 = 0x5403;
const IOCTL_TCSETSF: u64 = 0x5404;
const IOCTL_TIOCSCTTY: u64 = 0x540e;
const IOCTL_TIOCGPGRP: u64 = 0x540f;
const IOCTL_TIOCSPGRP: u64 = 0x5410;
const IOCTL_TIOCGWINSZ: u64 = 0x5413;
const IOCTL_TIOCSWINSZ: u64 = 0x5414;

const DEFAULT_ROWS: u16 = 24;
const DEFAULT_COLS: u16 = 80;

const NCCS: usize = 32;
const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VTIME: usize = 5;
const VMIN: usize = 6;
const VSTART: usize = 8;
const VSTOP: usize = 9;
const VSUSP: usize = 10;
const VREPRINT: usize = 12;
const VWERASE: usize = 14;
const VLNEXT: usize = 15;

const IF_IGNBRK: u32 = 0x0001;
const IF_BRKINT: u32 = 0x0002;
const IF_ISTRIP: u32 = 0x0020;
const IF_ICRNL: u32 = 0x0100;
const IF_IXON: u32 = 0x0400;

const OF_OPOST: u32 = 0x0001;
const OF_ONLCR: u32 = 0x0004;

const CF_CREAD: u32 = 0x0080;
const CF_CS8: u32 = 0x0030;

const LF_ISIG: u32 = 0x0001;
const LF_ICANON: u32 = 0x0002;
const LF_ECHO: u32 = 0x0008;
const LF_IEXTEN: u32 = 0x8000;

/// Linux termios layout for x86_64 (glibc compatible).
#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxTermios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; NCCS],
    c_ispeed: u32,
    c_ospeed: u32,
}

impl LinuxTermios {
    fn default_sane() -> Self {
        let mut c_cc = [0u8; NCCS];
        c_cc[VINTR] = 0x03;
        c_cc[VQUIT] = 0x1c;
        c_cc[VERASE] = 0x7f;
        c_cc[VKILL] = 0x15;
        c_cc[VEOF] = 0x04;
        c_cc[VTIME] = 0;
        c_cc[VMIN] = 1;
        c_cc[VSTART] = 0x11;
        c_cc[VSTOP] = 0x13;
        c_cc[VSUSP] = 0x1a;
        c_cc[VREPRINT] = 0x12;
        c_cc[VWERASE] = 0x17;
        c_cc[VLNEXT] = 0x16;
        Self {
            c_iflag: IF_IGNBRK | IF_BRKINT | IF_ISTRIP | IF_ICRNL | IF_IXON,
            c_oflag: OF_OPOST | OF_ONLCR,
            c_cflag: CF_CREAD | CF_CS8,
            c_lflag: LF_ISIG | LF_ICANON | LF_ECHO | LF_IEXTEN,
            c_line: 0,
            c_cc,
            c_ispeed: 0,
            c_ospeed: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxWinsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

impl LinuxWinsize {
    fn default_sane() -> Self {
        Self {
            ws_row: DEFAULT_ROWS,
            ws_col: DEFAULT_COLS,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }
}

struct TtyState {
    termios: LinuxTermios,
    winsize: LinuxWinsize,
    pgrp: u32,
}

/// Pseudo TTY backed by the architecture console.
///
/// # Implicit dependencies
/// - Assumes `Arch::console()` is initialised and can be accessed from any context that invokes
///   read/write operations on the global TTY.
/// - Resolves the caller process group via the scheduler when answering job-control ioctls.
pub struct TtyDevice {
    input: SpinLock<VecDeque<u8>>,
    output: SpinLock<VecDeque<u8>>,
    state: SpinLock<TtyState>,
}

impl TtyDevice {
    pub fn new() -> Self {
        Self {
            input: SpinLock::new(VecDeque::new()),
            output: SpinLock::new(VecDeque::new()),
            state: SpinLock::new(TtyState {
                termios: LinuxTermios::default_sane(),
                winsize: LinuxWinsize::default_sane(),
                pgrp: 0,
            }),
        }
    }

    pub fn push_input(&self, data: &[u8]) {
        let mut guard = self.input.lock();
        for byte in data {
            guard.push_back(*byte);
        }
    }

    pub fn drain_output(&self) -> alloc::vec::Vec<u8> {
        let mut guard = self.output.lock();
        guard.drain(..).collect()
    }

    pub fn clear_output(&self) {
        let mut guard = self.output.lock();
        guard.clear();
    }

    fn record_output(&self, data: &[u8]) {
        let mut guard = self.output.lock();
        for byte in data {
            guard.push_back(*byte);
        }
        while guard.len() > TTY_BUFFER_LIMIT {
            let _ = guard.pop_front();
        }
    }

    fn read_from_input(&self, buf: &mut [u8]) -> usize {
        let mut guard = self.input.lock();
        let mut read = 0usize;
        while read < buf.len() {
            if let Some(byte) = guard.pop_front() {
                buf[read] = byte;
                read += 1;
            } else {
                break;
            }
        }
        read
    }

    fn termios_snapshot(&self) -> LinuxTermios {
        self.state.lock().termios
    }

    fn winsize_snapshot(&self) -> LinuxWinsize {
        self.state.lock().winsize
    }

    fn set_termios(&self, termios: LinuxTermios) {
        self.state.lock().termios = termios;
    }

    fn set_winsize(&self, winsize: LinuxWinsize) {
        self.state.lock().winsize = winsize;
    }

    fn pgrp(&self) -> u32 {
        self.state.lock().pgrp
    }

    fn set_pgrp(&self, pgrp: u32) {
        self.state.lock().pgrp = pgrp;
    }

    fn current_process(&self) -> Option<ProcessHandle> {
        let pid = SCHEDULER.current_process_id()?;
        PROCESS_TABLE.process_handle(pid).ok()
    }

    fn current_process_pgrp(&self) -> Option<u32> {
        let proc = self.current_process()?;
        Some(proc.pgrp_id() as u32)
    }

    fn require_controlling_tty(&self) -> Result<ProcessHandle, ControlError> {
        let proc = self.current_process().ok_or(ControlError::Invalid)?;
        if !proc.has_controlling_tty() {
            return Err(ControlError::Invalid);
        }
        Ok(proc)
    }
}

impl Default for TtyDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for TtyDevice {
    fn name(&self) -> &str {
        "tty"
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Char
    }
}

impl ReadOps for TtyDevice {
    type Error = core::convert::Infallible;

    fn read(&self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut total = self.read_from_input(buf);
        if total == 0 {
            let console = Arch::console();
            let read = console.read(&mut buf[total..]).unwrap_or(0);
            total += read;
        }
        Ok(total)
    }
}

impl WriteOps for TtyDevice {
    type Error = core::convert::Infallible;

    fn write(&self, data: &[u8]) -> Result<usize, Self::Error> {
        let console = Arch::console();
        let written = console.write(data).unwrap_or(0);
        self.record_output(&data[..written]);
        Ok(written)
    }
}

impl CharDevice for TtyDevice {
    type Error = core::convert::Infallible;
}

impl ControlOps for TtyDevice {
    fn control(&self, request: &ControlRequest<'_>) -> Result<u64, ControlError> {
        println!(
            "[tty ioctl] pid={} cmd=0x{:x}",
            SCHEDULER.current_process_id().unwrap_or(0),
            request.command
        );
        let result = match request.command {
            IOCTL_TCGETS => {
                let termios = self.termios_snapshot();
                request.write_struct(&termios)?;
                Ok(0)
            }
            IOCTL_TCSETS | IOCTL_TCSETSW | IOCTL_TCSETSF => {
                let termios = request.read_struct::<LinuxTermios>()?;
                self.set_termios(termios);
                Ok(0)
            }
            IOCTL_TIOCGWINSZ => {
                let winsize = self.winsize_snapshot();
                request.write_struct(&winsize)?;
                Ok(0)
            }
            IOCTL_TIOCSWINSZ => {
                let winsize = request.read_struct::<LinuxWinsize>()?;
                self.set_winsize(winsize);
                Ok(0)
            }
            IOCTL_TIOCSCTTY => {
                let proc = self.current_process().ok_or(ControlError::Invalid)?;
                let pid = proc.id();
                if proc.session_id() != pid {
                    return Err(ControlError::Invalid);
                }
                if proc.has_controlling_tty() {
                    return Err(ControlError::Invalid);
                }
                proc.set_controlling_tty(ControllingTty::Global);
                self.set_pgrp(proc.pgrp_id() as u32);
                Ok(0)
            }
            IOCTL_TIOCGPGRP => {
                let _ = self.require_controlling_tty()?;
                let mut pgrp = self.pgrp();
                if pgrp == 0 {
                    if let Some(current) = self.current_process_pgrp() {
                        pgrp = current;
                        self.set_pgrp(pgrp);
                    }
                }
                let pgrp = pgrp as i32;
                request.write_struct(&pgrp)?;
                Ok(0)
            }
            IOCTL_TIOCSPGRP => {
                let _ = self.require_controlling_tty()?;
                let pgrp = request.read_struct::<i32>()?;
                if pgrp < 0 {
                    return Err(ControlError::Invalid);
                }
                if pgrp == 0 {
                    return Err(ControlError::Invalid);
                }
                self.set_pgrp(pgrp as u32);
                Ok(0)
            }
            _ => Err(ControlError::Unsupported),
        };
        println!(
            "[tty ioctl] pid={} cmd=0x{:x} ret={}",
            SCHEDULER.current_process_id().unwrap_or(0),
            request.command,
            match &result {
                Ok(val) => alloc::format!("ok({})", val),
                Err(err) => alloc::format!("err({:?})", err),
            }
        );
        result
    }
}

fn init_tty() -> Arc<TtyDevice> {
    Arc::new(TtyDevice::new())
}

static GLOBAL_TTY: LazyLock<Arc<TtyDevice>> = LazyLock::new_const(init_tty);

pub fn global_tty() -> Arc<TtyDevice> {
    GLOBAL_TTY.get().clone()
}
