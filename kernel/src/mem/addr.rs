use core::convert::TryInto;

pub trait Addr: Copy + core::fmt::Debug + Eq + Ord {
    type Raw: Copy + Ord + core::ops::Sub<Output = Self::Raw> + TryInto<usize>;

    const NULL: Self;

    fn from_raw(addr: Self::Raw) -> Self;
    fn as_raw(&self) -> Self::Raw;
    fn align_up(&self, align: usize) -> Self;
    fn is_aligned(&self, align: usize) -> bool;
    fn checked_add(&self, value: usize) -> Option<Self>;
}

macro_rules! impl_addr {
    ($name:ident, $raw:ty) => {
        #[repr(transparent)]
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
        pub struct $name($raw);

        impl $name {
            pub const fn new(raw: $raw) -> Self {
                Self(raw)
            }

            pub const fn as_raw(&self) -> $raw {
                self.0
            }
        }

        impl Addr for $name {
            type Raw = $raw;

            const NULL: Self = Self(0);

            fn from_raw(addr: Self::Raw) -> Self {
                Self(addr)
            }

            fn as_raw(&self) -> Self::Raw {
                self.0
            }

            fn align_up(&self, align: usize) -> Self {
                assert!(align.is_power_of_two(), "alignment must be a power of two");
                let align_raw = align as $raw;
                let mask = align_raw - 1;
                let raw = self.0;
                if raw & mask == 0 {
                    return Self(raw);
                }
                let add = align_raw - (raw & mask);
                let aligned = raw.checked_add(add).expect("align_up overflow");
                Self(aligned)
            }

            fn is_aligned(&self, align: usize) -> bool {
                assert!(align.is_power_of_two(), "alignment must be a power of two");
                let mask = (align as $raw) - 1;
                (self.0 & mask) == 0
            }

            fn checked_add(&self, value: usize) -> Option<Self> {
                let value_raw = value as $raw;
                self.0.checked_add(value_raw).map(Self)
            }
        }
    };
}

impl_addr!(PhysAddr, usize);
impl_addr!(VirtAddr, usize);

pub trait VirtIntoPtr {
    fn into_ptr(self) -> *const u8;
    fn into_mut_ptr(self) -> *mut u8;
    fn from_ptr(ptr: *const u8) -> Self;
}

impl VirtIntoPtr for VirtAddr {
    fn into_ptr(self) -> *const u8 {
        self.as_raw() as *const u8
    }

    fn into_mut_ptr(self) -> *mut u8 {
        self.as_raw() as *mut u8
    }

    fn from_ptr(ptr: *const u8) -> Self {
        Self::from_raw(ptr as usize)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct AddrRange<T: Addr> {
    pub start: T,
    pub end: T,
}

impl<T: Addr> AddrRange<T> {
    pub fn len_checked(&self) -> Option<usize> {
        let start = self.start.as_raw();
        let end = self.end.as_raw();
        if end < start {
            return None;
        }
        let diff = end - start;
        diff.try_into().ok()
    }

    pub fn is_empty(&self) -> bool {
        matches!(self.len_checked(), Some(0))
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PageSize(pub usize);

impl PageSize {
    pub const SIZE_4K: Self = Self(4 * 1024);
    pub const SIZE_2M: Self = Self(2 * 1024 * 1024);
    pub const SIZE_1G: Self = Self(1024 * 1024 * 1024);

    pub const fn bytes(self) -> usize {
        self.0
    }

    pub const fn is_power_of_two(self) -> bool {
        self.0.is_power_of_two()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Page<T: Addr> {
    pub start: T,
    pub size: PageSize,
}

impl<T: Addr> Page<T> {
    pub fn new(start: T, size: PageSize) -> Self {
        assert!(
            size.is_power_of_two(),
            "Page size {} must be a power of two",
            size.bytes()
        );
        assert!(
            start.is_aligned(size.bytes()),
            "Page start address {:?} is not aligned to {} bytes",
            start,
            size.bytes()
        );
        Self { start, size }
    }

    pub fn end(&self) -> T {
        self.start
            .checked_add(self.size.bytes())
            .expect("page end overflow")
    }

    pub fn contains(&self, addr: T) -> bool {
        let addr_val = addr.as_raw();
        let start = self.start.as_raw();
        let end = self.end().as_raw();
        addr_val >= start && addr_val < end
    }
}

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct MemPerm: u8 {
        const READ = 1;
        const WRITE = 2;
        const EXEC = 4;
        const USER = 8;
    }
}

impl MemPerm {
    pub const KERNEL_RX: Self = Self::READ.union(Self::EXEC);
    pub const KERNEL_RW: Self = Self::READ.union(Self::WRITE);
    pub const KERNEL_R: Self = Self::READ;
    pub const KERNEL_RWX: Self = Self::READ.union(Self::WRITE).union(Self::EXEC);

    pub const USER_R: Self = Self::READ.union(Self::USER);
    pub const USER_RW: Self = Self::READ.union(Self::WRITE).union(Self::USER);
    pub const USER_RX: Self = Self::READ.union(Self::EXEC).union(Self::USER);
    pub const USER_RWX: Self = Self::READ
        .union(Self::WRITE)
        .union(Self::EXEC)
        .union(Self::USER);

    pub fn is_readable(&self) -> bool {
        self.contains(Self::READ)
    }

    pub fn is_writable(&self) -> bool {
        self.contains(Self::WRITE)
    }

    pub fn is_executable(&self) -> bool {
        self.contains(Self::EXEC)
    }

    pub fn is_user_accessible(&self) -> bool {
        self.contains(Self::USER)
    }
}
