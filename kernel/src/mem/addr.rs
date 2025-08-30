pub trait Addr {
    const NULL: Self;
    fn from_usize(addr: usize) -> Self;
    fn from_ptr(addr: *const u8) -> Self;
    fn as_usize(&self) -> usize;
    fn as_ptr(&self) -> *const u8 {
        self.as_usize() as *const u8
    }
    fn as_ptr_mut(&self) -> *mut u8 {
        self.as_usize() as *mut u8
    }
    fn align_up(&self, align: usize) -> Self;
    fn is_aligned(&self, align: usize) -> bool;
}

macro_rules! impl_addr {
    ($name:ident) => {
        #[repr(transparent)]
        #[derive(Copy, Clone, PartialEq, Debug)]
        pub struct $name(usize);
        impl Addr for $name {
            const NULL: Self = $name(0);

            fn from_usize(addr: usize) -> Self {
                $name(addr)
            }

            fn from_ptr(addr: *const u8) -> Self {
                $name(addr as usize)
            }

            fn as_usize(&self) -> usize {
                self.0
            }

            fn align_up(&self, align: usize) -> Self {
                debug_assert!(align.is_power_of_two());
                let offset = self.as_ptr().align_offset(align);
                $name::from_ptr(unsafe { self.as_ptr().add(offset) })
            }

            fn is_aligned(&self, align: usize) -> bool {
                self.as_ptr().is_aligned_to(align)
            }
        }
    };
}

impl_addr!(PhysAddr);
impl_addr!(VirtAddr);

#[derive(Copy, Clone, Debug)]
pub struct AddrRange<T: Addr> {
    pub start: T,
    pub end: T,
}

impl<T: Addr> AddrRange<T> {
    pub fn len(&self) -> usize {
        self.end.as_usize() - self.start.as_usize()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Copy, Clone, Debug)]
pub enum PageSize {
    Size4K,
    Size2M,
    Size1G,
}

impl PageSize {
    pub fn bytes(&self) -> usize {
        match self {
            PageSize::Size4K => 4096,
            PageSize::Size2M => 2 * 1024 * 1024,
            PageSize::Size1G => 1024 * 1024 * 1024,
        }
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
            start.is_aligned(size.bytes()),
            "Page start address {:?} is not aligned to {} bytes",
            start.as_usize(),
            size.bytes()
        );
        Self { start, size }
    }

    pub fn end(&self) -> T {
        T::from_usize(self.start.as_usize() + self.size.bytes())
    }

    pub fn contains(&self, addr: T) -> bool {
        let addr_val = addr.as_usize();
        addr_val >= self.start.as_usize() && addr_val < self.end().as_usize()
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
