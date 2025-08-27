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
        #[derive(Copy, Clone, PartialEq)]
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
