use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::Deref;
use core::sync::atomic::{AtomicBool, Ordering};

use super::spinlock::SpinLock;

pub struct LazyLock<T, F = fn() -> T> {
    ready: AtomicBool,                 // set true after init completes
    value: UnsafeCell<MaybeUninit<T>>, // storage without requiring Default
    init: SpinLock<Option<F>>,         // Some(f) until first init; then None
}

impl<T> LazyLock<T, fn() -> T> {
    pub const fn new_const(f: fn() -> T) -> Self {
        Self {
            ready: AtomicBool::new(false),
            value: UnsafeCell::new(MaybeUninit::uninit()),
            init: SpinLock::new(Some(f)),
        }
    }
}

impl<T, F: FnOnce() -> T> LazyLock<T, F> {
    pub fn new(f: F) -> Self {
        Self {
            ready: AtomicBool::new(false),
            value: UnsafeCell::new(MaybeUninit::uninit()),
            init: SpinLock::new(Some(f)),
        }
    }

    pub fn get(&self) -> &T {
        if self.ready.load(Ordering::Acquire) {
            return unsafe { self.assume_init_ref() };
        }

        let mut guard = self.init.lock();

        if self.ready.load(Ordering::Acquire) {
            return unsafe { self.assume_init_ref() };
        }

        let f = guard.take().expect("LazyLock init reentered");
        unsafe { (*self.value.get()).write(f()) };
        self.ready.store(true, Ordering::Release);

        unsafe { self.assume_init_ref() }
    }

    pub fn get_mut(&mut self) -> &mut T {
        if !self.ready.load(Ordering::Acquire) {
            if let Some(f) = self.init.get_mut().take() {
                let value = f();
                unsafe { (*self.value.get()).write(value) };
                self.ready.store(true, Ordering::Release);
            } else {
                panic!("LazyLock init reentered");
            }
        }
        unsafe { &mut *(*self.value.get()).as_mut_ptr() }
    }

    #[inline]
    unsafe fn assume_init_ref(&self) -> &T {
        unsafe { &*(*self.value.get()).as_ptr() }
    }

    pub fn try_get(&self) -> Option<&T> {
        if self.ready.load(Ordering::Acquire) {
            Some(unsafe { self.assume_init_ref() })
        } else {
            None
        }
    }
}

impl<T, F> Deref for LazyLock<T, F>
where
    F: FnOnce() -> T,
{
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

unsafe impl<T: Sync, F: Send> Sync for LazyLock<T, F> {}
unsafe impl<T: Send, F: Send> Send for LazyLock<T, F> {}
