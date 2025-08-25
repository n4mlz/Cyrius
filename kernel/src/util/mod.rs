#[macro_export]
macro_rules! cast {
    ($n:expr) => {
        num_traits::cast($n).unwrap()
    };
}
