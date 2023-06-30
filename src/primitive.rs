pub trait Primitive<const SIZE: usize>:
    Sized
    + TryInto<u64>
    + std::fmt::Debug
    + TryInto<u128>
    + TryInto<usize>
    + TryFrom<u64>
    + TryFrom<u128>
    + Copy
{
    const BYTES: usize = SIZE;

    fn to_u64(self) -> u64;

    fn from_ne_bytes(bytes: [u8; SIZE]) -> Self;
}

macro_rules! impl_primitive {
    ($type:ty,$bytes:expr) => {
        impl Primitive<$bytes> for $type {
            fn to_u64(self) -> u64 {
                self as u64
            }

            fn from_ne_bytes(bytes: [u8; $bytes]) -> Self {
                // assert!(size == $bytes);
                // let bytes = unsafe { core::mem::transmute::<[u8; size], [u8; $bytes]>(bytes) };
                Self::from_ne_bytes(bytes)
            }
        }
    };
}

impl_primitive!(u8, 1);
impl_primitive!(u16, 2);
impl_primitive!(u32, 4);
impl_primitive!(u64, 8);
impl_primitive!(usize, 8);
impl_primitive!(u128, 16);
impl_primitive!(i8, 1);
impl_primitive!(i16, 2);
impl_primitive!(i32, 4);
impl_primitive!(i64, 8);
impl_primitive!(isize, 8);
impl_primitive!(i128, 16);
