use std::ops::BitAnd;

pub trait Primitive<const SIZE: usize>:
    Sized
    + core::fmt::Debug
    + TryInto<u8>
    + TryInto<u16>
    + TryInto<u32>
    + TryInto<u64>
    + TryInto<u128>
    + TryInto<usize>
    + TryFrom<u8>
    + TryFrom<u16>
    + TryFrom<u32>
    + TryFrom<u64>
    + TryFrom<u128>
    + TryFrom<usize>
    + Copy
    + BitAnd<Output = Self>
{
    const BYTES: usize = SIZE;

    fn to_u64(self) -> u64;

    fn from_ne_bytes(bytes: [u8; SIZE]) -> Self;

    fn to_ne_bytes(self) -> [u8; SIZE];

    fn count_ones(self) -> u32;

    fn is_zero(self) -> bool;

    fn msb(self) -> bool;
}

macro_rules! impl_primitive {
    ($type:ty,$bytes:expr) => {
        impl Primitive<$bytes> for $type {
            #[inline(always)]
            fn to_u64(self) -> u64 {
                self as u64
            }

            #[inline(always)]
            fn from_ne_bytes(bytes: [u8; $bytes]) -> Self {
                // assert!(size == $bytes);
                // let bytes = unsafe { core::mem::transmute::<[u8; size], [u8; $bytes]>(bytes) };
                Self::from_ne_bytes(bytes)
            }

            #[inline(always)]
            fn to_ne_bytes(self) -> [u8; $bytes] {
                // assert!(size == $bytes);
                // let bytes = unsafe { core::mem::transmute::<[u8; size], [u8; $bytes]>(bytes) };
                <$type>::to_ne_bytes(self)
            }

            #[inline(always)]
            fn count_ones(self) -> u32 {
                <$type>::count_ones(self)
            }

            #[inline(always)]
            fn is_zero(self) -> bool {
                self == 0
            }

            #[inline(always)]
            fn msb(self) -> bool {
                ((self & (1 << (8 * $bytes - 1))) > 0)
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
