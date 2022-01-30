use std::mem;

/// The length of a MAC in bytes.
pub const MAC_LEN: usize = 16;

/// The length of a compressed ristretto255 point in bytes.
pub const POINT_LEN: usize = 32;

/// The length of a ristretto255 scalar in bytes.
pub const SCALAR_LEN: usize = 32;

/// The length of a `u32` in bytes.
pub const U32_LEN: usize = mem::size_of::<u32>();

/// The length of a `u64` in bytes.
pub const U64_LEN: usize = mem::size_of::<u64>();
