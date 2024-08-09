pub mod primitives;
pub mod record;
pub mod traits;

pub const UNEXPECTED_OUT_OF_BOUND_PANIC: &str = "Unexpected out-of-bound error after length check";
pub const MAX_RECORD_LENGTH: usize = 1 << 14;
