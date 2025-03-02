// Binius
pub const LOG_INVERSE_RATE: usize = 2;
pub const SECURITY_BITS: usize = 100;

// XMSS - WOTS
pub const XMSS_HEIGHT: usize = 14; // Number of signatures per secret key = 2^XMSS_HEIGHT
pub const W: usize = 2; // number of bits of each WOTS chunck, must be a power of 2
pub const WOTS_FIXED_SUM: usize = (2usize.pow(W as u32) - 1) * 256 / (2 * W); // we avoid checksum chains using the technique of https://eprint.iacr.org/2022/778.pdf
