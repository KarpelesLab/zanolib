//! Small integer helpers used to size the proof systems.

/// `ceil(log2(x))`, with `ceil(log2(1)) == 0` by definition.
pub fn ceil_log2(x: usize) -> usize {
    if x <= 1 {
        return 0;
    }
    usize::BITS as usize - (x - 1).leading_zeros() as usize
}

/// Integer exponentiation by squaring.
pub fn int_pow(mut base: usize, mut exp: usize) -> usize {
    let mut result = 1usize;
    loop {
        if exp & 1 == 1 {
            result *= base;
        }
        exp >>= 1;
        if exp == 0 {
            break;
        }
        base *= base;
    }
    result
}

/// The smallest `m` with `ring_size <= n^m`, mirroring
/// `crypto::constexpr_ceil_log_n(v, n)`.
pub fn ceil_log_n(ring_size: usize, n: usize) -> usize {
    if ring_size <= 1 || n <= 1 {
        return 0;
    }
    let mut m = 0;
    let mut p = 1usize;
    while p < ring_size {
        m += 1;
        p *= n;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceil_log2_values() {
        assert_eq!(ceil_log2(0), 0);
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(2), 1);
        assert_eq!(ceil_log2(3), 2);
        assert_eq!(ceil_log2(4), 2);
        assert_eq!(ceil_log2(5), 3);
        assert_eq!(ceil_log2(64), 6);
        assert_eq!(ceil_log2(65), 7);
    }

    #[test]
    fn int_pow_values() {
        assert_eq!(int_pow(4, 0), 1);
        assert_eq!(int_pow(4, 1), 4);
        assert_eq!(int_pow(4, 3), 64);
        assert_eq!(int_pow(2, 10), 1024);
    }

    #[test]
    fn ceil_log_n_values() {
        assert_eq!(ceil_log_n(1, 4), 0);
        assert_eq!(ceil_log_n(4, 4), 1);
        assert_eq!(ceil_log_n(5, 4), 2);
        assert_eq!(ceil_log_n(16, 4), 2);
        assert_eq!(ceil_log_n(17, 4), 3);
    }
}
