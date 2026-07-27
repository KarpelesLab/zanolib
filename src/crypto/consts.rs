//! Hard-coded curve points and scalars, matching Zano's `crypto-sugar.h`.
//!
//! The points are stored in the reference code as extended coordinates in the
//! radix-2^25.5 field representation; they are converted here to the affine
//! encoding purecrypto consumes.

use super::field::Fe;
use super::{Point, Scalar};
use std::sync::LazyLock;

/// Rebuilds a point from extended coordinates `(X:Y:Z:T)` given as 10-limb
/// radix-2^25.5 field elements. `T` is redundant (`T = XY/Z`) and only checked.
fn point_from_extended(x: [i64; 10], y: [i64; 10], z: [i64; 10]) -> Point {
    let fx = Fe::from_int10(x);
    let fy = Fe::from_int10(y);
    let fz = Fe::from_int10(z);
    let zinv = fz.invert();
    let ax = fx.mul(&zinv);
    let ay = fy.mul(&zinv);
    let mut enc = ay.to_bytes();
    enc[31] |= (ax.to_bytes()[0] & 1) << 7;
    Point::decompress(&enc).expect("hard-coded constant is a valid curve point")
}

/// `-A^2` where `A = 486662`.
pub static FE_MA2: LazyLock<Fe> =
    LazyLock::new(|| Fe::from_int10([-12721188, -3529, 0, 0, 0, 0, 0, 0, 0, 0]));
/// `-A`.
pub static FE_MA: LazyLock<Fe> =
    LazyLock::new(|| Fe::from_int10([-486662, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
/// `sqrt(-2 * A * (A + 2))`.
pub static FE_FFFB1: LazyLock<Fe> = LazyLock::new(|| {
    Fe::from_int10([
        -31702527, -2466483, -26106795, -12203692, -12169197, -321052, 14850977, -10296299,
        -16929438, -407568,
    ])
});
/// `sqrt(2 * A * (A + 2))`.
pub static FE_FFFB2: LazyLock<Fe> = LazyLock::new(|| {
    Fe::from_int10([
        8166131, -6741800, -17040804, 3154616, 21461005, 1466302, -30876704, -6368709, 10503587,
        -13363080,
    ])
});
/// `sqrt(-sqrt(-1) * A * (A + 2))`.
pub static FE_FFFB3: LazyLock<Fe> = LazyLock::new(|| {
    Fe::from_int10([
        -13620103, 14639558, 4532995, 7679154, 16815101, -15883539, -22863840, -14813421, 13716513,
        -6477756,
    ])
});
/// `sqrt(sqrt(-1) * A * (A + 2))`.
pub static FE_FFFB4: LazyLock<Fe> = LazyLock::new(|| {
    Fe::from_int10([
        -21786234, -12173074, 21573800, 4524538, -4645904, 16204591, 8012863, -8444712, 3212926,
        6885324,
    ])
});
/// `sqrt(-1)`.
pub static FE_SQRT_M1: LazyLock<Fe> = LazyLock::new(|| {
    Fe::from_int10([
        -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686,
        11406482,
    ])
});

/// The neutral element.
pub static C_POINT_0: LazyLock<Point> = LazyLock::new(|| {
    point_from_extended(
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    )
});
/// The ed25519 base point `G`.
pub static C_POINT_G: LazyLock<Point> = LazyLock::new(|| {
    point_from_extended(
        [
            25485296, 5318399, 8791791, -8299916, -14349720, 6939349, -3324311, -7717049, 7287234,
            -6577708,
        ],
        [
            -758052, -1832720, 13046421, -4857925, 6576754, 14371947, -13139572, 6845540, -2198883,
            -4003719,
        ],
        [
            -947565, 6097708, -469190, 10704810, -8556274, -15589498, -16424464, -16608899,
            14028613, -5004649,
        ],
    )
});
/// `H`, the second generator; also the native coin asset id.
pub static C_POINT_H: LazyLock<Point> = LazyLock::new(|| {
    point_from_extended(
        [
            20574939, 16670001, -29137604, 14614582, 24883426, 3503293, 2667523, 420631, 2267646,
            -4769165,
        ],
        [
            -11764015, -12206428, -14187565, -2328122, -16242653, -788308, -12595746, -8251557,
            -10110987, 853396,
        ],
        [
            -4982135, 6035602, -21214320, 16156349, 977218, 2807645, 31002271, 5694305, -16054128,
            5644146,
        ],
    )
});
/// `H2`.
pub static C_POINT_H2: LazyLock<Point> = LazyLock::new(|| {
    point_from_extended(
        [
            1318371, 14804112, 12545972, -13482561, -12089798, -16020744, -21221907, -8410994,
            -33080606, 11275578,
        ],
        [
            3807637, 11185450, -23227561, -12892068, 1356866, -1025012, -8022738, -8139671,
            -20315029, -13916324,
        ],
        [
            -6475650, -7025596, 12403179, -5139984, -12068178, 10445584, -14826705, -4927780,
            13964546, 12525942,
        ],
    )
});
/// `U`, the range-proof aggregation generator.
pub static C_POINT_U: LazyLock<Point> = LazyLock::new(|| {
    point_from_extended(
        [
            30807552, 984924, 23426137, -5598760, 7545909, 16325843, 993742, 2594106, -31962071,
            -959867,
        ],
        [
            16454190, -4091093, 1197656, 13586872, -9269020, -14133290, 1869274, 13360979,
            -24627258, -10663086,
        ],
        [
            2212027, 1198856, 20515811, 15870563, -23833732, 9839517, -19416306, 11567295,
            -4212053, 348531,
        ],
    )
});
/// `X`, the asset-blinding generator.
pub static C_POINT_X: LazyLock<Point> = LazyLock::new(|| {
    point_from_extended(
        [
            25635916, -5459446, 5768861, 5666160, -6357364, -12939311, 29490001, -4543704,
            -31266450, -2582476,
        ],
        [
            23705213, 9562626, -716512, 16560168, 7947407, 2039790, -2752711, 4742449, 3356761,
            16338966,
        ],
        [
            17303421, -5790717, -5684800, 12062431, -3307947, 8139265, -26544839, 12058874,
            3452748, 3359034,
        ],
    )
});
/// `H + G`.
pub static C_POINT_H_PLUS_G: LazyLock<Point> = LazyLock::new(|| {
    point_from_extended(
        [
            12291435, 3330843, -3390294, 13894858, -1099584, -6848191, 12040668, -15950068,
            -7494633, 12566672,
        ],
        [
            -5526901, -16645799, -31081168, -1095427, -13082463, 4573480, -11255691, 4344628,
            33477173, 11137213,
        ],
        [
            -3837023, -12436594, -8471924, -814016, 10785607, 9492721, 10992667, 7406385, -5687296,
            -127915,
        ],
    )
});
/// `H - G`.
pub static C_POINT_H_MINUS_G: LazyLock<Point> = LazyLock::new(|| {
    point_from_extended(
        [
            -28347682, 3523701, -3380175, -14453727, 4238027, -6032522, 20235758, 4091609,
            12557126, -8064113,
        ],
        [
            4212476, -13419094, -114185, -7650727, -24238, 16663404, 23676363, -6819610, 18286466,
            8714527,
        ],
        [
            -3837023, -12436594, -8471924, -814016, 10785607, 9492721, 10992667, 7406385, -5687296,
            -127915,
        ],
    )
});

/// The native coin's asset id, as a point (`= H`).
pub static NATIVE_COIN_ASSET_ID_PT: LazyLock<Point> = LazyLock::new(|| *C_POINT_H);

fn sc(b: [u8; 32]) -> Scalar {
    Scalar::from_bytes_canonical(&b).expect("hard-coded scalar constant is canonical")
}

/// `0`.
pub static SC_ZERO: LazyLock<Scalar> = LazyLock::new(|| Scalar::ZERO);
/// `1`.
pub static SC_ONE: LazyLock<Scalar> = LazyLock::new(|| Scalar::ONE);
/// `-1 mod L`.
pub static SC_M1: LazyLock<Scalar> = LazyLock::new(|| Scalar::ONE.negate());
/// `1/8 mod L`, used to force points into the prime-order subgroup on-chain.
pub static SC_1DIV8: LazyLock<Scalar> = LazyLock::new(|| {
    sc([
        0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61, 0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3,
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x06,
    ])
});
/// `2^64 mod L`.
pub static SC_2P64: LazyLock<Scalar> = LazyLock::new(|| {
    sc([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ])
});
/// `L - 1`.
pub static SC_LM1: LazyLock<Scalar> = LazyLock::new(|| {
    sc([
        0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ])
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_point_matches_purecrypto() {
        assert_eq!(*C_POINT_G, Point::generator());
    }

    #[test]
    fn identity_is_identity() {
        assert_eq!(*C_POINT_0, Point::identity());
    }

    #[test]
    fn h_relations_hold() {
        assert_eq!(*C_POINT_H_PLUS_G, C_POINT_H.add(&C_POINT_G));
        assert_eq!(*C_POINT_H_MINUS_G, C_POINT_H.sub(&C_POINT_G));
    }

    #[test]
    fn one_div_eight_is_the_inverse_of_eight() {
        assert_eq!(SC_1DIV8.mul(&super::super::scalar_int(8)), Scalar::ONE);
    }

    #[test]
    fn sc_m1_is_l_minus_one() {
        assert_eq!(*SC_M1, *SC_LM1);
    }
}
