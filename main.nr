use dep::bignum::runtime_bignum::BigNum;
use dep::bignum::runtime_bignum::BigNumInstance;
use dep::bignum::runtime_bignum::BigNumTrait;
use dep::bignum::runtime_bignum::BigNumParamsTrait;

/**
 * @brief Verify an RSA signature generated via the pkcs1v15 signature scheme.
 * @details The fourth function parameter is required to define the value of `NBytes`
 *          when converting a BigNum into a byte array, the number of bytes is required and currently cannot be inferred.
 *          Once numeric generics can be derived by applying operations to other numeric generics the need for this will go away.
 *
 * @note We assume the public key exponent `e` is 65537 
 * Rough cost: 26,888 gates per verification. A circuit that verifies 1 signature (and does nothing else) will cost ~32k due to initialization costs of lookup tables
 **/
pub fn verify_sha256_pkcs1v15<let N: u64, Params, let NBytes: u64>(
    BNInstance: BigNumInstance<N, Params>,
    msg_hash: [u8; 32],
    sig: BigNum<N>,
    _: [u8; NBytes]
) -> bool where Params: BigNumParamsTrait<N> {
    // e = 65537 = 1 0000 0000 0000 0001
    let mut exponentiated = BNInstance.mul(sig, sig);
    exponentiated = BNInstance.mul(exponentiated, exponentiated);
    exponentiated = BNInstance.mul(exponentiated, exponentiated);
    exponentiated = BNInstance.mul(exponentiated, exponentiated);
    exponentiated = BNInstance.mul(exponentiated, exponentiated);
    exponentiated = BNInstance.mul(exponentiated, exponentiated);
    exponentiated = BNInstance.mul(exponentiated, exponentiated);
    exponentiated = BNInstance.mul(exponentiated, exponentiated);
    exponentiated = BNInstance.mul(exponentiated, exponentiated);
    exponentiated = BNInstance.mul(exponentiated, exponentiated);
    exponentiated = BNInstance.mul(exponentiated, exponentiated);
    exponentiated = BNInstance.mul(exponentiated, exponentiated);
    exponentiated = BNInstance.mul(exponentiated, exponentiated);
    exponentiated = BNInstance.mul(exponentiated, exponentiated);
    exponentiated = BNInstance.mul(exponentiated, exponentiated);
    exponentiated = BNInstance.mul(exponentiated, exponentiated);
    exponentiated = BNInstance.mul(exponentiated, sig);

    let mut padded_sha256_hash_bytes: [u8; NBytes] = BNInstance.to_le_bytes(exponentiated);
    compare_signature_sha256(padded_sha256_hash_bytes, msg_hash)
}

/**
 * @brief Compare a recovered byte hash from an RSA signature to the original message hash
 * @details Taken from https://github.com/richardliang/noir-rsa
 **/
fn compare_signature_sha256<let N: u64>(padded_sha256_hash: [u8; N], msg_hash: [u8; 32]) -> bool {
    // Get length of sig (e.g. 1048 = 128 bytes, 2048 = 256 bytes)
    // NOTE: Assume MAX_BYTES < 2^32 bit number. MAX_BYTES of 259 > 2^8 bits so need to cast it to u32

    for i in 0..32 {
        // Padded hash is reversed
        assert(padded_sha256_hash[31 - i] == msg_hash[i]);
    }

    let hash_prefix: [u8; 19] = [32, 4, 0, 5, 1, 2, 4, 3, 101, 1, 72, 134, 96, 9, 6, 13, 48, 49, 48];

    for i in 32..51 {
        assert(hash_prefix[i - 32] == padded_sha256_hash[i]);
    }

    assert(padded_sha256_hash[51] == 0);

    // Sub 32 bytes for hash, 19 bytes for prefix, 1 byte for 0, 1 byte for 1, 1 byte for 0
    let ps_len = N - 54;
    for i in 52..N {
        if i as u32 < 52 + ps_len as u32 {
            // PS padding which depends on RSA modulus / sig length. 1024 bits = 128 bytes = 128 - 54 = 74 bytes of 0xFF padding
            assert(padded_sha256_hash[i] == 255);
        } else if i as u32 == 52 + ps_len as u32 {
            // Pad 0x01
            assert(padded_sha256_hash[i] == 1);
        } else if i as u32 == 53 + ps_len as u32 {
            // 0x00
            assert(padded_sha256_hash[i] == 0);
        } else {
            // Padded with 0 until MAX_BYTES
            assert(padded_sha256_hash[i] == 0);
        }
    }

    true
}

struct Params2048 {
}

impl BigNumParamsTrait<18> for Params2048 {
    fn k() -> u64 { 2048 }
    fn modulus_bits() -> u64 { 2048 }
}
struct Params1024 {
}

impl BigNumParamsTrait<9> for Params1024 {
    fn k() -> u64 { 1024 }
    fn modulus_bits() -> u64 { 1024 }
}
#[test]
fn test_verify_sha256_pkcs1v15_1024() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());

    let BNInstance: BigNumInstance<9, Params1024> = BigNumInstance::new(
        [
        0xe908724e0d28a1565511879e00f063, 0x58dea28d5112982c8ab8597d3e611f, 0xb115f9878acc910a47b41ac8d5f763, 0xc71b0a719c2283f710f86024737cee, 0x9ee9eb73e95b84f033af5217337427, 0x8fcab34c99cc2661dd57de15ae2110, 0xa38db8a829eec5550342f6f66334dc, 0xd7c4b32fd351a47d860fda1897330e, 0x98c92a33a0f33fd7
    ],
        [
        0x55582e8ba08822783fbd7d07390be2, 0x1d7d83f9dce3983c66f440dcc2f33e, 0x6072d13c84a4cb304f58fbabe782e7, 0x0cee5e0dd62bc54d15a91a4ea3bc50, 0xc485e6f946c45cf660fba4f49325cb, 0x1f0e45df0464b065c94e84ed1dad8c, 0xe4c7b3976310ea239059d834b545f3, 0xd418145200fa77235f5f8d852b121f, 0x01acf0bd16cad9bd8f
    ]
    );
    let signature = BNInstance.from_array(
        [
        0x393f230b55a12fb7bb39c7edd2cf48, 0x78f7d0a217d340407cae4f39b8f001, 0x603909ff76a519f3c8e96d695d462e, 0x0640ab230b459bf4b20b4823a5b850, 0x02ba190de61a85074b18e228231984, 0xe1424c0779825707aa433ecb86c388, 0xbed8087d947a9c6c56625ad20c91aa, 0x7da4a0c2eee3a3c0d61e892ab4ada9, 0x6ef98a936c8bf8e5
    ]
    );
    let empty_array: [u8; 128] = [0; 128];
    assert(verify_sha256_pkcs1v15(BNInstance, sha256_hash, signature, empty_array));
}

#[test]
fn test_verify_sha256_pkcs1v15_2048() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("hello world".as_bytes());

    let BNInstance: BigNumInstance<18, Params2048> = BigNumInstance::new(
        [
        0x183b4cadacea64716b6535b25a86ad, 0x129a32e9fbd374949e81b080546c2b, 0x9276332765f54b9b4d6fe23f4983a4, 0x91df05fde1a414c9fbf38808a01032, 0x97ca171c382e082ddd6c81be090902, 0x97161dde47ed979939451704b72648, 0x3b66f0c93f8ddbc62bb99f6b8fad2d, 0xc3a046fcad814d8938da372cd84d2a, 0xfe903cfe3ee4de6de3916023bb87f2, 0x8be5fd99c8b46dce9aab27ce4b3883, 0x0d99dfe50dd2288123804872da8543, 0xbb6d8afef8b2c7e3b86ad96973d4e5, 0x17e08fa3c5391279b844581f67825c, 0x09511f4a436abe495bfbfcc254d9c5, 0xf80d02572d620eab5ad7ecfbe2c20c, 0x2a5307402a05f59ba232ad0c8366d0, 0x7b9169630b317c38d549a86f85fcfc, 0xf2
    ],
        [
        0xf4effa025abe90db41dc5bb5934a5f, 0x2596b25aa09f6a0e290accebbef006, 0x330e9567ec5eca92b7a8ce72ad3d83, 0xccf98d178ec4017e4947cadc02da7c, 0xaed6044ffeeb12de4d1e67aedfda78, 0xb5ae8a5a4637b632800e2f41dfbf0a, 0x8304360d359cf2f0d5d97c039f9b04, 0x53cde0d0633c0e66e1da9a118f6a96, 0xf9a83822351097bb1ed123d10290f5, 0xeb489c7f7227c09ca0117264dcf04f, 0x6a1b3618478a235f438adf84533177, 0x71c03085e38a87f5ec8e51c27dde98, 0xcf3e89d9cf253ef61d65d4431334d9, 0xa5a1a59e98fb7f49c746149324201d, 0x38f46c635f884f24c254eaa37981d6, 0x1c42be15dd95e1ac5bf01972b24ff9, 0x4555dd506d1f89e61279293c03db90, 0x010e
    ]
    );
    let signature = BNInstance.from_array(
        [
        0x5f0937ed1aacbdb83991e21c89ca8a, 0x5a1fa4ef2faf4042401c9121c73874, 0x7379fbb7713fbf807d250f7401afb8, 0x9cc5ce8813f3a83a72b681a4d434b2, 0x11cb49ac2ee1f9bed8a008b8327e1e, 0xf3362524f1224e48827b34a62f6ace, 0x3498a2944e32a3798fe9da684b32ae, 0xc346c33528bcdf7a06805126a29402, 0x6ac93f2fa68f270ec73674eae24380, 0x222c72de080496533ceeb8af827910, 0xc22889b311a53203278b942ca67100, 0x93d75567f7fe9ee7ca9871a0cb09f9, 0x049dabd976a9574847b1614f6b739c, 0xdc66b621dbae623df9b657b52fa1b0, 0xf37e82cc1eced382e11fc32e673f67, 0xe50545eb9027f1144a0ba7bbb0c886, 0xb6193409539c515d3c55a45c5734b1, 0x4b
    ]
    );
    let empty_array: [u8; 256] = [0; 256];
    assert(verify_sha256_pkcs1v15(BNInstance, sha256_hash, signature, empty_array));
}
