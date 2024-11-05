use dep::bignum::{ RuntimeBigNum, params::BigNumParams };

/**
 * @brief Compare a recovered byte hash from an RSA signature to the original message hash
 * @details Taken from https://github.com/richardliang/noir-rsa
 **/
fn compare_signature_sha256<let N: u32>(padded_sha256_hash: [u8; N], msg_hash: [u8; 32]) -> bool {
    // Get length of sig (e.g. 1048 = 128 bytes, 2048 = 256 bytes)
    // NOTE: Assume MAX_BYTES < 2^32 bit number. MAX_BYTES of 259 > 2^8 bits so need to cast it to u32
    for i in 0..32 {
        // Padded hash is reversed
        assert(padded_sha256_hash[31 - i] == msg_hash[i]);
    }

    let hash_prefix: [u8; 19] =
        [32, 4, 0, 5, 1, 2, 4, 3, 101, 1, 72, 134, 96, 9, 6, 13, 48, 49, 48];

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

/**
 * @brief Verify an RSA signature generated via the pkcs1v15 signature scheme.
 * @details The fourth function parameter is required to define the value of `NBytes`
 *          when converting a BigNum into a byte array, the number of bytes is required and currently cannot be inferred.
 *          Once numeric generics can be derived by applying operations to other numeric generics the need for this will go away.
 *
 * @note The exponent `e` can be either 65537 or 3 (i.e. the most common values in use for RSA)
 * Rough cost: 2,048 bit RSA: 26,888 gates per verification
 *             1,024 bit RSA: 11,983 gates per verification
 * A circuit that verifies 1 signature (and does nothing else) will cost ~32k due to initialization costs of lookup tables
 **/
pub fn verify_sha256_pkcs1v15<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 32],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
) -> bool {
    assert((exponent == 3) | (exponent == 65537), "Exponent must be 65537 or 3");
    let mut exponentiated = sig * sig; // sig^2
    if exponent == 65537 {
        // e = 65537 = 1 0000 0000 0000 0001
        exponentiated = exponentiated * exponentiated; // sig^4
        exponentiated = exponentiated * exponentiated; // sig^8
        exponentiated = exponentiated * exponentiated; // sig^16
        exponentiated = exponentiated * exponentiated; // sig^32
        exponentiated = exponentiated * exponentiated; // sig^64
        exponentiated = exponentiated * exponentiated; // sig^128
        exponentiated = exponentiated * exponentiated; // sig^256
        exponentiated = exponentiated * exponentiated; // sig^512
        exponentiated = exponentiated * exponentiated; // sig^1024
        exponentiated = exponentiated * exponentiated; // sig^2048
        exponentiated = exponentiated * exponentiated; // sig^4096
        exponentiated = exponentiated * exponentiated; // sig^8192
        exponentiated = exponentiated * exponentiated; // sig^16384
        exponentiated = exponentiated * exponentiated; // sig^32768
        exponentiated = exponentiated * exponentiated; // sig^65536
    }
    // otherwise, e = 3 = 11
    exponentiated = exponentiated * sig; // either sig^2 * sig = sig^3 or sig^65536 * sig = sig^65537
    let mut padded_sha256_hash_bytes: [u8; (ModBits + 7) / 8] = exponentiated.to_le_bytes();
    compare_signature_sha256(padded_sha256_hash_bytes, msg_hash)
}

#[test]
fn test_verify_sha256_pkcs1v15_1024() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("hello world! test#123".as_bytes());
    let params: BigNumParams<9, 1024> = BigNumParams::new(
        false,
        [
            0x483fd4238ca29c3a06f8161ee16faf,
            0xf366b16a37c2db80d2977eab0ebbdc,
            0x92ba4d77ff2425727ad38eea1cc2fe,
            0x3fc50862a0e6afbcae13d5f85c220a,
            0xe634dcea239a6a896597d4f75af455,
            0x32e1448d1489bca56d983562715680,
            0x1a81ef873140c0cfc191a44bfe6e88,
            0x96066f4df0e14de07329df952aba45,
            0xc2e161b4944381bb,
        ],
        [
            0x9c0b9f33d5b6960db5d70095a87724,
            0xfb5245423548a808b8aee833d783b8,
            0x790c0d7558b38dc24122455bf48f92,
            0x39227725aaea9c83a99acf4b847682,
            0xbd468a00b83cb026568150030eff3a,
            0xcbb4f5cef905ca04f92f266e0493e8,
            0xe19ad572a7bc2bb8168c81b0867c04,
            0xbe2075bf10bc8a16725befb36d7f49,
            0x15049cee2f37078121,
        ],
    );

    let signature: RuntimeBigNum<9, 1024> = RuntimeBigNum {
        params,
        limbs: [
            0xe6fe1016893fed66550af77d706698,
            0x9dd3b648afbbdb748ab97b4d609f0d,
            0x83098d3b45c588c69c0e36ff9b210a,
            0x5a793d529a382b34a491f68e4d959d,
            0xa8c43b964794a4c11da2e57ef226df,
            0x68654e3681728df9daff17a3b0bc66,
            0x8aa4c9accfffae4fd5cd453c8c5335,
            0x8b243f7074dacdcd869b94f3eef7fe,
            0x3a8c12564704f5ad,
        ],
    };

    assert(verify_sha256_pkcs1v15(sha256_hash, signature, 65537));
}

#[test]
fn test_verify_sha256_pkcs1v15_2048() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());

    let params: BigNumParams<18, 2048> = BigNumParams::new(
        false,
        [
            0x6d235ca5aab99a4c05ff2a03574427,
            0xec267a6bbe7ffe4b6e8da9cf24897c,
            0xcdaa2e64a6116d5bdf82460a108af3,
            0xf6c184c2d2f4cc7ed3b7eaf28e257e,
            0x7511d2771cdf315a07ba2e0058cb8b,
            0x641d6eb5119b1b8e643eda5ade2dc3,
            0xffc28bdb9f8f0ddc596675feae14fc,
            0xcbc67f77f37393c3419a2340f859ad,
            0x5cd500e0341275ce468e62db47107d,
            0x3049eba2be3f9408f2c9ed2ae27d90,
            0xc2f431dd169858ac5269d2512f4189,
            0x36ace99a589959ea0425444cfb440d,
            0x825fbf23e4e49a3b8f1fa714681f77,
            0x8125cd82c2776832cf839ee1a9332c,
            0xacbefb6a860c88ecbef30d52472137,
            0x24166d0e0b434e207d4e8ecfd66cc9,
            0x180955377f255f7bc29506fb45a8cb,
            0xf7,
        ],
        [
            0xd08ee8d0e8ac5ce306aa570cfe1c05,
            0xed045b877e042b6c144e6aa9cce044,
            0x845096769616e1351bd198cb0938ae,
            0xe4512a74991f500c166befa3c2f524,
            0x81a05d9646ce1212d658399b5b566d,
            0x1211121678c29a52c6d66eeca965b9,
            0x93dfb350c2b86c8a2a2464cd84e03c,
            0x9747aff06e0b9527bc5ad313c8173e,
            0x1ca0a8eb7986c264406bf2a8752034,
            0xe6abe17cf0f33ec2f655a85c027269,
            0xd157b2f2739eec33b38908711b45df,
            0xecc0246c32b828f0f603c9feea2daf,
            0x76cb733ba6093e7fc2cfc29e07d7c4,
            0x7c6f3519480fc9490894acf0c7087f,
            0xb92c0644fa19196c5be9d142611269,
            0x4db094df57cae1fa0bf4e8faec435b,
            0xa2426a309776b8e5d0be5257586c59,
            0x1093,
        ],
    );

    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum {
        params,
        limbs: [
            0xad8c7c5ec9162b4769e0cfe5ebf840,
            0x0d57cdde315319930d4e9eda1a7c1e,
            0xafc455e0e01ef5a57160f0df8a786c,
            0xbf1c1e64e91e316ec3ec02e68c23d6,
            0x8df9a02bb6a52c932ad0d2832e33a6,
            0xa3eacb4ebcb99a4a48be662698a9b8,
            0x4fef3847f3e94050802ab50f29a01d,
            0xa493fa7d68bd2b0d9e1a1d768053c0,
            0x707d984f377f71262954eabd10e268,
            0xfec30d40733948f36919b3ffa07366,
            0xc9bf002b29ce6a860ba284a4426e34,
            0xbc839ec24aad3c05a9aaccefca9e63,
            0x07fe1918a7d98dd52e49e9d775461c,
            0x098fdfe7d87d48732502814ee90808,
            0x64de99868676d8b02d7b43b0474636,
            0x27910e77bdc54ba42a4322a5ce8200,
            0xc3b7b95e779c9a11895c88fe24bced,
            0x96,
        ],
    };
    assert(verify_sha256_pkcs1v15(sha256_hash, signature, 65537));
}

#[test]
fn test_verify_sha256_pkcs1v15_2048_exponent_3() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("hello world".as_bytes());

    let params: BigNumParams<18, 2048> = BigNumParams::new(
        false,
        [
            0xea12ae77c634ac18e8914b0f112919,
            0x7a385b52ed45602b3166e3006cab17,
            0xce91edcb26009ae4ca5ec9032ace54,
            0xec45aa323af9389e814dfa59e4e106,
            0x50332220bbc7184b2b54c87acb79fb,
            0x1fead59aea9260a545bb9b1e098753,
            0xb362f1fc50b04e6581b34f97a769b5,
            0x409c9d7b3a3ecb214e9dc5524e21a3,
            0x88974631f1a1eed0c9d1fa6cc3c622,
            0xadacc23ed4a6e2c0e968ad1da6e5b5,
            0x480a5bbcc4e18d45937957d44adff2,
            0x4d54fd4d3ab7ac249866b6aeaaf37f,
            0x7eb6e94460e5dab5f15c55faf1bf5b,
            0xc0bca2fb49828eb02a02cb3d95f48a,
            0xeeb45b7149ee2bffe342120c8ef177,
            0x9108e90248dfab616da128279b0391,
            0xd446716c4e0be2123afd277a2cf8a7,
            0xe5,
        ],
        [
            0x8653d918663eb92721c6efedf149e4,
            0x3dbb26bf3a033499240fd8ef578107,
            0x69a15f7a032e80ef1496b60b3b95ae,
            0xc9aff3026bae96644fc904d80d3c0a,
            0x4cb0ae9774e8045235dd864f81314f,
            0x65c558cd398b18126e7f3788d196c6,
            0x5d7cdb26a9343a94726693b0b5a6c6,
            0x4b3cd2b0ef752aa26ba6a7fba6f795,
            0x6632fa88182883e987e0db1bcaaaea,
            0x38098156f929b4fda6d3026667b3a0,
            0x5d5bee367212e64a7d1bd3307082a4,
            0xf2622828a7f6e5d906388ec2aa850c,
            0xacfdba93e953a71ce0a75f3f88c96f,
            0xf8a2b79dfe7264e30b058d44747277,
            0x8cf6a50c2e0723546a03d684e3fda,
            0xc95e8eb25fe50e2ad34e494492abf,
            0x6a078f758586eb4b1e60059a1826b1,
            0x11d2,
        ],
    );

    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum {
        params,
        limbs: [
            0xcd01362e23da8aa633cb5a0fb9808d,
            0xd3be03e14b0c1eea086ef6aca3d51a,
            0xc7bb806d6723bb12c95ce0e3bc5588,
            0x05f9843f35688f97a88273cc30b661,
            0x25679e918a53da7baa6840d660305c,
            0xb89d2c648f85e1372ae090aa89e19c,
            0xb90686c46e3c9be1e0f4006047bf5b,
            0xd2d27921c3c5b8613d4fec51eb7045,
            0xf5e86133acb02bd34dbac6805c5958,
            0x84fe10899677d060461b0c3619dcfc,
            0x8c9a26f5a68450509aca9d347f0d51,
            0xccb9f4406f2c75407b871d39a06cb1,
            0xcc95879813f3f90c64f7b5c21b3b0e,
            0xc519654312dce978c9f368724d8c8f,
            0x5ec258287e34b65bd13cb4c05381ae,
            0xd8b5e5f82508cde542538a1973f37f,
            0xe035ef2e15b18975521e6ff25072c0,
            0x34,
        ],
    };

    assert(verify_sha256_pkcs1v15(sha256_hash, signature, 3));
}
