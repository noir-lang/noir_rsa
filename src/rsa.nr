use dep::bignum::RuntimeBigNum;

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
        if i < 52 + ps_len {
            // PS padding which depends on RSA modulus / sig length. 1024 bits = 128 bytes = 128 - 54 = 74 bytes of 0xFF padding
            assert(padded_sha256_hash[i] == 255);
        } else if i == 52 + ps_len {
            // Pad 0x01
            assert(padded_sha256_hash[i] == 1);
        } else if i == 53 + ps_len {
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
 * @note The `exponent` can be either 65537 or 3 (i.e. the most common values in use for RSA)
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

mod tests {

    use crate::types::RBN2048;
    use super::verify_sha256_pkcs1v15;
    use bignum::params::BigNumParams;
    use bignum::RuntimeBigNum;

    #[test]
    fn test_verify_sha256_pkcs1v15_1024() {
        // Output of `cargo run -- --msg "hello world! test#123" --bits 1024` in the `signature_gen` directory
        let sha256_hash: [u8; 32] = dep::std::hash::sha256("hello world! test#123".as_bytes());
        assert(
            sha256_hash
                == [
                    220, 155, 229, 143, 122, 133, 55, 215, 75, 44, 132, 111, 57, 33, 248, 84, 213,
                    170, 193, 96, 253, 57, 124, 13, 251, 42, 92, 147, 105, 172, 233, 85,
                ],
        );

        let params: BigNumParams<9, 1024> = BigNumParams::new(
            false,
            [
                0xab238ad9cb37979a43aefbf10be8fb,
                0x31347febe45fe8c2dac1dd30900704,
                0xa5a9a6b9cd0cc2b9d13bbd4e068263,
                0x5eac6390f7873fe97ff9bb14a173ea,
                0xbc41f700c91fd733a2c63177bbdbd4,
                0x41442bd58769a3595b659a2ec9c6be,
                0x4ddc91395f330382aa2e2d3fbe147,
                0x3d008ff255a0bc71c7887f5728ba1,
                0xb640c3a8f511c64e,
            ],
            [
                0x5d53d2634c6a0918266043968ce263,
                0x5dd4be3dce0323a492ee9340aec4db,
                0xf82d0e2e5c8319f01a460c72c01854,
                0x236e6fc6e62e8a1d522acda5fb3892,
                0xdaf755619d66e580901aa224d03174,
                0x8366291616480e7e1f202dbcedda87,
                0x40ba1202537d1e94561ccc05265586,
                0x69b993d857ba89ea5de9822aeb4b93,
                0x167968c0000761a273,
            ],
        );

        let signature: RuntimeBigNum<9, 1024> = RuntimeBigNum {
            params,
            limbs: [
                0xc3850e84ea02da3f028ff422f4d6a9,
                0x9761f0bd9021f76d45c60df0670a19,
                0xc1ede421a43607ab623ed4d5a17fc8,
                0x86197b4315206f4d53200b42555831,
                0xe95783b69db28c26a83706f39d04cd,
                0x18b178dc1a9ec76fb22b57e4dfa703,
                0xdd0e19cd5a09ab48e7af4d0e3470e3,
                0x10004dfab1cf91304e80e6baa4dfc7,
                0x241c3fd77b90adef,
            ],
        };

        assert(verify_sha256_pkcs1v15(sha256_hash, signature, 65537));
    }

    #[test]
    fn test_verify_sha256_pkcs1v15_2048() {
        // Output of `cargo run -- --msg "Hello World! This is Noir-RSA"` in the `signature_gen` directory
        let sha256_hash: [u8; 32] =
            dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
        assert(
            sha256_hash
                == [
                    91, 207, 46, 60, 22, 153, 217, 144, 2, 127, 224, 143, 181, 45, 32, 120, 122,
                    131, 166, 79, 166, 183, 43, 158, 116, 105, 73, 207, 196, 77, 33, 5,
                ],
        );

        let params: BigNumParams<18, 2048> = BigNumParams::new(
            false,
            [
                0x8d5e7d9daedd6cfd1c9bdf0227e05b,
                0xbfb937fc4d3cf02cc0af780f3cab44,
                0xd20637ef7adcf5d238ee87bccc9bca,
                0xb9db4f2663108e2f8b673f7612ae8b,
                0x85f894ef669b36bfd3d86b0a28873,
                0xdcc70e1884e38b8229cce3b884121d,
                0x35488d1138e0b03e1676f7f5d8a5b3,
                0xe1a97820e7dcbb4eab35c9b71bb273,
                0x97d19eb3c63249ddbfcff915863f54,
                0x3a78c7af6da0f6af0d67b1ca4b6065,
                0xd7a3c433c020f624821e5e678c7d69,
                0x52d5b53240feae82ffea3d2a3d9b09,
                0xb8aad5e19e2163f68997c6fdd71906,
                0x5db432d06e8b0bf59511100c7894e2,
                0xadc0bbc4c54da10d1cc88438ea3127,
                0xece1cf6a1501109cd2734d5893c8d9,
                0x7196b90acdf06c31b1288064fd0c27,
                0xc8,
            ],
            [
                0x1b1deccf4dbde852c34a5d6908a0f,
                0xbc9e5bdab22f023fbcca58692bccf5,
                0x1f65439685623e45396ff55751c3bf,
                0x2b6ad2c5f8e3aac15d0ccbab816bfa,
                0x5ca2e8e3048243c16c708a8030ab0d,
                0x30079bfeb1fa51e5501581173ca19c,
                0xff8d5f6bea485fdcc2716327f69ab4,
                0x36b599d81589416b5b5f037986b999,
                0x75612e34a4ff29f0a19a7823512f58,
                0x288b6897929b54c3b26a5faa07c00f,
                0x4b5675fa13ab7444f1f047d3eb1bbe,
                0x6ba0ac610ef9f267ab30fe25bb1c84,
                0xa386b48ee03168d5cea3ecb9dc901f,
                0xacf1a01f7dba44e050c976142fb1f6,
                0x97a63b5cb7efc60d3502946aec63cf,
                0x12cc1d5cab10a1e9e2398d29b9e3ef,
                0x4635cf25c66e76bba8034df46204fb,
                0x146f,
            ],
        );

        let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum {
            params,
            limbs: [
                0xad29e07d16a278de49a371b9760a27,
                0x86311920cc0e17a3c20cdff4c56dbb,
                0x863556c6c5247dd83668dd825716ae,
                0xc247c960945f4485b46c33b87425ca,
                0x7326463c5c4cd5b08e21b938d9ed9a,
                0x4f89fe0c82da08a0259eddb34d0da1,
                0x43a74e76d4e1bd2666f1591889af0d,
                0x240f7b80f0ff29f4253ee3019f832d,
                0xc6edd131fbaaf725fd423dac52b362,
                0x85f9732679242163e8afff44f6104d,
                0xd3c3bbcb1757013fd6fb80f31dd9a6,
                0x9008633f15df440e6df6d21ee585a2,
                0x324df3425ed256e283be5b6b761741,
                0xc60c1302929bd0e07caa4aeff4e8fd,
                0x600d804ff13ba8d0e1bc9508714212,
                0x50f7e75e5751d7edd61167027926be,
                0x0db41d39442023e1420a8a84fe81d9,
                0xab,
            ],
        };
        assert(verify_sha256_pkcs1v15(sha256_hash, signature, 65537));
    }

    #[test]
    fn test_verify_sha256_pkcs1v15_2048_exponent_3() {
        // Output of `cargo run -- --msg "hello world" -e 3` in the `signature_gen` directory
        let sha256_hash: [u8; 32] = dep::std::hash::sha256("hello world".as_bytes());
        assert(
            sha256_hash
                == [
                    185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218, 125, 171, 250, 196,
                    132, 239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233,
                ],
        );

        let params: BigNumParams<18, 2048> = BigNumParams::new(
            false,
            [
                0xe40ee47801326543c8e84b85d567c1,
                0x5b54ea87f0ce29de1995697b0696fd,
                0x457078f8fdce68b437cac0970b2452,
                0x473ec776fee3731b6ab06e35875ddc,
                0x62dedd594e5f12c80c3ccb5791a6cd,
                0xecb934b9d8272c5e3a418145345499,
                0xd1af643b3d785470ed0c6cd633f706,
                0xb58a57b9e96eccbdfc7c17f0333d4,
                0x2ebd34b5039fc596504927c282c60d,
                0x3a44928a74f25fc1043bb37ce4dfa8,
                0x91448459f9617fac33a2816162ac9e,
                0x70cb910d9f3e1a78864640ec6c8240,
                0x9aed33f6b31f1c9de67248a98c180,
                0x7f1416e032c79488c94b311e87bd9c,
                0x7191b4ebb1b3fffa949fa48ed01e5,
                0x350a75cbaeca6bfdd71ca83cdbcae9,
                0xfb1d274fa207457c6814d42c09f9cf,
                0xd4,
            ],
            [
                0x803bf4d38110a7d37fdd05f590dee9,
                0xa68d317c933f37cab5ab4e7c00a3b9,
                0x476a05a536bf5f2aa1b8850146cba7,
                0xca297ea8b5528d91d4836ff27c30ab,
                0x75cf2eaab76eefa12bbd570f1aea9f,
                0x8f6a8ab877d9c5bcd98c37bdc5c2d3,
                0xd497db1f6ebe83decacaa647fabea6,
                0x686b27ca330e25e7a7cf197f6433ef,
                0xfde04d2225c8308b07580af0058a0f,
                0xa29fb69777c0e916976243b2b09855,
                0xf983592285852e7e1c2cb3ae968323,
                0x673608017f9f5acf67a01b73728d70,
                0xeeff82521c0bc432a05f4b7444fac0,
                0x85a89c4d229f60aaa3aa7ac7dac1e2,
                0xcfecff93bc9fbfe0d6dff6091f2db8,
                0xf20f047dcb224b4447bd098c07f8c2,
                0x554bb53cadeb3eaab911a189f90227,
                0x133b,
            ],
        );

        let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum {
            params,
            limbs: [
                0xa250eff812c63eaaeaa3f04641c05f,
                0xecc09613cb8b289c1f37c8f92e6a05,
                0x2c0a0510058360c07af65d46f594fd,
                0x943d67513363d3de430c94a1dafe7c,
                0x511ec8e9b10bc6c6ff0d6c232ccf92,
                0x50ffd07b3c093b3f5fc027de847731,
                0xc268e1489449943fdafdf89ff168c3,
                0x0b8b7f9f49b492f78fda58d252f23a,
                0x491c6c4ef836a6a8730b7bf81e865e,
                0x8746c75fb079d014e419543f56d7f0,
                0x65804c417d6168a8bc0025d255cebf,
                0xf695e91b77890b8e3fd775fa56e627,
                0x5e90001c0218550f4083ae28025a2f,
                0x526bd4eff34f25f62a698f0470e0a6,
                0x7f224306a7d9daf536b1559434c6c6,
                0x88809f16fe1fcea3c87511d9319735,
                0x7694685fee0bfab4a9196b92ec6f2e,
                0xa7,
            ],
        };

        assert(verify_sha256_pkcs1v15(sha256_hash, signature, 3));
    }

    #[test]
    fn smoke_test() {
        // Output of `cargo run -- --msg "hello world"` in the `signature_gen` directory
        // Create runtime params:
        let modulus_limbs = [
            0x65af46d235241cf0e8fbe8cff4abb7,
            0xeead39ba3f377ddd5ccb2ef2085190,
            0xe483f94c0a98e8b618d92fb926f596,
            0x1fa8c1b2c62cca6db090cd74a29db2,
            0xc38e22042fcb74585a7e535301f50f,
            0xcbc4378e5212752743ae78a75a44a9,
            0xf5acc41788d9a346a0f75630a8b2b6,
            0xf7a741bb3ecf1aadd5a327f362abd8,
            0x4d5f24e815db43a1b2cc2ba40f8715,
            0xe501f1a01305cb198475a4bff0da2e,
            0xd541b78cfbc2b314083c340840c82c,
            0xa0ab069c26b2a0458f4c642bf72526,
            0x2ccb676d8f22517116fee0d2340533,
            0x7cf2a7cf772025c0a83747bbc18228,
            0xf9475f17988a56f17b3bdf88dc72dc,
            0x4ff228bee24415fae7a7c05771e830,
            0x55acd96b485515c38906106cf0d189,
            0xb9,
        ];
        let redc_limbs = [
            0x172c8f156f020ad88d30fa3ba47f03,
            0x1740a43a67cb9a7be1ac1422d77246,
            0x2d967be1edf369834317e04856e591,
            0x65d9fa0de5fdab598c04d9a515156a,
            0xc6791a661ea7621db7e6c4ec48f466,
            0xa4a1a7c06d3e8a0bcbc540c6af6788,
            0xdcaffeb149f5bf646caa00d7355715,
            0xb75471630a9d0fefb5cb61e66991a1,
            0x97c041a0fc30fdff3d5ed16997da02,
            0xbfbe7d217694b269e1ed37819c2f17,
            0x1b44ffc3180531e2ab8bdf7848a3a9,
            0x9f004af11132cb68bb55998ed7616a,
            0x1b15dbbb96ce80f479724bbd768a0c,
            0x59ba1419093ae6ed2592ffb3065867,
            0xa35b69affa3bb3f4713f315e50b584,
            0xa873210f83a6de0d8cbb816af3e37,
            0xbe4fe7cf98da87ec87638030797e92,
            0x1619,
        ];

        let signature_limbs = [
            0x2f397c4611d4a4271453e1e50e1578,
            0xe506a7f47c721a4943783e8ad459e6,
            0x6cc4ae1d91cb381cba9673470999fb,
            0x1e127364d07f94e58227f50fbf5687,
            0xf64a2579c7189f882d68832d16faa4,
            0x3b014b74c6c6f76f2f8af170fa0fe4,
            0x7df41e68c86815a6fdc33968c66b67,
            0x6a57ac06282527242fddb6ed08dbdc,
            0xac40d37b819c4b6193f90a634e4fc7,
            0x96606ed166a7f032d858cd40ac73a5,
            0x8eb7d4351159a46733f92610d5c597,
            0xc8e8e9faa9738e82dbe774a3f5cf07,
            0x89ca84fd54ee3d5cca87c9f178375e,
            0xdb7a1465fc76507ea498a351af70dd,
            0x6ac6fe14f51c711f983125c776f712,
            0x3254c17fef51bf4194a8a1674634e3,
            0xee38c83c77c6e1ff7b70a5d9d1dd0f,
            0x26,
        ];

        let hash: [u8; 32] = [
            0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d,
            0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac,
            0xe2, 0xef, 0xcd, 0xe9,
        ];

        let has_multiplicative_inverse = false;
        let params: BigNumParams<18, 2048> =
            BigNumParams::new(has_multiplicative_inverse, modulus_limbs, redc_limbs);

        let signature: RBN2048 = RBN2048::from_array(params, signature_limbs);

        assert(verify_sha256_pkcs1v15(hash, signature, 65537));
    }
}
