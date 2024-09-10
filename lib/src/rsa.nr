use dep::bignum::BigNum;
use dep::bignum::runtime_bignum::BigNumInstance;
use dep::bignum::runtime_bignum::BigNumTrait;
use dep::bignum::runtime_bignum::BigNumInstanceTrait;

use crate::types::{RSA, BN1024, BN2048, BNInst1024, BNInst2048, RSA1024, RSA2048};

global HASH_LEN: u32 = 32;

fn reverse_array<let N: u32>(array: [u8; N]) -> [u8; N] {
    let mut reversed = [0 as u8; N];
    for i in 0..N {
        reversed[i] = array[N - i - 1];
    }
    reversed
}

fn get_array_slice<let N: u32, let M: u32>(array: [u8; N], start: u32, end: u32) -> [u8; M] {
    let mut slice = [0 as u8; M];
    for i in 0..M {
        if i < end - start {
            slice[i] = array[start + i];
        }
    }
    slice
}

fn mgf1_sha256<let SEED_LEN: u32, let MASK_LEN: u32>(seed: [u8; SEED_LEN]) -> [u8; MASK_LEN] {
    // MASK_LEN must be less than 2^32 * HASH_LEN
    dep::std::field::bn254::assert_lt(MASK_LEN as Field, 0xffffffff * HASH_LEN as Field + 1);

    // HASH_LEN bytes are added at each iteration and there is at least 1 iteration
    // so if HASH_LEN is not enough to fill MASK_LEN bytes in one iteration, 
    // another one is required and so on.
    let iterations = (MASK_LEN / HASH_LEN) + 1;

    let mut mask: [u8; MASK_LEN] = [0; MASK_LEN];
    let mut hashed: [u8; HASH_LEN] = [0; HASH_LEN];

    for i in 0..iterations {
        let mut block: [u8; 256] = [0; 256];

        // Copy seed to block
        for j in 0..SEED_LEN {
            block[j] = seed[j];
        }

        // Add counter to block
        let counter_bytes = (i as Field).to_be_bytes(4);
        for j in 0..4 {
            block[SEED_LEN + j] = counter_bytes[j];
        }

        // Hash the block
        // First SEED_LEN bytes are the seed, next 4 bytes are the counter
        hashed = dep::std::hash::sha256_var(block, SEED_LEN as u64 + 4);

        // Copy hashed output to mask
        for j in 0..HASH_LEN {
            if i * HASH_LEN + j < MASK_LEN {
                mask[i * HASH_LEN + j] = hashed[j];
            }
        }
    }

    mask
}

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
impl<BN, BNInstance, let NumBytes: u32> RSA<BN, BNInstance, NumBytes>  where BN: BigNumTrait, BNInstance: BigNumInstanceTrait<BN> {
    pub fn verify_sha256_pss(
        _: Self,
        instance: BNInstance,
        msg_hash: [u8; 32],
        sig: BN,
        key_size: u32
    ) -> bool {
        let mut exponentiated = instance.mul(sig, sig);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, sig);
        let em:[u8; NumBytes] = reverse_array(exponentiated.to_le_bytes());

        // The modulus size in bits minus 1
        let em_bits = key_size - 1;
        // The actual length of the encoded message without any of the leftmost 0s
        let em_len = (em_bits + 7) / 8;
        // The length of the modulus in bytes
        let key_len = (key_size + 7) / 8;
        let h_len = 32;
        let s_len = 32;

        // Check if emLen < hLen + sLen + 2
        assert(em_len >= h_len + s_len + 2);

        // Check if eM ends with 0xBC
        assert(em[em.len() - 1] == 0xBC);

        let db_mask_len = em_len - h_len - 1;
        // 256 - 32 - 1 = 223
        // As hash is 32 bytes and we also remove the 0xBC at the end, we have 223 bytes left for DB
        let masked_db: [u8; 223] = get_array_slice(em, em.len() - key_len, db_mask_len + em.len() - key_len);
        let h = get_array_slice(em, db_mask_len + em.len() - key_len, em.len() - 1);

        // Mask the leftmost bits
        let bits_to_mask = 8 * em_len - em_bits;
        let mask = 0xFF >> bits_to_mask as u8;
        let first_byte = masked_db[em.len() - key_len];
        // Make sure the 8 * em_len - em_bits leftmost bits are 0
        // c.f. https://github.com/RustCrypto/RSA/blob/aeedb5adf5297892fcb9e11f7c0f6c0157005c58/src/algorithms/pss.rs#L205
        assert((first_byte & !mask) == 0);

        // Generate dbMask using MGF1
        let db_mask:[u8; 223] = mgf1_sha256(h);

        // Compute DB = maskedDB xor dbMask
        let mut db = [0 as u8; 223];
        for i in 0..db_mask_len {
            db[i] = masked_db[i] ^ db_mask[i];
        }

        // Set leftmost byte of DB to 0
        db[0] = 0;

        // Check if the leftmost octets of DB are zero
        for i in 0..(em_len - h_len - s_len - 2) {
            assert(db[i] == 0);
        }

        // Check if the octet at position emLen - hLen - sLen - 2 is 0x01
        assert(db[em_len - h_len - s_len - 2] == 0x01);

        // Extract salt
        let salt: [u8; 32] = get_array_slice(db, db_mask_len - s_len, db_mask_len);

        // Construct M'
        // M' = (0x)00 00 00 00 00 00 00 00 || msg_hash || salt
        let mut m_prime = [0 as u8; 72]; // 8 + h_len + s_len
        for i in 8..40 {
            m_prime[i] = msg_hash[i - 8];
        }
        for i in 40..72 {
            m_prime[i] = salt[i - 40];
        }

        // Compute H'
        let h_prime = dep::std::hash::sha256(m_prime);

        // Compare H and H'
        h == h_prime
    }
    /**
 * @brief Verify an RSA signature generated via the pkcs1v15 signature scheme.
 * @details The fourth function parameter is required to define the value of `NBytes`
 *          when converting a BigNum into a byte array, the number of bytes is required and currently cannot be inferred.
 *          Once numeric generics can be derived by applying operations to other numeric generics the need for this will go away.
 *
 * @note We assume the public key exponent `e` is 65537 
 * Rough cost: 2,048 bit RSA: 26,888 gates per verification
 *             1,024 bit RSA: 11,983 gates per verification
 * A circuit that verifies 1 signature (and does nothing else) will cost ~32k due to initialization costs of lookup tables
 **/
    pub fn verify_sha256_pkcs1v15(_: Self, instance: BNInstance, msg_hash: [u8; 32], sig: BN) -> bool {
        // e = 65537 = 1 0000 0000 0000 0001
        let mut exponentiated = instance.mul(sig, sig);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, exponentiated);
        exponentiated = instance.mul(exponentiated, sig);

        let mut padded_sha256_hash_bytes: [u8; NumBytes] = exponentiated.to_le_bytes();
        compare_signature_sha256(padded_sha256_hash_bytes, msg_hash)
    }
}

#[test]
fn test_verify_sha256_pkcs1v15_1024() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());

    let BNInstance: BNInst1024 = BigNumInstance::new(
        [
        0xe908724e0d28a1565511879e00f063, 0x58dea28d5112982c8ab8597d3e611f, 0xb115f9878acc910a47b41ac8d5f763, 0xc71b0a719c2283f710f86024737cee, 0x9ee9eb73e95b84f033af5217337427, 0x8fcab34c99cc2661dd57de15ae2110, 0xa38db8a829eec5550342f6f66334dc, 0xd7c4b32fd351a47d860fda1897330e, 0x98c92a33a0f33fd7
    ],
        [
        0x55582e8ba08822783fbd7d07390be2, 0x1d7d83f9dce3983c66f440dcc2f33e, 0x6072d13c84a4cb304f58fbabe782e7, 0x0cee5e0dd62bc54d15a91a4ea3bc50, 0xc485e6f946c45cf660fba4f49325cb, 0x1f0e45df0464b065c94e84ed1dad8c, 0xe4c7b3976310ea239059d834b545f3, 0xd418145200fa77235f5f8d852b121f, 0x01acf0bd16cad9bd8f
    ]
    );
    let signature: BN1024 = BigNum::from_array(
        [
        0x393f230b55a12fb7bb39c7edd2cf48, 0x78f7d0a217d340407cae4f39b8f001, 0x603909ff76a519f3c8e96d695d462e, 0x0640ab230b459bf4b20b4823a5b850, 0x02ba190de61a85074b18e228231984, 0xe1424c0779825707aa433ecb86c388, 0xbed8087d947a9c6c56625ad20c91aa, 0x7da4a0c2eee3a3c0d61e892ab4ada9, 0x6ef98a936c8bf8e5
    ]
    );

    let rsa: RSA1024 = RSA {};
    assert(rsa.verify_sha256_pkcs1v15(BNInstance, sha256_hash, signature));
}

#[test]
fn test_verify_sha256_pkcs1v15_2048() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("hello world".as_bytes());
    let BNInstance: BNInst2048 = BigNumInstance::new(
        [
        0x183b4cadacea64716b6535b25a86ad, 0x129a32e9fbd374949e81b080546c2b, 0x9276332765f54b9b4d6fe23f4983a4, 0x91df05fde1a414c9fbf38808a01032, 0x97ca171c382e082ddd6c81be090902, 0x97161dde47ed979939451704b72648, 0x3b66f0c93f8ddbc62bb99f6b8fad2d, 0xc3a046fcad814d8938da372cd84d2a, 0xfe903cfe3ee4de6de3916023bb87f2, 0x8be5fd99c8b46dce9aab27ce4b3883, 0x0d99dfe50dd2288123804872da8543, 0xbb6d8afef8b2c7e3b86ad96973d4e5, 0x17e08fa3c5391279b844581f67825c, 0x09511f4a436abe495bfbfcc254d9c5, 0xf80d02572d620eab5ad7ecfbe2c20c, 0x2a5307402a05f59ba232ad0c8366d0, 0x7b9169630b317c38d549a86f85fcfc, 0xf2
    ],
        [
        0xf4effa025abe90db41dc5bb5934a5f, 0x2596b25aa09f6a0e290accebbef006, 0x330e9567ec5eca92b7a8ce72ad3d83, 0xccf98d178ec4017e4947cadc02da7c, 0xaed6044ffeeb12de4d1e67aedfda78, 0xb5ae8a5a4637b632800e2f41dfbf0a, 0x8304360d359cf2f0d5d97c039f9b04, 0x53cde0d0633c0e66e1da9a118f6a96, 0xf9a83822351097bb1ed123d10290f5, 0xeb489c7f7227c09ca0117264dcf04f, 0x6a1b3618478a235f438adf84533177, 0x71c03085e38a87f5ec8e51c27dde98, 0xcf3e89d9cf253ef61d65d4431334d9, 0xa5a1a59e98fb7f49c746149324201d, 0x38f46c635f884f24c254eaa37981d6, 0x1c42be15dd95e1ac5bf01972b24ff9, 0x4555dd506d1f89e61279293c03db90, 0x010e
    ]
    );
    let signature: BN2048 = BigNum::from_array(
        [
        0x5f0937ed1aacbdb83991e21c89ca8a, 0x5a1fa4ef2faf4042401c9121c73874, 0x7379fbb7713fbf807d250f7401afb8, 0x9cc5ce8813f3a83a72b681a4d434b2, 0x11cb49ac2ee1f9bed8a008b8327e1e, 0xf3362524f1224e48827b34a62f6ace, 0x3498a2944e32a3798fe9da684b32ae, 0xc346c33528bcdf7a06805126a29402, 0x6ac93f2fa68f270ec73674eae24380, 0x222c72de080496533ceeb8af827910, 0xc22889b311a53203278b942ca67100, 0x93d75567f7fe9ee7ca9871a0cb09f9, 0x049dabd976a9574847b1614f6b739c, 0xdc66b621dbae623df9b657b52fa1b0, 0xf37e82cc1eced382e11fc32e673f67, 0xe50545eb9027f1144a0ba7bbb0c886, 0xb6193409539c515d3c55a45c5734b1, 0x4b
    ]
    );
    let rsa: RSA2048 = RSA {};
    assert(rsa.verify_sha256_pkcs1v15(BNInstance, sha256_hash, signature));
}

#[test]
fn test_mgf1_sha256() {
    let seed: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
    let expected_mask: [u8; 32] = [
        106, 93, 232, 46, 236, 203, 51, 228, 103, 104, 145, 29, 197, 74, 26, 194, 135, 200, 40, 232, 179, 172, 220, 135, 51, 185, 209, 35, 194, 131, 176, 190
    ];
    let mask: [u8; 32] = mgf1_sha256(seed);
    assert(mask == expected_mask);
}

#[test]
fn test_verify_sha256_pss_2048() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
    let BNInstance: BNInst2048 = BigNumInstance::new(
        [
        0x9c149f9aa49db0ee279be7b1b9f2b1, 0x472c42ef0019a179b36a37313423d5, 0x6796724132fb7b7b14db1078126604, 0xafbc95dc121ab99608b8f4145536b7, 0xef72836154b7feaaa7b4a79e07a3fa, 0x44ef7a3c294a863a2b8820c17a5ce6, 0x7bbb5c1d1160b1136cf310155d04d3, 0x81e11b000f6d1a72cdd0c57225a29c, 0x9d02c16e2643b7d38e082bdde79b0a, 0xd8d1905fde1d7bafc516ef0a544793, 0x41aa69097fc68ca3efb4a20e953f45, 0xc1580306d50a17bdeef26eeace7d9e, 0x69ecdf56a571e2349c615851b28f62, 0x79d7c408c01d0d601a318c3c3fb840, 0x94c5ac3935445baf4de56e50c50b30, 0x4d5c5d278e3a0f7f0617908b86ef71, 0x2ad08f95d923c8c04d9d93d072e13d, 0xaf
    ],
        [
        0xabdcccb22151f142cbaa207bf6cc89, 0xeaad15b6065fcff60108c268554cfd, 0xc508f4e0a4559a78166f1739577c8e, 0xb140e6600daaeb1038e38081ed338c, 0x72e332e60e3c44cdedbe157b539714, 0xf60bff05409ef357f90d0087def9b3, 0x9c82957c546f138ee9c7edd6e8fe18, 0xe04e36bd481ece291a557975dab90, 0xfd7c8ea97e11164495d881394d304b, 0xfa5a096283f960b1256700d772e9, 0x61c0057ea007659e58ac8754fec77c, 0x57bc9dd907a5065cd6ba3d6bd6b0e9, 0x517515a3fd6408b5e5766be7a692c5, 0x2b817d4eb0fe5afd47900c0e56f93f, 0xf604e52448f245c64e0e66198018e8, 0x8db41fd0ec788dec05113586c205ea, 0x224597fab441cd104694d7d61e0a57, 0x176
    ]
    );
    let signature: BN2048 = BigNum::from_array(
        [
        0x17b138e0afc2893ae13d2eea1ce349, 0x5d18d222dfc4af50aa6eb31eeb8403, 0x29d2a6d0fc929addd1785228f0f350, 0x162ff4f4bfc98867ff1e9ae7e4dfa2, 0xd38c9fe831a9acb84eb5754fde653f, 0xd9629bcc05a5ba2fd4edbd257c8b22, 0xc130ab593612459d247b0a1430515f, 0x20f1b3ca2724f0f811a8c793130196, 0x507cc26d77029853a1ef7a46c7f3c1, 0xb335060a4a9f58b25173d84e50b600, 0x5836975b3491cfe85a98204fca00f2, 0x17f96851d11d36ab2b93adb7aa3c07, 0x8e36e106516fded0e68a2a1be0d6b6, 0x697f2906a826b9dee8f3f497596db6, 0x38fdb5f7ca447d7b55e3f4ab592050, 0x2511143f27e0ce03e03100532b68a5, 0x01db0955c41de01a6c2e4bb902b621, 0x3d
    ]
    );

    let rsa: RSA2048 = RSA {};
    assert(rsa.verify_sha256_pss(BNInstance, sha256_hash, signature, 2048));
}

// The following test is using an unusual key size to test an edge case for key size not divisible by 8
/*#[test]
fn test_verify_sha256_pss_1964() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
    let BNInstance: BNInst1964 = BigNumInstance::new(
        [
        0x2a035f94929bb130deaf854028f433, 0xbcfe17113a631a59158c3a81b85d4d, 0x136b271c541b8dbad5672777c48d9a, 0xa7f9a26a6fcebd3299c1604c501818, 0x8eb621862ba1bb8c432bc64c21e0a0, 0x1e0be8f31f728998e1e8783d06271d, 0x70f2a1450579e00f86bb39abe44cd8, 0xf26823e29557176366145bad958caa, 0x5b11eb8d6d8d5f0afb047b8826747a, 0xbfd7ee9d32a932bf274c75b63c8f40, 0x26bf6dc058ec401fd5f34c7ec1755e, 0xa04110ce6ae975c6f9075dc8917565, 0x24b194b23c695ba8eea35a6f336c2a, 0x153f3fec0be28f1f1636069149ba47, 0xca764dc95c1f96a325f9d51254a790, 0x67ea496073a3adcb0d093afec3c2a2, 0xcdd00d115e5
    ],
        [
        0xeb858462288906c78264566f2517bf, 0x307764ae5c67f7b179be6178742f97, 0x2eadd630b79ccfbea22e68e50701b9, 0x2683b85d13dffa94d1c986870489f1, 0x6d9f9788a78c52cab1918b4070842b, 0xd93261e5f34c5508a47183b62fb3b4, 0xd4b3a75c20554347708df7583ff81f, 0x63d7878156e7ea6a62f8c3f7e6f15f, 0x6cc531bba9e02310e414a3aa4e1a06, 0x19b50bf06c4444b2a788ec44c41c91, 0xd6bad67102a89597684b9d53f5370f, 0x726cc1262518f1b59aded3184d3ae4, 0xd018338b704c0a2535dee1fe70ce60, 0x9ec435e1f1652d2dde4e56cce77901, 0x41460a18f3fed1112e41afc93a2464, 0xc19e91fbbab21f155e4b71dbe9a7dc, 0x13e6ce9d6a14
    ]
    );
    let signature: BN1964 = BigNum::from_array(
        [
        0x29787913470259aee2641be22694c6, 0xec09bc1e2d77c6585d183298e7821f, 0x44b3474a5a85c68fd5b1c0d58b8a14, 0xb4305577f64847c7365e4c50bd3ce6, 0x6fa468f111116d3b240bc26a6f7aa1, 0xfa4e31aea797f4e13d832798e84698, 0x318e9578a49fa2cfea99f604597688, 0xc8be4cf64d62c6342b7ee14be70cb5, 0xc7a942ab90fbff9e8791d6a24ae841, 0xd75dc97acf08b6c3d6fbe52ed2d025, 0x06708e15a6d7649eac7c37ab06c9d6, 0xc5602556b8d74f4e98983b65eb698b, 0xd1ce86b68f8737ef86c35344f4d55e, 0xff6c2b0f9e8a62758c36bdcfe31ce9, 0xbadab8d8f0a51ff4d8d94600eb7c58, 0xcefdcd5b6b58a024020ee703e313b3, 0x0a1a27008f49
    ]
    );

    let rsa: RSA1964 = RSA {};
    assert(rsa.verify_sha256_pss(BNInstance, sha256_hash, signature, 1964));
}*/
