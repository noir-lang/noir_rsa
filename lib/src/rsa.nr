use dep::bignum::BigNum;
use dep::bignum::runtime_bignum::BigNumInstance;
use dep::bignum::runtime_bignum::BigNumTrait;
use dep::bignum::runtime_bignum::BigNumInstanceTrait;
use dep::bignum::runtime_bignum::BigNumParamsTrait;
use crate::types::{
    RSA, BN1024, BN2048, BNInst1024, BNInst2048, RSA1024, RSA2048, BN1025, BNInst1025, RSA1025, BN1964,
    BNInst1964, RSA1964, BN4096, BNInst4096, RSA4096
};

global HASH_LEN: u32 = 32;

fn reverse_array<let N: u32>(array: [u8; N]) -> [u8; N] {
    let mut reversed = [0 as u8; N];
    for i in 0..N {
        reversed[i] = array[N - i - 1];
    }
    reversed
}

fn get_array_slice<let N: u32, let M: u32>(array: [u8; N], start: u32, end: u32) -> [u8; M] {
    assert(end - start <= M);
    let mut slice = [0 as u8; M];
    for i in 0..M {
        if i < end - start {
            slice[i] = array[start + i];
        }
    }
    slice
}

fn pow(base: u32, exp: u32) -> u32 {
    let mut result = 1;
    for _ in 0..exp {
        result *= base;
    }
    result
}

/**
 * @brief Generate a mask from a seed using the MGF1 algorithm with SHA256 as the hash function
 **/
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
        let mut block: [u8; SEED_LEN + 4] = [0; SEED_LEN + 4];

        // Copy seed to block
        for j in 0..SEED_LEN {
            block[j] = seed[j];
        }

        // Add counter to block
        let counter_bytes: [u8; 4] = (i as Field).to_be_bytes();
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
    /**
    * @brief Verify an RSA signature generated via the PSS signature scheme.
    * @details `key_size` is the size of the RSA modulus in bits and is required to correctly decode the signature.
    *
    * @note We assume the public key exponent `e` is 65537
    **/
    pub fn verify_sha256_pss(
        _: Self,
        instance: BNInstance,
        msg_hash: [u8; 32],
        sig: BN,
        key_size: u32
    ) -> bool {
        // Exponentiate the signature assuming e = 65537
        let mut exponentiated = instance.mul(sig, sig);
        for _ in 0..15 {
            exponentiated = instance.mul(exponentiated, exponentiated);
        }
        exponentiated = instance.mul(exponentiated, sig);
        // Convert the exponentiated signature to a byte array and reverse it to 
        // get it in big endian order, which is much easier to work with for 
        // the rest of the verification process
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
        assert_eq(em[em.len() - 1], 0xBC);

        let db_mask_len = em_len - h_len - 1;
        // In some rare cases, em_len is not equal to key_len (e.g. 1025 bit RSA)
        // In this case, we'll have a leading zero byte in em that we need to ignore
        // c.f. https://github.com/RustCrypto/RSA/blob/aeedb5adf5297892fcb9e11f7c0f6c0157005c58/src/algorithms/pss.rs#L242
        let offset = key_len - em_len;
        // As the hash is 32 bytes and we also remove the 0xBC at the end, we have up to NumBytes - 33 bytes left for DB
        // For example, for 2048 bit RSA (i.e. 256 bytes), we have 256 - 33 = 223 bytes left for DB
        // and for 1024 bit RSA (i.e. 128 bytes), we have 128 - 33 = 95 bytes left for DB
        let masked_db: [u8; NumBytes - 33] = get_array_slice(em, offset, db_mask_len + offset);
        let h = get_array_slice(em, db_mask_len + offset, em.len() - 1);

        // Make sure the 8 * em_len - em_bits leftmost bits are 0
        // c.f. https://github.com/RustCrypto/RSA/blob/aeedb5adf5297892fcb9e11f7c0f6c0157005c58/src/algorithms/pss.rs#L205
        let bits_to_mask = 8 - (8 * em_len - em_bits);
        let mask_value = pow(2, bits_to_mask as u32);
        assert_eq(masked_db[0] as u32 / mask_value, 0);

        // Generate dbMask using MGF1
        let db_mask:[u8; NumBytes - 33] = mgf1_sha256(h);

        // Compute DB = maskedDB xor dbMask
        let mut db = [0 as u8; NumBytes - 33];
        for i in 0..db_mask_len {
            db[i] = masked_db[i] ^ db_mask[i];
        }

        // Set leftmost byte of DB to 0
        db[0] = 0;

        // Check if the leftmost octets of DB are zero
        for i in 0..(em_len - h_len - s_len - 2) {
            assert_eq(db[i], 0);
        }

        // Check if the octet at position emLen - hLen - sLen - 2 is 1
        assert_eq(db[em_len - h_len - s_len - 2], 1);

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
 * @note The exponent `e` can be either 65537 or 3 (i.e. the most common values in use for RSA)
 * Rough cost: 2,048 bit RSA: 26,888 gates per verification
 *             1,024 bit RSA: 11,983 gates per verification
 * A circuit that verifies 1 signature (and does nothing else) will cost ~32k due to initialization costs of lookup tables
 **/
    pub fn verify_sha256_pkcs1v15(_: Self, instance: BNInstance, msg_hash: [u8; 32], sig: BN, exponent: u32) -> bool {
        assert((exponent == 3) | (exponent == 65537), "Exponent must be 65537 or 3");
        let mut exponentiated = instance.mul(sig, sig); // sig^2

        if exponent == 65537 {
            // e = 65537 = 1 0000 0000 0000 0001
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^2 * sig^2 = sig^4
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^8
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^16
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^32
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^64
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^128
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^256
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^512
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^1024
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^2048
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^4096
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^8192
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^16384
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^32768
            exponentiated = instance.mul(exponentiated, exponentiated); // sig^65536
        }
        // otherwise, e = 3 = 11

        exponentiated = instance.mul(exponentiated, sig); // either sig^2 * sig = sig^3 or sig^65536 * sig = sig^65537

        let mut padded_sha256_hash_bytes: [u8; NumBytes] = exponentiated.to_le_bytes();
        compare_signature_sha256(padded_sha256_hash_bytes, msg_hash)
    }
}

#[test]
fn test_verify_sha256_pkcs1v15_1024() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());

    let BNInstance: BNInst1024 = BigNumInstance::new(
        [0x267a81687f691d373b11a1b9bff4a7, 0x5f68676fdefabdffef3d55b4caed91, 0xd9657fc8d2920c84313cc45a00ef28, 0xd2b6b87cea51408b4c0c6f42137349, 0x280f4eb1f31e7b0e7c647d501b98fa, 0x9b54af4604e4fbd6692f07d1dbcfdf, 0x2648733c74c21ae2682c7f7fa33492, 0x388ae035d204107e06315c6bf5d5cf, 0xd2b8178e1202353a],
        [0x7c762331281f2048792c9d2c29181e, 0x41f46206496754ae3015b560cf983f, 0xd9af95cca97efc17d1dfe4a23be55a, 0x9aaf33238937d8ed0a666681a25c67, 0xce824b31fa43e73990103eb1abf01b, 0x93b94ec888e5ae709526a7d26fb83, 0x9a292a95a58f526f123fb43632a7e8, 0x8720b3863df62c2a9c74a94fabc2ad, 0x13702dd0b4c4170e76]
    );
    let signature: BN1024 = BigNum::from_array(
        [0xca2952afeb4a53d5f04ef5da8fb1ac, 0x3ac5669f97a9a3c348f6a8f19410c0, 0xaef7871847a6f7a41518e449c850c9, 0xff5cee86baf6e2f1ac7826fdceda81, 0x0ac8ef23a44fdf08c96f0dd7101691, 0x6047e61cb2159cad43c3cd81b94a27, 0x085087bf5ad68049907466aada42e0, 0x77fb01eb713699f58d5de56e2c3085, 0x944e7f7002edf2bd]
    );

    let rsa: RSA1024 = RSA {};
    assert(rsa.verify_sha256_pkcs1v15(BNInstance, sha256_hash, signature, 65537));
}

#[test]
fn test_verify_sha256_pkcs1v15_2048() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("hello world".as_bytes());
    let BNInstance: BNInst2048 = BigNumInstance::new(
        [0xaf86acdc2edb5e2e6b80ae97ec6e01, 0xefabc0656838a3d8ce1efc0e4573fb, 0xbc8db319ce48229d975d72667b081b, 0xa867e0b28d59b34f6268b01255e9b4, 0x7fa1e5d205f156bb0f4ae06dc21678, 0xe14cf7dc8cde86604744bfa09c9f43, 0xa12c98158e42d963081bb0e5909074, 0xb7428ef3edda9348d59932e869a395, 0x3810573ace3dad29a4b2d27b46cefb, 0xe42c6f4b09dea7ea09da6b2939723f, 0x6abef0b63e9c7eb0a003c1cecb12d2, 0xd13390f93ac152a9d795449b4477df, 0xbebf49b31f8dedc348766ee0cce5a3, 0xf54eba4bc078ced4d393636b37ee54, 0xccf2434ce0476e0eb05b3fc97b5207, 0xcb0f65c02f33a3230c30adfd613aef, 0xf25020257c87f7d884686c7ed9aeb2, 0xc9],
        [0xd5e7f858f4ac84349d34a76d58947e, 0x8796ae37c4bf1eaef57b08719bc6e2, 0xaff657fba7b760debce3d966cfd2aa, 0x8fcc2a4864108086726b2195dd4ee, 0xa49b949ab7f8183fb3b32838cba6cc, 0x67cae6e1a680e589c3c12478dc81ea, 0x52ff1d4ff5f5f4c0df42c9c89cbb12, 0x86b4b87dcc52a0bcfd465e040ae891, 0xb750fa6eda9da6ac5ee2761cfa84d6, 0xd48e01e5bf813b9603132e0e37a578, 0x5ecb2e1f0d05d59ec1dbcb9c9afa7, 0xa47daaff887a579cf3a7469d5c9c6c, 0x4bc5a7caf30cfbe4e21a87bcc481fc, 0x79d3bce8e6fd9a0d1b03f51b717853, 0x503021077988dfcaa4964e98f7e6a9, 0x4beb0c42f2984ebef6529f3bb1ce20, 0x58375802bf932345e24dfba3c7dc81, 0x1448]
    );
    let signature: BN2048 = BigNum::from_array(
        [0xecb7946ae26bb51a9051a836a78326, 0x60f75b637ab5b07e6d61f51df935ec, 0x0ac1c325459a21cc1fcf2d2bec635d, 0x2c07999eef9fe3455c411111731651, 0x1cb13d316472503d8d49b53d4c71ad, 0x8b06a585b629e7eb9ebe4200bd691c, 0xeae049862236fc8828f1d8460097e8, 0x5e195603db54467ef7ef0736c9b6b7, 0x21f0533c44d09d43b22d71205d5139, 0xe31249310bea8c3f8ac50a3bb7d24b, 0x691ce6653ab191eeefa111fe68cdce, 0xf2d22a5eba73f31e14f54b613287a5, 0x683f29e32d3997dc8ddd67bb1fc693, 0x1c6ac2c887b9d2e6134a170237111e, 0xe9d16da72b95827bac5a076a242f3f, 0x2f4b6e78c8d350ae21d3f153b85906, 0x67ebea1e397eac097fa854f4917b42, 0x2a]
    );
    let rsa: RSA2048 = RSA {};
    assert(rsa.verify_sha256_pkcs1v15(BNInstance, sha256_hash, signature, 65537));
}

#[test]
fn test_verify_sha256_pkcs1v15_2048_exponent_3() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());

    let BNInstance: BNInst2048 = BigNumInstance::new(
        [0x75c5bca4f8f2f82385265949b3bb75, 0x7ace99cb37c121c3cd1939f2c1487c, 0x4d17fcd80b52bbf66cf8f97572b02e, 0x7b96003c6ff353494a478df6b4af73, 0x893b40fe212bcfb135120246253b85, 0x3a8c7e266288bbf8758e46c89c9de1, 0x7274f2ebf076dcd8ab34f847667664, 0x5e9d8f74c324471f3f106ca1fe80d5, 0xaa4095f895c786f9e84516808f969, 0xbf5e88eb78c5cf3e750431eebdf182, 0x57d23c9b283bee3989d2389cc5f94d, 0x2b3118c96b322e8ea6e02c5a51a9d6, 0x289c6ec4480ffab775beb329a1a039, 0xd46bcd28660f9c9567c84341ff1a2a, 0x581a62726ce0d53142d296933db8b0, 0x8c6555a8e1ecefdef78f2c176ee8b3, 0x655e3d71e389d347a449f4fdd9031a, 0xb0],
        [0xe62e1ecde94ae8051b38164e003ee3, 0x8441eed84fc22b5353a37239d064e3, 0x38710ab45e32e6bce719b59b76172, 0x69089817150853e46c87a89e9d95ac, 0x300f94a0fbb1c36169c42a02410302, 0xed60de07623a530d2c589e7a42cc25, 0xfd9b3649c01b7046e6d441d7fde5f0, 0x8eaf43ee8219078022bc9c5faa0b13, 0xd974d63a560abb5f26175bb7690f42, 0x6da24d7dfa8bd86f4343f40573d1ef, 0xd94e4160df59053155e3c89a540b59, 0x7d472519d0dead12e34efec753f55a, 0xa0ec9c9c04bf19c89a42500e4dc454, 0xed9fffb3a0ae3a70b1c66a7006a68a, 0xba517c632b980d1390fe3f1853edc0, 0xda44d3af10a3f7e9795760f19f2082, 0x71b87c9f2f9ace997aba7c92698b93, 0x1738]
    );

    let signature: BN2048 = BigNum::from_array(
        [0x030b31f451992d212692eb7d89cc0b, 0x7153553e0d75775e097b22fdd8929b, 0x84da65592a46d92e852bd9a4079785, 0x840b20118b55dc1e197c4d5030d70c, 0x04bbf2031f56081b88fe01aae1fd08, 0x144d82f260967fcf3a905f7dd039e7, 0x73674964ae057790bcc6ee5e5e9ccf, 0x704fe04fd0112bcd55417d1dc1d045, 0x0b3ca2d3181e093b418df04e87730b, 0x8f47cbd2fae384d84040b68f074083, 0x8f2f009bf83c883a77793383df44c8, 0x920b833f64288e95680c474b8c788e, 0x7ca14d6d484f830452dbf95aa4b30b, 0xb696a5efca533d2e97fd5cf619cfd7, 0x8d28e472e31c98a732a8266f9e6ca1, 0x8871c309a036d09f9bb2e66761a366, 0xea39d14a83537ed8e922c5300cbd7d, 0x0e]
    );

    let rsa: RSA2048 = RSA {};
    assert(rsa.verify_sha256_pkcs1v15(BNInstance, sha256_hash, signature, 3));
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
        [0x45648f4ade2ac1f40c18b44a2951ad, 0xd558cced315cbced65532e416ab0ea, 0x67c3818b41ed79f0e9e06b10b31a39, 0x9bb9db99001fe165b2a18bfb8ff423, 0xc792c2037f2abe206bdc987898a73b, 0x6630acf8743e8ffca5199b195d2e32, 0xbffc9f0464184da3de5f0efa5a705b, 0xe14bd49bd3ec93d8f3e84f47a32e6d, 0x2d6abfec39882cd67f7804b9ff278e, 0x1140883fa39129d297ebee534cdf58, 0x96bc387e08849589aa1dda5d381cd2, 0x31c60ecdf4d3c1119814b724779a9e, 0x1a4882267e3e2e6074b40448d62087, 0x9e015854d57eae42e5b515d357a755, 0xb593f8dfc8434f32d7d30277b1abc, 0x4e7184b54966a30552fc92df470aa, 0xa8a3c9172762978b03464671f8288e, 0xba],
        [0x1c63831dbaa98693ab59ca2ae5a88, 0x3e67cf06ca2556701f3aa8d158552, 0x7c63171078a831165ed8b2dd116675, 0x9e1f1bca55d0e220e58ddbbb387972, 0xd7c72f20722cc7af897d5819424801, 0xf0434a631cffe4c4d56874bff93661, 0x8767e83f45cfff15cca95d5dc6f48c, 0xf210d697748e9ad45c0f7c3ed3bda8, 0xc960d59cb9dd48d50e12c2ef04dda2, 0xbf07cf1ecc532686848dca09d061c2, 0xc491a60be200f9574ad6aa31977a4f, 0x67681170f25ab2aff941b18e21e1bd, 0xc485fc6deda1ba84f2bfcfbea2c044, 0x776bc3eac3728ec7f85ca2496ee8e4, 0x4d82eeb8ecdc1ec53280fce96c05e, 0x514088d39ff1cae50d2f67db91458f, 0x9c1553de9eef61a83b288c4d11610e, 0x15f1]
    );
    let signature: BN2048 = BigNum::from_array(
        [0xcce57aaed9eed21edef9d96d9ebdf8, 0x181f152657736ea458462ff45b1d81, 0x9df8c00fefe67c3a727c1f84641d2a, 0xe3bb299609d4f4bfe7e979123f6962, 0x6cf987c686983f184262419dc8d64b, 0xedc086f713d60c9d661a4e7fdae380, 0xb95ada34d5b9217d9eaa89d1d7a3d1, 0xec275d1d4e3e74296eab26318df81f, 0x3c943e2d3e12f1394952de70d92ac9, 0x4a4e8a625138a533b9b71cbb03c991, 0xa5379dfc363e79c5a55ad71a01948e, 0x9340e047e0d4be67ac7f1517fe2673, 0xdf2606ac8cbbcad391c5e925bf5082, 0x249690032f10b7986e7edbb8ec0d6a, 0x8c07da4fbed69ab71f127fb5edf73c, 0x64aefd403b6a4353ebdc9b7fce82bc, 0x5ecc107633bc4cc1a3adb545b474de, 0x7b]
    );

    let rsa: RSA2048 = RSA {};
    assert(rsa.verify_sha256_pss(BNInstance, sha256_hash, signature, 2048));
}

#[test]
fn test_verify_sha256_pss_4096() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
    let BNInstance: BNInst4096 = BigNumInstance::new(
        [0xa6222b52f49e7258fe4fee04ea2d9, 0x2fd64c9fce4dba1e003e9b0947ee34, 0xf46a24f43be90f258013ba55794c6a, 0xda8100ed967a7577f4144295e37b68, 0x8545db58ed5cb1a78661a725c2e2df, 0xfc1673fba9882dc0c1bf1ebd95e9a7, 0xf8863f5481969b504d93ec7b3634f, 0xafedf06a9d7583f1c06b2ee8a1f2b8, 0x375c3f57b70cb7fc6b934445a97ebe, 0xd89ad291b95a70bf4922b45d2efff8, 0x2bf000f6408944083d93e45030e827, 0xf55cb42313719c7a2bfa07b3eb1ed4, 0x6d8656a0f3b41fa1a717140dc5ce90, 0x404b10d983681bd3f9ed1534d5bfa2, 0xced48aead2b9ba16f08a0fb968a96c, 0x43acf088910c3322f7da5c2d0a2211, 0x58b7e2d7b7f268eb990fc464defe90, 0x2be3be3a4fedf432a98dda3c220958, 0xf9156a2bafb69ef294360c25d22759, 0x1b7e6763845875a1886345b4ee8940, 0xa40ae130e9762120841e1930873975, 0x2d883272a543cf8fd0cdfbecc94367, 0x715a88142fec78eb472f6684cd942d, 0xdd302fea25298915e2db875f6ab621, 0x6612ced822df9c00c368466391fe23, 0x48acb5eea186585b9c24443397b8fb, 0x53fc8b5e2bedc30b81f632371f1e8a, 0x7ef026faeb670fc44abfeee192bec6, 0xb07bb4bfb19773a319052ffac029a9, 0x81c21e9e538893cb04debde34bc02e, 0x823427edc35eaf0a2f5d493318db74, 0xbad02f47a1ff078d0103affc3792b1, 0xe297eab3b3edafcf99c2ba52cb8424, 0x3e7e575d40629a07980fa71996e807, 0xc27a],
        [0x54aba16603d87dec091aa1821ce3b0, 0x8f6a9c560fe4f4d5fb83999853bd1c, 0x4d9b41fcc316ae6b1a9bb7eefa7713, 0x623fcac3bfa0aa5f932acc0f0f28c9, 0xb29eca15e9ba6d9bbcd2ac543f9558, 0x43689b8fe8bbb48269c2fb3b03a624, 0xc6f8b1cbefb4cb7d2eec1bc951808b, 0x4074a7837f67403f497133fee0e29, 0x536ba97fd34f92aae1e0354bc17db0, 0x784c203e438e43ddddae491fd0c0e9, 0xf41ae3f5f5060d212bcc7c4ee71d2, 0xe539fd3b39a98377199ae15d165ea, 0xd13be03a50e9694c4c84e2541303ed, 0x38136b8771f62c9778e1f812ceadec, 0x23bea00ab5c2efafde2c8ea46673a8, 0xa4d3523ba9389da81c46adde61fece, 0xadb3053369bb6e7233eea01174caa2, 0x68995fa9f373e420a9f6e6fa2329e7, 0x38f83f074d3ee3674e7336349a0d4e, 0xd9ecb79c431b08a695e4808a636a48, 0x3498c268b8bb4936c9e8f9fa73da27, 0x123ed10b1358dde62125f1191fc922, 0xa5a412e4c3c73dbb5cba119c48af2d, 0xbee3217219d507e4a6ff74b9b9eee5, 0x2ee5efcaee7ca45ffcd85f10eeb21b, 0xb977bc65277e5723737f52905837bc, 0xd1fd3aa6e7717bceccf73b04c8bf2d, 0x7964355f3acd61d2408ce20a964740, 0xfc2e76f487e6ca0e6bcadbf9d3801d, 0xfb0ea20336cf95062efb880d82cab5, 0x6884d9ca882e37df90f8f5c603b7b1, 0x9be945fc633fcc0dd2b84ec1debef5, 0x8d834cbc2c9a3aa4a85a3994bc569d, 0x7055060035c122b095b75e6de37d48, 0x150fc2]
    );
    let signature: BN4096 = BigNum::from_array(
        [0xdeb402a595b32a248fd427ed84c743, 0x75f1b3656f2eb61c3e4164375052cf, 0x33aa80998875b8b48263611706607b, 0xd9c80be79f586e80ac3af1a8d5ea53, 0xf0b116fd85546f206ae49d041d0223, 0x406a397f56e62863aa7b6ed1429dec, 0xd7e0bbd7ac00a419f3fef0098e904f, 0x303665df221e3691c84c6502d1b807, 0xb2ce0e36df94a88f8120b53a0bcb84, 0xe8e55991ffdb5b731b77cb249991d1, 0xbaa946c3acb9696a4d416d86291fd2, 0x7746a7486603b1cfb5dc5f800ee409, 0x567d9470319309142967b699404091, 0x5ee6fbb50c8637805ec6c7780a9e0a, 0x32bf8a51bc178cdb664ca911c857ea, 0xe928146ddcc0865c10215611955243, 0x5d12083acd2e3a1b7f7313dea0b894, 0x8620f5ba7615db0a3285c735813a73, 0x7b84f0e392902e84792c4879f48fbc, 0x1437df81c544ea4d7fdb020bfb7fcb, 0x09fb8b36d3a58a6a5fff27c1664d97, 0xef70898862d34d8f2d7c1bb1fb8103, 0xd24f625196ae71e3064596a7dd80f3, 0xeb646b3e5958fc213a0f711a5c68c4, 0x7f57a200d1894a07a33610c56a543d, 0xa54baf3fadfe09f896d2f2c88df7e7, 0xb605122c80e189236329bbf9ad6c9f, 0xa6ac0b396215d0f50b3705cd08788a, 0xdad6946e3c27a25ab484a0ed338788, 0x874dfd4c3723c395217a881b93283a, 0xf5ac1d98a50f59a40db4e2d4864a07, 0x9d6ed5b0d10028a291588a3359cd32, 0x7d8b67a1bad38a5ec750dc27bc8ae0, 0xa2ddd25f61adf97f5e2e8a0ef99ba8, 0x2244]
    );

    let rsa: RSA4096 = RSA {};
    assert(rsa.verify_sha256_pss(BNInstance, sha256_hash, signature, 4096));
}

// Test an unusual key length that is not a multiple of 8
#[test]
fn test_verify_sha256_pss_1964() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
    let BNInstance: BNInst1964 = BigNumInstance::new(
        [0xe62ce4613d178a8af9154a28c804c9, 0xe9c80bb90ee949aa26d5554f5b7323, 0xa823c32e66dce57c7617704f092c82, 0x8b7eee92772e414a23ee9dd5ef843a, 0x6590039cb62daeea7a96faf674175c, 0x2905f4400973a1442181701f12f30d, 0xc5f0a37929848a5fbe070ddc915dee, 0x2ada1490d935ef7700c43dc2565539, 0xa99acb3b526abb963d71e527c17e2e, 0xf9d79341476659c231dc93313fb440, 0x168d8abd0528fa146b6401034358f2, 0x6d7386e7d66bec5392a463d34f7b5d, 0xeb245f85612f76849ce32cd5f9011e, 0x2d171c40f36f34eeb17b4643c7f9e2, 0xd582273cf4c5fb0c195ccac1526478, 0x1df64d0a6c95698d34c1b16640ad92, 0xdd8e29ecdc0],
        [0x7893f159b37d9b4d46e77e420d3315, 0x97913c7ea0db74a13b793686c0fa, 0x3eddab2786c599e1fcd99b06a1b151, 0x6f922b72a2386f483d35d5017ef102, 0xcf9ede21d4ca70a045ccdac95c1e9, 0xbe7c0cc79955f74eafb82000838e19, 0x26bd0fc82288bde663f5dff239b55b, 0x95f857821550531b848b454b4f7dc7, 0xef08d9d594fbf1547ac00a03323aa7, 0x3bb9f9263bfe85814477c58de4934d, 0x214887fd218e3573f1aae50917a816, 0xe6f1abc97678adf59b2008645d8802, 0x28dd35618649eef12941db95081242, 0xc13764316f70444e7120b6ae5088f5, 0xefb1aba9512f1b2c88db34a4938796, 0x6aed9a143fb37749eca936a60ae25c, 0x127ccb9568ee6]
    );
    let signature: BN1964 = BigNum::from_array(
        [0x37c3a3f915fb9e787412d457ec4a63, 0xd60918c40b6c50bcc8afa8d1ea754f, 0x98eec8d63deeb22eca4f9d15b7e935, 0xc841db8c9930934dcc8171a5fee4b4, 0x3341bdb96ed1d734959e257dbc85ca, 0x32701c7557ca04c15cd9e18f45d37b, 0xefd3dae979f5a920654dc7a3ea2277, 0x1d6724ec09b112e8776c115874a53f, 0xf403d3593f85b9ab421fa26bf99298, 0x04e85e3628f4c3fc254a92c56ba0b8, 0x975bb82f1fe3c3d1656e098682f69f, 0x0ad72d532c8e6e17398d918c360973, 0xc4ba256370766c633e77d4102a8919, 0xc4d3bb32bc889aca394bef272d3f71, 0x5d56778a3d1ad3117471d4060761b0, 0x5fd5d71fec72f615614d6347935f35, 0x09ab8ab67e43]
    );

    let rsa: RSA1964 = RSA {};
    assert(rsa.verify_sha256_pss(BNInstance, sha256_hash, signature, 1964));
}

// Test an edge case where the key length in bytes is greater than the encoded message length
#[test]
fn test_verify_sha256_pss_1025() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
    let BNInstance: BNInst1025 = BigNumInstance::new(
        [0xb1393f670c84e59a64139757ea4909, 0x1fcbf4a8e510ac71312d03414c0619, 0xcc3d9bda9c11034390bcb8c852cea7, 0x97a04769b163f2f0a7b96fefb42547, 0x2ead08e21531483127fd01b5243764, 0x58c3da337c1ebed9de0f5c0fa1aac4, 0x2667a80676d9c06d51501010c51e33, 0xb567df997852d2635155f6628938a, 0x1320f45ae735bb5f0],
        [0xc8f30dba46192f554acb68f7211d34, 0x1ed365f286ecd84e2e1f11d31bb237, 0xfc198af89a43fd2d6667a780ed188, 0x135a1e8d8ece93f4a514b849d5051d, 0xaf7accfc60db02b8e9b93933ac6b90, 0x1478bde459eac5596266622b4bd552, 0xe76986d831e1ae022a278baa051d4b, 0xa0d58e2d2f2fe861d65d597fd73443, 0x3588343e88d4b5ba71]
    );
    let signature: BN1025 = BigNum::from_array(
        [0x18c0d9f2225042399fec91d0b185b7, 0xd5b5da59f9f0888fe5f21a33f2e24e, 0xab382ee56d5da63c0f9bce10aaf682, 0x8bbd09d319136c6f9bc75b93222c50, 0x59270a017901c92d035a2d949abbee, 0x822af6fd2a10d4866005439a4597f5, 0x549a492b7e3a028c39c45881ac802f, 0x9467c197693214dc890ff5e3c2cb98, 0x0104962fcc5cb849b2]
    );

    let rsa: RSA1025 = RSA {};
    assert(rsa.verify_sha256_pss(BNInstance, sha256_hash, signature, 1025));
}
