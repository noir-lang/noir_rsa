use dep::bignum::BigNum;
use dep::bignum::runtime_bignum::BigNumInstance;
use dep::std;

use dep::rsa::types::{RSA, RSA2048, BN2048, BNInst2048};

fn main(bn: [[Field; 18]; 2], hash: [u8; 32], signature: BN2048) {
    let rsa: RSA2048 = RSA {};

    let BNInstance: BNInst2048 = BigNumInstance::new(bn[0], bn[1]);

    assert(rsa.verify_sha256_pkcs1v15(BNInstance, hash, signature));
}

#[test]
fn test_main() {
    // Output of `cargo run -- "hello world"` in the `signature_gen` directory
    let hash: [u8; 32] = [
        44, 242, 77, 186, 95, 176, 163, 14, 38, 232, 59, 42, 197, 185, 226, 158, 27, 22, 30, 92, 31, 167, 66, 94, 115, 4, 51, 98, 147, 139, 152, 36
    ];
    let signature: BN2048 = BigNum::from_array(
        [
        0x6a6f5e0452068d059239596499427e, 0x49874fff56ea7d5b82affe13aff398, 0x8308e0b83c4493fe3d36677d5c5f20, 0x7b74cb72e02b0bf597757cbd6b874a, 0xb3bb213180fbc065e80148751d2524, 0x1c4c705d5ecd56bd6a8aa9a6d84894, 0x6b4d426b0ec097a55ae974842425ef, 0x8d9d942447e7adaa33ac0971040c46, 0xbf190a8aa6badf43475b0df01fe440, 0x9f8cb910501645e353112d2cc61519, 0xdac9f06a74b78ed9f1f6e9b07980e5, 0x97212e5771d1f99e87666cff37f219, 0x39bb405b61f21fdcea09190d12e3b5, 0x578092bcac46bb96fbbac4d6629f86, 0x318f31f85d9675cfb9276d7452d05d, 0x17b89cc9cd00b8349838da3e2e9a31, 0xe527eaec955b8cbce6b83e64cdb907, 0x4e
    ]
    );
    let bn = [
        [
            0xcccf08e1d72f1e09c96a1d45fa7ebf, 0x451697572b91ec507198cf9b5cb9bb, 0xf10583347b1086741d88d770b97f86, 0xa6b09bf6a6fc537fd20c09aebbc02c, 0x9062f17b0c8ff4cdbcf5ec5dcaa11c, 0xffe8818f651c10a007dfed65268611, 0x1fc98113a2f756f71e2aa0980af51d, 0xb58e1cfae449c77c606d0ac2b8dcd0, 0xf1c51612848b08bdab6606ed6f7d84, 0x17bc64df41aa696d6fea80db134085, 0xf47ddb8f078888734806920a286966, 0x76dd5ea8fef16f3a97ec5763d6aa3b, 0xba8a4edcc12d02ed34a2c4c5c20cc9, 0x74d02b69d4c6679f21476669910c72, 0x467650c3fae9218446bd2dc6af509e, 0x3fdfcc8d6417caedde949c3440d12, 0x47286c36472b5cacc3ca5707a243c2, 0xc1
        ],
        [
            0xe4cd9ccaa953dd98075a6d009793c8, 0xc016aacf3bbeca04f3ec400b91da8d, 0xb0ce42ae48ed76825d1c6a4846bba8, 0xf5c3e89edafd2aab4a5dc93ee9b601, 0x1b0656182baa22226285a24c99116b, 0x6b32bd281f20b4ce44ae30f4e46d69, 0xa2d9c08c9a88927cc0969cfefffdff, 0x1cf7c83f500d162b24a4a829660803, 0x629cde32525c3b22139e6c8e38366e, 0x7ebcfeeabc68bf330945b3bdd98273, 0x65911b4114a7ea3cbdce11aae463e4, 0x5091a1dc5a4f02a0168fee7da515aa, 0x3ec8a6223b48a4df3641d59c3ddfd, 0xc6901c74e7c8a968403d618a2a088a, 0xa077d01679560228faeb5e4fe0d47d, 0x7f9010a2cde8cd10bc03ec56f90364, 0x13909fd6c85b9eeb2aaaf64643cd46, 0x153
        ]
    ];
    main(bn, hash, signature);
}
