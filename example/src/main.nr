use dep::bignum::{params::BigNumParams, RuntimeBigNum};
use dep::rsa::{rsa::verify_sha256_pkcs1v15, types::RBN2048};

// Examples of the signature limbs, modulus, and redc params can be generated via
// ../../signature_gen/main.rs.
// Note: technically, the `signature` could've been passed into `main` directly,
// for a much cleaner interface.
// The reason we chose this more verbose approach here, was to reduce the amount of
// data to generate for the Prover.toml file.
fn main(
    hash: [u8; 32],
    signature_limbs: [Field; 18],
    modulus_limbs: [Field; 18],
    redc_limbs: [Field; 18],
) {
    let has_multiplicative_inverse = false;
    let params: BigNumParams<18, 2048> =
        BigNumParams::new(has_multiplicative_inverse, modulus_limbs, redc_limbs);

    let signature: RBN2048 = RBN2048::from_array(params, signature_limbs);

    assert(verify_sha256_pkcs1v15(hash, signature, 65537));
}

#[test]
fn test_main() {
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

    let hash: [u8; 32] = dep::std::hash::sha256("hello world".as_bytes());

    main(hash, signature_limbs, modulus_limbs, redc_limbs);
}
