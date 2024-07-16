# noir_rsa

Optimized Noir library that evaluates RSA signatures.

Uses https://github.com/zac-williamson/noir-bignum as a dependency.

NOTE: library is experimental and currently will only compile using the nightly build of noir (as of 15 July 2024)

# Usage

See tests in `lib.nr` for examples. (TODO: flesh this out!)

```
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("hello world".as_bytes());
    let BNInstance: BigNumInstance<18, Params2048> = BigNumInstance::new(
        [ // first parameter = modulus
        0x183b4cadacea64716b6535b25a86ad, 0x129a32e9fbd374949e81b080546c2b, 0x9276332765f54b9b4d6fe23f4983a4, 0x91df05fde1a414c9fbf38808a01032, 0x97ca171c382e082ddd6c81be090902, 0x97161dde47ed979939451704b72648, 0x3b66f0c93f8ddbc62bb99f6b8fad2d, 0xc3a046fcad814d8938da372cd84d2a, 0xfe903cfe3ee4de6de3916023bb87f2, 0x8be5fd99c8b46dce9aab27ce4b3883, 0x0d99dfe50dd2288123804872da8543, 0xbb6d8afef8b2c7e3b86ad96973d4e5, 0x17e08fa3c5391279b844581f67825c, 0x09511f4a436abe495bfbfcc254d9c5, 0xf80d02572d620eab5ad7ecfbe2c20c, 0x2a5307402a05f59ba232ad0c8366d0, 0x7b9169630b317c38d549a86f85fcfc, 0xf2
    ],
        [ // second parameter = barrett reduction parameter (used in unconstrained functions, does not need to be constrained or derived in-circuit from modulus)
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
```

# Costs

Rough cost:

- 2,048 bit RSA: 26,888 gates per verification
- 1,024 bit RSA: 11,983 gates per verification

A circuit that verifies 1 signature (and does nothing else) will cost ~32k due to initialization costs of lookup tables
