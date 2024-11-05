use dep::bignum::params::BigNumParams;
use dep::bignum::RuntimeBigNum;

use dep::rsa::rsa::verify_sha256_pkcs1v15;
use dep::rsa::types::RBN2048; // Used if we can solve the error described in comments below.

// This will work after https://github.com/noir-lang/noir/pull/6450
// fn main(hash: [u8; 32], signature: RBN2048) {
//     assert(verify_sha256_pkcs1v15(hash, signature, 65537));
// }

// // Workaround to the above error: pass the signature and its params as arrays, instead of as a pretty RuntimeBigNum struct. Sad face.
fn main(
    hash: [u8; 32],
    signature_limbs: [Field; 18],
    params_tuple: (bool, [Field; 18], [Field; 18]),
) {
    // Ugly reconstitution of the params, until https://github.com/noir-lang/noir/pull/6450 is merged.
    let params: BigNumParams<18, 2048> =
        BigNumParams::new(params_tuple.0, params_tuple.1, params_tuple.2);

    let signature = RuntimeBigNum::from_array(params, signature_limbs);

    assert(verify_sha256_pkcs1v15(hash, signature, 65537));
}

#[test]
fn test_main() {
    // Create runtime params:
    let has_multiplicative_inverse = true;
    let modulus_limbs = [
        0x413f4f8b6405fdb76f85540f5663c5,
        0x1dffa8aaa6192d9f031a8c1d55dc33,
        0xefccc1c3eb6c189c147cd485f56771,
        0xc62eaf58cfd1a6eead6ec82e44111a,
        0xf693ea8b22a50265d43eb2235d910b,
        0x6eb385b77042a98e1f708a5b76fa17,
        0xad5ad6b87eea566a26a05f5a59713b,
        0x979c5611b54a78df8fd0b5b0464de6,
        0xfde57bd223c394f50249f18d5522aa,
        0xc6cd804f8bac07c9e81cc06fe323e9,
        0x84ec399cf67c012f58a7b81515b63d,
        0x61eba631d274a78a5387d0e2929d77,
        0x40e2bb193409130671ac8f3e7c1fcf,
        0x2aa7d8d4aec0cf96ad8fe0d0779dbb,
        0x26d56c517952712bcdf1e8f1ffafc6,
        0x9786e9f338cb9e6de55c436153978a,
        0xb867413d06a32724b33657bbf1e3f2,
        0xe8,
    ];
    let redc_limbs = [
        0xbc5184dd6dc06d396240375a5211c0,
        0x6280f148f5356bbea76382819bf475,
        0x93d5ca8016d2335de4fc0988e7e24b,
        0xd96e4c1d3210702c33d6470e16cfa0,
        0xe2dbfaf8d02d4251862905787f2561,
        0x9538f84fa231c9baac81216e2d9ed5,
        0xcb82246c4a83da9398570aaabd4d2a,
        0x94b04ca9ae375eebbb9c87479d3bee,
        0x7deacf1e79cfe70937e9eee7ed887a,
        0xa0f7bae3d1a70b98538142db43a58b,
        0xaac2ec033a9ab117f077e3e06ba954,
        0x4f937780ab7d644c95d1a34dcf450a,
        0xc17dd532df051696582c85316a2517,
        0x69f59bbbfa26851603d97da9a83709,
        0xc506921f809dcbb4c07aea96102050,
        0xbe638141f7b4d62660d59519ebdacf,
        0xbc084a1b1ca76abe6f8ae8fcff6417,
        0x1199,
    ];
    let params: BigNumParams<18, 2048> =
        BigNumParams::new(has_multiplicative_inverse, modulus_limbs, redc_limbs);

    let signature_limbs = [
        0x33aee5bd60a8d0664fe7780b7fde43,
        0xc66f8a5fc4a74d18b83b27da6d4e04,
        0x501c489c1764ad72e5c5b1bb56f1c6,
        0xb1a8c5029f8422efdcfd1621f70da9,
        0xe9b80989d178e8852266a7631c3b99,
        0xb95a3af119a4ca60350a31ad3b9d7e,
        0x64a98fdbb8441abc103fe2617149d9,
        0xfd5a9db30568b2b151bd243b1816a9,
        0x12d2be80d5959660831cc3b7929159,
        0xae6034247561d3dfa882ca20d61ff6,
        0x786973219800b65edd92b0b0b05d09,
        0x516fdbed6a0d7afa3516dbba1ea473,
        0x2f14e2807fa6c3d9cc5b7667aec5ac,
        0x9a6a1997e1f7cfdeac736073ec4ce2,
        0x24c94d7ea832e1afc889e82bd42c1b,
        0x4cfb977a1102edca719f9c2e3f2c2e,
        0x7c7cd4f29c3da09f7fa8ddf73df0b2,
        0x77,
    ];

    let signature: RBN2048 = RuntimeBigNum::from_array(params, signature_limbs);

    // Output of `cargo run -- --msg "hello world"` in the `signature_gen` directory
    let hash: [u8; 32] = dep::std::hash::sha256("hello world".as_bytes());

    /* COMMENT-OUT ONE OF THESE CALLS TO `main`. */
    /* ATTEMPT 1 */
    // This will work after https://github.com/noir-lang/noir/pull/6450
    //    main(hash, signature);
    /* ATTEMPT 2 */
    // This succeeds:
    let params_tuple: (bool, [Field; 18], [Field; 18]) =
        (has_multiplicative_inverse, modulus_limbs, redc_limbs);

    main(hash, signature_limbs, params_tuple);
}
