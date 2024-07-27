# noir_rsa

Optimized Noir library that evaluates RSA signatures.

Uses https://github.com/zac-williamson/noir-bignum as a dependency.

NOTE: library is experimental and currently will only compile using the nightly build of noir (as of 15 July 2024)

# Usage

See tests in `lib.nr` for examples.

To construct a `BigNumInstance` objects, both the bignum modulus (the public key) and a Barrett reduction parameter are required as arrays of Field elements, with each element representing a 120-bit slice of the number.

See `signature_gen/src/main.rs` for how these parameters can be derived. The rust crate `noir-bignum-paramgen` contains both libraries and an executable that performs this formatting (https://crates.io/crates/noir-bignum-paramgen).

## Example Use

See tests in `lib.nr` for additional examples. The `pubkey_redc_param` parameter can be derived via the `noir-bignum-paramgen` tool and provided as a witness via Prover.toml

```rust
    use dep::noir_rsa::bignum::BigNum;
    use dep::noir_rsa::bignum::runtime_bignum::BigNumInstance;
    use dep::noir_rsa::bignum::fields::Params2048;
    use dep::noir_rsa::RSA;

    type BN2048 = BigNum<18, Params2048>;
    type BNInstance = BigNumInstance<18, Params2048>;
    type RSA2048 = RSA<BN2048, BNInstance, 256>;

    fn verify_signature(pubkey: [u8; 256], signature: [u8; 256], pubkey_redc_param: BN2048)
        let sha256_hash: [u8; 32] = dep::std::hash::sha256("hello world".as_bytes());
        let modulus: BN2048 = BigNum::from_byte_be(pubkey);
        let signature: BN2048 = BigNum::from_byte_be(signature);

        let instance: BNInstance = BigNumInstance::new(modulus, pubkey_redc_param);

        let rsa: RSA2048 = RSA {};
        assert(rsa.verify_sha256_pkcs1v15(BNInstance, sha256_hash, signature));
    }
```

# Costs

Rough cost:

- 2,048 bit RSA: 26,888 gates per verification
- 1,024 bit RSA: 11,983 gates per verification

A circuit that verifies 1 signature (and does nothing else) will cost ~32k due to initialization costs of lookup tables
