# noir_rsa

Optimized Noir library that evaluates RSA signatures.

This library uses https://github.com/zac-williamson/noir-bignum as a dependency.

## Benchmarks

We ran a benchmark to measure the number of gates of the circuit, the proving time and the verification time of the RSA verification. The benchmark includes two main scenarios: the signature verification of one signature and 10 different signatures. For both scenarios, we reported all the metrics mentioned above.

On the one hand, the number of gates is measured using the `bb gates` command. On the other hand, the timing measures are taken using the `hyperfine` command line tool which takes the average of ten executions of the proving and verification commands. These averages are the ones reported in the results presented here.

The results for the verification of one signature are the following:

| **Bit length** | **Circuit size** | **Avg. proving time (BB) [ms]** | **Avg. verification time (BB) [ms]** | **Avg. proving time (UH) [ms]** | **Avg. verification time (UH) [ms]** |
|----------------|------------------|---------------------------------|--------------------------------------|---------------------------------|--------------------------------------|
|           1024 |             2204 |                           234.8 |                                 33.2 |                             181 |                                 37.1 |
|           2048 |             7131 |                           345.6 |                                 32.7 |                           261.9 |                                 36.4 |

On the other hand, the results for the verification of 10 signatures are the following:

| **Bit length** | **Circuit size** | **Avg. proving time (BB) [ms]** | **Avg. verification time (BB) [ms]** | **Avg. proving time (UH) [ms]** | **Avg. verification time (UH) [ms]** |
|----------------|------------------|---------------------------------|--------------------------------------|---------------------------------|--------------------------------------|
|           1024 |            21516 |                           970.9 |                                 32.3 |                           514.4 |                                 36.7 |
|           2048 |            63821 |                          1801.7 |                                 32.3 |                           964.2 |                                   37 |

### Costs

Rough cost:

- 2,048 bit RSA: 26,888 gates per verification
- 1,024 bit RSA: 11,983 gates per verification

A circuit that verifies 1 signature (and does nothing else) will cost ~32k due to initialization costs of lookup tables

## Dependencies

- Noir ≥v0.32.0
- Barretenberg ≥v0.46.1

Refer to [Noir's docs](https://noir-lang.org/docs/getting_started/installation/) and [Barretenberg's docs](https://github.com/AztecProtocol/aztec-packages/blob/master/barretenberg/cpp/src/barretenberg/bb/readme.md#installation) for installation steps.

## Installation

In your _Nargo.toml_ file, add the version of this library you would like to install under dependency:

```
[dependencies]
noir_rsa = { tag = "v0.2", git = "https://github.com/noir-lang/noir_rsa" }
```

## Usage

See tests in `lib.nr` for examples.

### Parameters

#### RSA signature

To verify an RSA signature, you first need a signature.

Depending on the application you are building, you might be expecting user signatures from existing signing services (e.g. emails, passports, git commits), or you might be building the ability for users to sign directly in your application.

Either way, you are free to choose how you collect / generate the signatures as long as they comply with the PKCS#1 v1.5 RSA cryptography specifications.

An example of how to generate a PKCS#1 v1.5 signature in Rust: https://docs.rs/rsa/latest/rsa/#pkcs1-v15-signatures

#### Parse for Noir RSA

Once you have gathered the RSA signature, you will need to parse it to a compatible format with this Noir RSA library.

The rust crate `noir-bignum-paramgen` contains both libraries and an executable that performs this formatting (https://crates.io/crates/noir-bignum-paramgen). See `signature_gen/src/main.rs` for how these parameters can be derived.

To construct a `BigNumInstance` objects, both the bignum modulus (the public key) and a Barrett reduction parameter are required as arrays of Field elements, with each element representing a 120-bit slice of the number.

### End-to-end example

#### 1. Generate RSA signature

TODO

#### 2. Parse parameters for Noir RSA

The `pubkey_redc_param` parameter can be derived via the `noir-bignum-paramgen` tool and provided as a witness via Prover.toml

TODO

#### 3. Verify signature in Noir

See tests in `lib.nr` for additional examples.

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
