# noir_rsa

Optimized Noir library that evaluates RSA signatures.

This library uses <https://github.com/zac-williamson/noir-bignum> as a dependency.

## Benchmarks

TODO

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

## End-to-end example

### Generate RSA signature

To verify an RSA signature, you first need a signature.

Depending on the application you are building, you might be expecting user signatures from existing signing services (e.g. emails, passports, git commits), or you might be building the ability for users to sign directly in your application.

Either way, you are free to choose how you collect / generate the signatures as long as they comply with the PKCS#1 v1.5 RSA cryptography specifications.

You need to install Rustup and run it in order to install Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup
```

Then clone this repo, move into the `signature_gen` folder, and run `cargo run`, optionally with the message to sign:

```bash
cd signature_gen
cargo run # or cargo run -- "hello world!"
```

The program prints the hash of the message, the RSA signature, and the BigNumber instance you should use.

#### Use it in your Noir test

Move into the `example` folder. Replace the hardcoded values with result of the previous step. Since you know the size of your key, you can import those types from the rsa lib:

```diff
-    let hash: [u8; 32] = etc...
-    let signature: BN2048 = etc...
-    let BNInstance: [[Field; 18]; 2] = etc...
+    let hash: [u8; 32] = paste from terminal...
+    let signature: BN2048 = paste from terminal...
+    let bn: [[Field; 18]; 2] = paste from terminal...
```

Run the test:

```bash
nargo test
```

#### Prove it

Run `nargo check` to initialize `Prover.toml`:

```bash
nargo check
```

Take the result of step 1 and make it in toml format. Example:

```toml
bn = [
    [
        "0xcba7415fa9d2192d5cdac144f95f75",
        "0x2b46305b91eeed9e9a992076172b46",
        "0x76c9e6e0a407e67bc0a3ee276927d7",
        "0x0d0eaa3b10ab266755ea20c44619f6",
        "0x4b040e9ab1acb761b1ab9a60309ee4",
        "...etc"
    ]
]
```

Then execute it, and prove it i.e. with barretenberg:

```bash
nargo execute rsa
bb prove -b ./target/example.json -w ./target/rsa.gz -o ./target/proof
```

### Verify it

To verify, we need to export the verification key:

```bash
bb write_vk -b ./target/example.json -o ./target/vk
```

And verify:

```bash
bb verify -k ./target/vk -p ./target/proof
```
