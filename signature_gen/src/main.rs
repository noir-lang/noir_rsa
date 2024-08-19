use num_bigint::BigUint;
use rsa::pkcs1v15::Signature;
use rsa::pkcs1v15::VerifyingKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::env;

use rand;
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

use noir_bignum_paramgen::{bn_limbs, bn_runtime_instance};

fn generate_2048_bit_signature_parameters(msg: &str) {
    let mut hasher = Sha256::new();
    hasher.update(msg.as_bytes());
    let hashed_message = hasher.finalize();

    let hashed_as_bytes = hashed_message
        .iter()
        .map(|&b| b.to_string())
        .collect::<Vec<String>>()
        .join(", ");

    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
    let bits: usize = 2048;
    let priv_key: RsaPrivateKey =
        RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key: RsaPublicKey = priv_key.clone().into();

    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(priv_key);
    let sig: Vec<u8> = signing_key.sign(msg.as_bytes()).to_vec();

    let sig_bytes = &Signature::try_from(sig.as_slice()).unwrap().to_bytes();

    let sig_uint: BigUint = BigUint::from_bytes_be(sig_bytes);

    let sig_str = bn_limbs(sig_uint.clone(), 2048);
    println!("let hash: [u8; 32] = [{}];", hashed_as_bytes);
    println!(
        "let signature: BN2048 = BigNum::from_array({});",
        sig_str.as_str()
    );

    let r = bn_runtime_instance(pub_key.n().clone(), 2048, String::from("BNInstance"));

    println!("{}", r.as_str());
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let msg = if args.len() > 1 {
        &args[1]
    } else {
        "hello world"
    };

    generate_2048_bit_signature_parameters(msg);
}

fn test_signature_generation_impl() {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key: RsaPublicKey = priv_key.clone().into();
    let text: &str = "hello world";
    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(priv_key);
    let sig: Vec<u8> = signing_key.sign(text.as_bytes()).to_vec();
    let verifying_key = VerifyingKey::<Sha256>::new(pub_key);

    let result = verifying_key.verify(
        text.as_bytes(),
        &Signature::try_from(sig.as_slice()).unwrap(),
    );
    result.expect("failed to verify");
}

#[test]
fn test_signature_generation() {
    test_signature_generation_impl();
}
