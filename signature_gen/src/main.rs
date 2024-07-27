use num_bigint::BigUint;
use rsa::pkcs1v15::Signature;
use rsa::{RsaPrivateKey, RsaPublicKey};

use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use sha2::Sha256;

use noir_bignum_paramgen::{bn_limbs, bn_runtime_instance};

fn generate_2048_bit_signature_parameters() {
    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
    let bits: usize = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key: RsaPublicKey = priv_key.clone().into();

    let msg: &str = "hello world";

    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(priv_key);
    let sig: Vec<u8> = signing_key.sign(msg.as_bytes()).to_vec();

    let sig_bytes = &Signature::try_from(sig.as_slice()).unwrap().to_bytes();

    let sig_uint: BigUint = BigUint::from_bytes_be(sig_bytes);

    let sig_str = bn_limbs(sig_uint.clone(), 2048);
    println!(
        "let signature: BigNum<18, Params2048> = BigNum::from_array({});",
        sig_str.as_str()
    );

    let r = bn_runtime_instance(pub_key.n().clone(), 2048, String::from("BNInstance"));
    println!("{}", r.as_str());
}

fn main() {
    generate_2048_bit_signature_parameters();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use rsa::pkcs1v15::Signature;
    use rsa::signature::{Signer, Verifier};
    use rsa::{pkcs1v15::VerifyingKey, RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;

    #[test]
    fn test_signature_generation() {
        let mut rng = thread_rng();
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
}
