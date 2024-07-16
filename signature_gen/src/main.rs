 use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey, pkcs8, signature};
 use rsa::pkcs1v15::VerifyingKey;
 use rsa::pkcs1v15::Signature;
 use num_bigint::BigUint;
 use base64ct::{Base64, Encoding};
 use hex_literal::hex;
 use num_traits::FromPrimitive;
 use num_traits::ToPrimitive;
 use num_traits::Num;

 use rsa::errors::{Error, Result};
 use rsa::Pkcs1v15Sign;
 use sha1::{Digest, Sha1};
 use sha2::Sha256;
 use rsa::traits::{
    Decryptor, EncryptingKeypair, PublicKeyParts, RandomizedDecryptor, RandomizedEncryptor,
};

use rand;

const NUM_BITS: u64 = 2048;
const BITS_PER_LIMB: u64 = 120;
const NUM_LIMBS: u64 = (NUM_BITS / BITS_PER_LIMB) + ((NUM_BITS % BITS_PER_LIMB != 0) as u64);


fn get_modtest() -> BigUint {

    let limbs: [&str; 9] =
    ["e908724e0d28a1565511879e00f063", "58dea28d5112982c8ab8597d3e611f", "b115f9878acc910a47b41ac8d5f763", "c71b0a719c2283f710f86024737cee", "9ee9eb73e95b84f033af5217337427", "8fcab34c99cc2661dd57de15ae2110", "a38db8a829eec5550342f6f66334dc", "d7c4b32fd351a47d860fda1897330e", "98c92a33a0f33fd7"];
    let shift: BigUint = (BigUint::from(1 as u64) << BITS_PER_LIMB as usize);
    let mut result: BigUint = BigUint::from(0 as u64);
    for i in 0..9 {
        let idx = 8 - i;
        let limbstr = limbs[idx as usize];
        let r = BigUint::from_str_radix(limbstr, 16);
        let limb: BigUint = r.expect("uh oh?");
    
        result = result.clone() << BITS_PER_LIMB as usize;
        result = result.clone() + limb;
    }
    result
}

fn format_bignum(input: &[u8], msg: &str) {
    const NUM_LIMBS: u64 = NUM_BITS / BITS_PER_LIMB + (NUM_BITS % BITS_PER_LIMB != 0) as u64;
    let mut limbs: [[u8; 15]; NUM_LIMBS as usize] = [[0; 15]; NUM_LIMBS as usize];

    for i in 0..input.len() {
        let limb_num = i / 15;
        let limb_idx = i % 15;
        // internal limbs are big endian
        limbs[limb_num][14 - limb_idx] = input[i];
    }
    print!("{} = [", msg);
    for i in 0..NUM_LIMBS - 1 {
        print!("0x{}, ", hex::encode(&limbs[i as usize]));
    }
    println!("0x{}]", hex::encode(&limbs[NUM_LIMBS as usize - 1]));
}

fn format_bignum2(input: Vec<BigUint>, msg: &str) {

    print!("{}, [", msg);
    for i in 0..input.len() - 1 {
        let bytes = input[i].to_bytes_be();
        print!("0x{}, ", hex::encode(&bytes));
    }
    let bytes = input[input.len() - 1].to_bytes_be();
    println!("0x{}]", hex::encode(&bytes));
}

fn split_into_limbs(mut input: BigUint) -> Vec<BigUint> {
    let one = BigUint::from(1 as u64);
    let mask: BigUint = (one.clone() << BITS_PER_LIMB as usize) - one.clone();

    let mut r: Vec<BigUint> = Vec::new();
    for _ in 0..NUM_LIMBS {
        let slice = input.clone() & mask.clone();
        input = input.clone() >> BITS_PER_LIMB as usize;
        r.push(slice);
    }
    r
}

fn compute_double_modulus(modulus: BigUint) -> Vec<BigUint> {
    let double_modulus = modulus.clone() + modulus.clone();

    let shift = BigUint::from(1 as u64) << 120;
    let mut limbs = split_into_limbs(double_modulus);
    let num_limbs = limbs.len();
    limbs[0] += shift.clone();
    for i in 1..num_limbs - 1 {
        limbs[i] = limbs[i].clone() - BigUint::from(1 as u64) + shift.clone();
    }
    limbs[num_limbs - 1] = limbs[num_limbs - 1].clone() - BigUint::from(1 as u64);
    limbs
}

fn generate_2048_bit_signature_parameters() {
    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
    let bits: usize = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key: RsaPublicKey = priv_key.clone().into();

    
    let multiplicand = BigUint::new([1].to_vec()) << 4096;
    let barrett_reduction_parameter =  multiplicand / pub_key.n();

    let msg: &str = "hello world";

    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(priv_key);
    let sig: Vec<u8> = signing_key.sign(msg.as_bytes()).to_vec();

    let sig_bytes = &Signature::try_from(sig.as_slice()).unwrap().to_bytes();

    let sig_uint: BigUint = BigUint::from_bytes_be(sig_bytes);
    let sig_limbs = split_into_limbs(sig_uint.clone());

    let modulus_limbs = split_into_limbs(pub_key.n().clone());
    let double_modulus_limbs = compute_double_modulus(pub_key.n().clone());
    let redc_limbs = split_into_limbs(barrett_reduction_parameter.clone());

    format_bignum2(modulus_limbs, "modulus_2048: [Field; 18] =");
    format_bignum2(double_modulus_limbs, "double_modulus: [Field; 18] = ");
    format_bignum2(redc_limbs, "redc_param: [Field; 18] = ");
    format_bignum2(sig_limbs, "signature: [Field; 18] = ");

    // format_bignum(&pub_key.n().to_bytes_le(), "modulus");
    // format_bignum(&barrett_reduction_parameter.to_bytes_le(), "redc_param");
  //  println!("signature bytes = {:?}", sig_bytes);
}
 fn main() {
    generate_2048_bit_signature_parameters();

    // let modulus = get_modtest();
    // let modulus_limbs = split_into_limbs(modulus.clone());

    // let multiplicand = BigUint::new([1].to_vec()) << 2048;
    // let barrett_reduction_parameter =  multiplicand / modulus.clone();

    // let double_modulus_limbs = compute_double_modulus(modulus.clone());
    // let redc_limbs = split_into_limbs(barrett_reduction_parameter.clone());

    // format_bignum2(modulus_limbs, "modulus");
    // format_bignum2(double_modulus_limbs, "double_modulus");
    // format_bignum2(redc_limbs, "redc_param");
 }

 fn testing() {
     let mut rng = rand::thread_rng();
     let bits = 2048;
     let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
     let pub_key: RsaPublicKey = priv_key.clone().into();
     println!("pub key = {:x?}", pub_key);
     let foobar = pub_key.n().to_str_radix(16);

     let pubkey_n: &BigUint = pub_key.n();
     let mulx = BigUint::new([1].to_vec()) << 4096;
     let r =  mulx / pubkey_n;
     println!("test mul = {:?}", r.to_str_radix(16));
    // pubkey_n.mul()
     let text: &str = "hello world";
     println!("pubkey foobar = {:?}", foobar);

     
     let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(priv_key);
    let sig: Vec<u8> = signing_key.sign(text.as_bytes()).to_vec();
    let verifying_key = VerifyingKey::<Sha256>::new(pub_key);

//     let bytes: &[u8] = b"rsa4096"; // HACK - the criterion is that the signature has leading zeros.
//     let signature = signing_key.sign(bytes);
    let foo = Pkcs1v15Sign::new::<Sha256>();
    let result = verifying_key.verify(
        text.as_bytes(),
        &Signature::try_from(sig.as_slice()).unwrap(),
    );
    println!("sig? {:x?}", &Signature::try_from(sig.as_slice()).unwrap());
    println!("errm {:?}", result);
    result.expect("failed to verify");

//     let result = pub_key.verify(foo, &digest, sig);

    // let pub_key = RsaPublicKey::from(&priv_key);
    
    // // Encrypt
    // let data = b"hello world";
    // let enc_data = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &data[..]).expect("failed to encrypt");
    // assert_ne!(&data[..], &enc_data[..]);
    
    // // Decrypt
    // let dec_data = priv_key.decrypt(Pkcs1v15Encrypt, &enc_data).expect("failed to decrypt");
    // assert_eq!(&data[..], &dec_data[..]);
    test_verify_pkcs1v15();
    println!("Hello, world!");
    // println!("dec_data {:?}", dec_data);
}

// mod tests {
    use rsa::*;
    use rsa::signature::{
        hazmat::{PrehashSigner, PrehashVerifier},
        DigestSigner, DigestVerifier, Keypair, RandomizedDigestSigner, RandomizedSigner,
        SignatureEncoding, Signer, Verifier,
    };
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaCha8Rng,
    };
    use sha3::Sha3_256;
    
  //  use rsa::RsaPublicKey;
    


fn get_private_key() -> RsaPrivateKey {
    // In order to generate new test vectors you'll need the PEM form of this key:
    // -----BEGIN RSA PRIVATE KEY-----
    // MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
    // fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu
    // /ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWu
    // RTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/
    // EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7A
    // IU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlS
    // tAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V
    // -----END RSA PRIVATE KEY-----

    RsaPrivateKey::from_components(
        BigUint::from_str_radix("9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077", 10).unwrap(),
        BigUint::from_u64(65537).unwrap(),
        BigUint::from_str_radix("7266398431328116344057699379749222532279343923819063639497049039389899328538543087657733766554155839834519529439851673014800261285757759040931985506583861", 10).unwrap(),
        vec![
            BigUint::from_str_radix("98920366548084643601728869055592650835572950932266967461790948584315647051443",10).unwrap(),
            BigUint::from_str_radix("94560208308847015747498523884063394671606671904944666360068158221458669711639", 10).unwrap()
        ],
    ).unwrap()
}

fn test_verify_pkcs1v15() {
    let priv_key = get_private_key();

    let tests = [
        (
            "Test.\n",
            hex!(
                "a4f3fa6ea93bcdd0c57be020c1193ecbfd6f200a3d95c409769b029578fa0e33"
                "6ad9a347600e40d3ae823b8c7e6bad88cc07c1d54c3a1523cbbb6d58efc362ae"
            ),
            true,
        ),
        (
            "Test.\n",
            hex!(
                "a4f3fa6ea93bcdd0c57be020c1193ecbfd6f200a3d95c409769b029578fa0e33"
                "6ad9a347600e40d3ae823b8c7e6bad88cc07c1d54c3a1523cbbb6d58efc362af"
            ),
            false,
        ),
    ];
    let pub_key: RsaPublicKey = priv_key.into();

    for (text, sig, expected) in &tests {
        let digest = Sha1::digest(text.as_bytes()).to_vec();
        let result = pub_key.verify(Pkcs1v15Sign::new::<Sha1>(), &digest, sig);
        match expected {
            true => result.expect("failed to verify"),
            false => {
                result.expect_err("expected verifying error");
            }
        }
    }
}
// }

// fn sign_verify() {
//     use pkcs8::DecodePrivateKey;
//     use signature::Signer;

//     use rsa::pkcs1v15::SigningKey;
//     use rsa::pkcs1v15::VerifyingKey;

//     use rsa::RsaPrivateKey;
//     let mut rng = rand::thread_rng();
//     let bits = 2048;

//     let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
//     let pub_key = RsaPublicKey::from(&priv_key);

//     let signing_key = SigningKey::<sha2::Sha256>::new(priv_key);

//     let bytes: &[u8] = b"rsa4096"; // HACK - the criterion is that the signature has leading zeros.
//     let signature = signing_key.sign(bytes);

//     let verifying_key = VerifyingKey::<sha2::Sha256>::new(pub_key);

//     verifying_key.verify();
//     // let expected: &str = "029E365B60971D5A499FF5E1C288B954D3A5DCF52482CEE46DB90DC860B725A8D6CA031146FA156E9F17579BE6122FFB11DAC35E59B2193D75F7B31CE1442DDE7F4FF7885AD5D6080266E9A33BB4CEC93FCC2B6B885457A0ABF19E2DAA00876F694B37F535F119925CCCF9A17B90AE6CF39F07D7FEFBEECDF1B344C14B728196DDD154230BADDEDA5A7EFF373F6CD3EF6D41789572A7A068E3A252D3B7D5D706C6170D8CFDB48C8E738A4B3BFEA3E15716805E376EBD99EA09C6E82F3CFA13CEB23CD289E8F95C27F489ADC05AAACE8A9276EE7CED3B7A5C7264F0D34FF18CEDC3E91D667FCF9992A8CFDE8562F65FDDE1E06595C27E0F82063839A358C927B2";
//     // assert_eq!(format!("{}", signature), expected);
//     // assert_eq!(format!("{:x}", signature), expected.to_lowercase());
//     // assert_eq!(format!("{:X}", signature), expected);
//     // assert_eq!(signature.to_string(), expected);
// }