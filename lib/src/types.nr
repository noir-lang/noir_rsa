use dep::bignum::BigNum;
use dep::bignum::runtime_bignum::BigNumInstance;
use dep::bignum::fields::Params2048;
use dep::bignum::fields::Params1024;
use dep::bignum::fields::Params4096;
use dep::bignum::runtime_bignum::BigNumParamsTrait;

struct RSA<BN, BNInstance, let NumBytes: u32>{}

struct Params1025 {}
impl BigNumParamsTrait<9> for Params1025 {
    fn modulus_bits() -> u32 {
        1025
    }
}

struct Params1964 {}
impl BigNumParamsTrait<17> for Params1964 {
    fn modulus_bits() -> u32 {
        1964
    }
}

type BN1024 = BigNum<9, Params1024>;
type BN1025 = BigNum<9, Params1025>;
type BN1964 = BigNum<17, Params1964>;
type BN2048 = BigNum<18, Params2048>;
type BN4096 = BigNum<35, Params4096>;
type BNInst1024 = BigNumInstance<9, Params1024>;
type BNInst1025 = BigNumInstance<9, Params1025>;
type BNInst1964 = BigNumInstance<17, Params1964>;
type BNInst2048 = BigNumInstance<18, Params2048>;
type BNInst4096 = BigNumInstance<35, Params4096>;

type RSA1024 = RSA<BN1024, BNInst1024, 128>;
type RSA1025 = RSA<BN1025, BNInst1025, 129>;
type RSA1964 = RSA<BN1964, BNInst1964, 246>;
type RSA2048 = RSA<BN2048, BNInst2048, 256>;
type RSA4096 = RSA<BN4096, BNInst4096, 512>;
