use dep::bignum::BigNum;
use dep::bignum::fields::{Params1024, Params2048};
use dep::bignum::runtime_bignum::BigNumInstance;

pub struct RSA<BN, BNInstance, let NumBytes: u32> {}

pub(crate) type BN1024 = BigNum<9, Params1024>;
pub(crate) type BN2048 = BigNum<18, Params2048>;
pub(crate) type BNInst1024 = BigNumInstance<9, Params1024>;
pub(crate) type BNInst2048 = BigNumInstance<18, Params2048>;

pub(crate) type RSA1024 = RSA<BN1024, BNInst1024, 128>;
pub(crate) type RSA2048 = RSA<BN2048, BNInst2048, 256>;
