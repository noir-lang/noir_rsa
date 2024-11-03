use bignum::RuntimeBigNum;

pub struct RSA<BN, let NumLibs: u32, let NumBytes: u32> {}

pub(crate) type BN1024 = RuntimeBigNum<9, 1024>;
pub(crate) type BN2048 = RuntimeBigNum<18, 2048>;

pub(crate) type RSA1024 = RSA<BN1024, 9, 128>;
pub(crate) type RSA2048 = RSA<BN2048, 18, 256>;
