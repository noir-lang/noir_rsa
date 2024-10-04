use dep::bignum::BigNum;
use dep::bignum::runtime_bignum::BigNumInstance;
use dep::bignum::fields::Params2048;
use dep::bignum::fields::Params1024;

struct RSA<BN, BNInstance, let NumBytes: u32>{}

type BN1024 = BigNum<9, Params1024>;
type BN2048 = BigNum<18, Params2048>;
type BNInst1024 = BigNumInstance<9, Params1024>;
type BNInst2048 = BigNumInstance<18, Params2048>;

type RSA1024 = RSA<BN1024, BNInst1024, 128>;
type RSA2048 = RSA<BN2048, BNInst2048, 256>;
