use dep::bignum::BigNum;
use dep::bignum::runtime_bignum::BigNumInstance;
use dep::std;

use dep::rsa::types::{RSA, RSA2048, BN2048, BNInst2048};

fn main(bn: [[Field; 18]; 2], hash: [u8; 32], signature: BN2048) {
    let rsa: RSA2048 = RSA {};

    let BNInstance: BNInst2048 = BigNumInstance::new(bn[0], bn[1]);

    assert(rsa.verify_sha256_pkcs1v15(BNInstance, hash, signature));
}

#[test]
fn test_main() {
    // Output of `cargo run -- "hello world"` in the `signature_gen` directory
    let hash: [u8; 32] = [
        14, 191, 119, 204, 204, 105, 178, 189, 13, 235, 67, 77, 193, 200, 22, 100, 15, 133, 90, 42, 236, 139, 97, 242, 214, 182, 3, 247, 46, 101, 91, 137
    ];
    let signature: BN2048 = BigNum::from_array(
        [
        0x58a652a880f069215a69ad24a0c3e3, 0x2f5e824cfc7994ad2207d760ce6b0b, 0xc46f7aef8f118c6a3db00441f43bdb, 0x6b828556d69b102db711b438408a21, 0x89169cfcdefa181f14673adfa8beaf, 0x3dc5a6504580eb0e483d65e4f077aa, 0xe3055308aab899fd4b745c46133edc, 0xd15dbf592eda031689735d6c23abdc, 0x1381995315d49df1e37f51722c2f0f, 0x588a569c2bfbb8ca36c9a91f26641b, 0x4ed49c7896eec8e55cc365ea661afc, 0xa1bbd9ca400c8a4e53f4e1bd80682a, 0xa9b87252c1556d3d4ab166350d6017, 0x8dcfd412cd743ff56705b44a044bdf, 0x3e5a75b2fcfaf57666cdc6528c2752, 0x8fd558955a580b899740ba6e4f0c3e, 0x988a12f6db3d7ee4af8f761892b604, 0xd2
    ]
    );
    let bn = [
        [
            0x9caae9551eeffa3bc6c21e6b5a9c73, 0xffb542d0a5dbf4abaf0f4216f8a5c7, 0x2f26109fdef9efc07ec67598b1565d, 0x41e55a4b7f7100ca3e795ec30a0a6c, 0x334fbad0abbe2cfadaa60ec35696ab, 0x9a3ec7ea7f3a715756614902354e88, 0xb6345d342acc576570c00fbb047cc1, 0xdd801ea95a28cdea173b210c69545d, 0xf5789a44070e34a72229853c77591e, 0x56825d3786c04ce6c4956dccdb5871, 0x555bbc2679a8c869adcd16b97082fd, 0xb550ea3b9ab4165b60389a2fb46e1b, 0xc4c9b5fc49fe9f68ea23d829e24ed0, 0x9f5d00160f2f2478ccb82a3c4d481d, 0x879e67a7a1c9cda9207fb8a1c27b23, 0x69308ffa13ccf5a9d808bfb20f59cf, 0xedf2cc1edbc609f21c32c37ecd59fd, 0xc4
        ],
        [
            0x22f8e96ac7a22671d445f34bd8b128, 0xe33ff1dcde5c8c77be4310988e0eb0, 0x12cc7346bce9dbd41e8831623fb222, 0xb6959ea618f3f2170c18709130aa64, 0x78eab64848073b586c2e171b58cd5c, 0x13d1f1aec7f75d9f95412f9eca6ac4, 0x4d0a334095ac776ae249977b33297b, 0x38ac4d99e9a386705f9c1b1413cdb3, 0x88eadda0a791f1afee7edebc19452f, 0xabd6209133a060d57fd2baebf34b5e, 0xd206f3e180e46564c78e2985142860, 0xf976700427b1fc5d77053cb62e572b, 0x3528f5879b9b422b94b411a41733fc, 0x9af5baae725ea206d4163de6dbeb9f, 0xbc162e72e3362c02f87f9367390ee8, 0x72faa2f9e7baa82c7daf371f83de48, 0xca06f9c01ce5451f279f8ac006ee65, 0x14c
        ]
    ];
    main(bn, hash, signature);
}
