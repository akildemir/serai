use zeroize::Zeroize;

use sha2::{Digest, Sha256};

use group::ff::{Field, PrimeField};

use elliptic_curve::{
  generic_array::GenericArray,
  bigint::{Encoding, U384},
  hash2curve::{Expander, ExpandMsg, ExpandMsgXmd},
};

use crate::Ciphersuite;

macro_rules! kp_curve {
  (
    $feature: literal,
    $lib:     ident,

    $Ciphersuite: ident,
    $ID:          literal
  ) => {
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
    pub struct $Ciphersuite;
    impl Ciphersuite for $Ciphersuite {
      type F = $lib::Scalar;
      type G = $lib::ProjectivePoint;
      type H = Sha256;

      const ID: &'static [u8] = $ID;

      fn generator() -> Self::G {
        $lib::ProjectivePoint::GENERATOR
      }

      fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
        // Handle dsts which are greater than 255 bytes
        let mut dst = dst;
        let oversize = Sha256::digest([b"H2C-OVERSIZE-DST-".as_ref(), dst].concat());
        if dst.len() > 255 {
          dst = oversize.as_ref();
        }

        // While one of these two libraries does support directly hashing to the Scalar field, the
        // other doesn't. While that's probably an oversight, this is a universally working method

        // This method is from
        // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html
        // Specifically, Section 5

        // While that draft, overall, is intended for hashing to curves, that necessitates
        // detailing how to hash to a finite field. The draft comments that its mechanism for
        // doing so, which it uses to derive field elements, is also applicable to the scalar field

        // Unfortunately, there's currently no test vectors for this, despite them being requested
        // in https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/issues/343

        // The hash_to_field function is intended to provide unbiased values
        // In order to do so, a wide reduction from an extra k bits is applied, minimizing bias to
        // 2^-k
        // k is intended to be the bits of security of the suite, which is 128 for secp256k1 and
        // P-256
        const K: usize = 128;

        // L is the amount of bytes of material which should be used in the wide reduction
        // The 256 is for the bit-length of the primes, rounded up to the nearest byte threshold
        // This is a simplification of the formula from the end of section 5
        const L: usize = (256 + K) / 8; // 48

        // In order to perform this reduction, we need to use 48-byte numbers
        // First, convert the modulus to a 48-byte number
        // This is done by getting -1 as bytes, parsing it into a U384, and then adding back one
        let mut modulus = [0; L];
        // The byte repr of scalars will be 32 big-endian bytes
        // Set the lower 32 bytes of our 48-byte array accordingly
        modulus[16 ..].copy_from_slice(&(Self::F::zero() - Self::F::one()).to_bytes());
        let modulus = U384::from_be_slice(&modulus).wrapping_add(&U384::ONE);

        // The defined P-256 and secp256k1 ciphersuites both use expand_message_xmd
        let mut wide = U384::from_be_bytes({
          let mut bytes = [0; 48];
          ExpandMsgXmd::<Sha256>::expand_message(&[msg], dst, 48).unwrap().fill_bytes(&mut bytes);
          bytes
        })
        .reduce(&modulus)
        .unwrap()
        .to_be_bytes();

        // Now that this has been reduced back to a 32-byte value, grab the lower 32-bytes
        let mut array = *GenericArray::from_slice(&wide[16 ..]);
        let res = $lib::Scalar::from_repr(array).unwrap();

        // Zeroize the temp values we can due to the possibility hash_to_F is being used for nonces
        wide.zeroize();
        array.zeroize();
        res
      }
    }
  };
}

#[cfg(feature = "secp256k1")]
kp_curve!("secp256k1", k256, Secp256k1, b"secp256k1");
#[cfg(feature = "secp256k1")]
#[test]
fn test_secp256k1() {
  ff_group_tests::group::test_prime_group_bits::<k256::ProjectivePoint>();

  // Ideally, a test vector from hash to field (not FROST) would be here
  // Unfortunately, the IETF draft only provides vectors for field elements, not scalars
  assert_eq!(
    Secp256k1::hash_to_F(
      b"FROST-secp256k1-SHA256-v11nonce",
      &hex::decode(
        "\
80cbea5e405d169999d8c4b30b755fedb26ab07ec8198cda4873ed8ce5e16773\
08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c"
      )
      .unwrap()
    )
    .to_repr()
    .iter()
    .cloned()
    .collect::<Vec<_>>(),
    hex::decode("acc83278035223c1ba464e2d11bfacfc872b2b23e1041cf5f6130da21e4d8068").unwrap()
  );
}

#[cfg(feature = "p256")]
kp_curve!("p256", p256, P256, b"P-256");
#[cfg(feature = "p256")]
#[test]
fn test_p256() {
  ff_group_tests::group::test_prime_group_bits::<p256::ProjectivePoint>();

  assert_eq!(
    P256::hash_to_F(
      b"FROST-P256-SHA256-v11nonce",
      &hex::decode(
        "\
f4e8cf80aec3f888d997900ac7e3e349944b5a6b47649fc32186d2f1238103c6\
0c9c1a0fe806c184add50bbdcac913dda73e482daf95dcb9f35dbb0d8a9f7731"
      )
      .unwrap()
    )
    .to_repr()
    .iter()
    .cloned()
    .collect::<Vec<_>>(),
    hex::decode("f871dfcf6bcd199342651adc361b92c941cb6a0d8c8c1a3b91d79e2c1bf3722d").unwrap()
  );
}
