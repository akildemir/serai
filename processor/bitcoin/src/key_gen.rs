use std::collections::HashMap;

use ciphersuite::{group::GroupEncoding as _, *};
use dkg::{ThresholdKeys, Curves, Participant};

/// Secp256k1, and an elliptic curve defined over its scalar field (secq256k1).
pub struct Secp256k1;
impl Curves for Secp256k1 {
  type ToweringCurve = ciphersuite_kp256::Secp256k1;
  type EmbeddedCurve = secq256k1::Secq256k1;
  type EmbeddedCurveParameters = secq256k1::Secq256k1;
}

use crate::{primitives::x_coord_to_even_point, scan::scanner};

pub(crate) struct KeyGenParams;
impl key_gen::KeyGenParams for KeyGenParams {
  const ID: &'static str = "Bitcoin";

  type ExternalNetworkCiphersuite = Secp256k1;

  fn tweak_keys(
    keys: &mut ThresholdKeys<<Self::ExternalNetworkCiphersuite as Curves>::ToweringCurve>,
  ) {
    fn parity_byte(keys: &ThresholdKeys<<Secp256k1 as Curves>::ToweringCurve>) -> u8 {
      let key = keys.group_key().to_bytes();
      let key: &[u8] = key.as_ref();
      key[0]
    }
    if parity_byte(keys) == 3 {
      let params = keys.params();
      let interpolation = keys.interpolation().clone();
      let negated_secret_share = {
        let mut secret_share = keys.original_secret_share().clone();
        *secret_share = -*secret_share;
        secret_share
      };
      let negated_verification_shares = Participant::iter()
        .take(usize::from(params.n()))
        .map(|l| (l, -keys.original_verification_share(l)))
        .collect::<HashMap<_, _>>();
      *keys = ThresholdKeys::new(
        params,
        interpolation,
        negated_secret_share,
        negated_verification_shares,
      )
      .expect("negating valid keys yielded invalid keys");
    }
    assert_eq!(parity_byte(keys), 2, "group key didn't have an even y coordinate after tweaking");

    // Create a scanner to assert these keys, and all expected paths, are usable
    scanner(keys.group_key());
  }

  fn encode_key(
    key: <<Self::ExternalNetworkCiphersuite as Curves>::ToweringCurve as WrappedGroup>::G,
  ) -> Vec<u8> {
    let key = key.to_bytes();
    let key: &[u8] = key.as_ref();
    // Skip the parity encoding as we know this key is even
    key[1 ..].to_vec()
  }

  fn decode_key(
    key: &[u8],
  ) -> Option<<<Self::ExternalNetworkCiphersuite as Curves>::ToweringCurve as WrappedGroup>::G> {
    x_coord_to_even_point(key)
  }
}
