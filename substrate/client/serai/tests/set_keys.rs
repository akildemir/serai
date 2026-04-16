use rand_core::{RngCore as _, OsRng};

use sp_core::{Pair as _, sr25519::Pair};

use serai_client_serai::{
  abi::{
    primitives::{
      crypto::{Public, EmbeddedEllipticCurveKeys, ExternalKey, KeyPair},
      network_id::ExternalNetworkId,
      validator_sets::{Session, ExternalValidatorSet},
    },
    validator_sets::Event as ValidatorSetsEvent,
  },
};

mod common;
use common::{set_keys, wait_until_genesis_block_completed};

#[tokio::test]
async fn test_set_keys() {
  let mut test = dockertest::DockerTest::new();
  let (composition, handle) = serai_substrate_tests::composition(
    "alice",
    serai_docker_tests::fresh_logs_folder(true, "serai-client/set_keys"),
  );
  test.provide_container(
    composition
      .replace_cmd(["serai-node", "--network", "solo"].into_iter().map(str::to_owned).collect())
      .replace_env([("RUST_LOG".to_owned(), "runtime=debug".to_owned())].into()),
  );

  test
    .run_async(async |ops| {
      let serai = serai_substrate_tests::rpc(&ops, handle).await;

      // wait until we go past the genesis block
      wait_until_genesis_block_completed(&serai).await;

      let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
      let aux_keys = Pair::from_string("//Alice", None).unwrap();
      {
        let mut found = false;
        let genesis_block = serai.block_by_number(0).await.unwrap().unwrap();
        let events = serai.events(genesis_block.header.hash()).await.unwrap();
        for event in events.validator_sets().set_embedded_elliptic_curve_keys_events() {
          if let ValidatorSetsEvent::SetEmbeddedEllipticCurveKeys {
            validator: _,
            keys: EmbeddedEllipticCurveKeys::Serai(key),
          } = event
          {
            assert_eq!(*key, <[u8; 32]>::from(aux_keys.public()));
            found = true;
          }
        }
        assert!(found);
      }

      let key_pair = KeyPair(
        {
          let mut public = [0; 32];
          OsRng.fill_bytes(&mut public);
          Public(public)
        },
        {
          #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
          let mut external_key =
            vec![0; (OsRng.next_u64() as usize) % (ExternalKey::MAX_SIZE as usize)];
          OsRng.fill_bytes(&mut external_key);
          ExternalKey(external_key.try_into().unwrap())
        },
      );

      set_keys(&serai, set, key_pair, &[aux_keys]).await;
    })
    .await;
}
