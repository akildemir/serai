use std::collections::HashMap;

use rand_core::OsRng;

use ciphersuite::{
  group::{ff::PrimeField, GroupEncoding},
  WrappedGroup, WithPreferredHash,
};
use dalek_ff_group::Ristretto;
use embedwards25519::Embedwards25519;
use secq256k1::Secq256k1;

use sp_core::{Pair as _, sr25519::Pair};

use dockertest::{
  LogAction, LogPolicy, LogSource, LogOptions, StartPolicy, TestBodySpecification, PullPolicy,
  Image,
};

use serai_client_serai::abi::primitives::network_id::ExternalNetworkId;

use crate::{RPC_USER, RPC_PASS};

// This is for test only.
fn insecure_arbitrary_key_from_name<C: WithPreferredHash>(name: &str) -> C::F {
  C::hash_to_F(&[b"insecure arbitrary key".as_slice(), name.as_bytes()].concat())
}

fn insecure_keypair_from_name(name: &str) -> Pair {
  Pair::from_string(&format!("//{name}"), None).unwrap()
}

pub fn coordinator_instance(
  name: &str,
  message_queue_key: <Ristretto as WrappedGroup>::F,
) -> TestBodySpecification {
  serai_docker_tests::build("coordinator".to_owned());

  TestBodySpecification::with_image(
    Image::with_repository("serai-dev-coordinator").pull_policy(PullPolicy::Never),
  )
  .replace_env(
    [
      ("MESSAGE_QUEUE_KEY".to_owned(), hex::encode(message_queue_key.to_repr())),
      ("DB_PATH".to_owned(), "./coordinator-db".to_owned()),
      ("SERAI_KEY".to_owned(), {
        hex::encode(&insecure_keypair_from_name(name).as_ref().secret.to_bytes()[.. 32])
      }),
      (
        "RUST_LOG".to_owned(),
        "serai_coordinator=trace,".to_owned() +
          "serai-coordinator-libp2p-p2p=trace," +
          "tributary_chain=trace," +
          "tendermint=trace",
      ),
    ]
    .into(),
  )
}

pub fn serai_composition(name: &str) -> TestBodySpecification {
  serai_docker_tests::build("serai".to_owned());
  TestBodySpecification::with_image(
    Image::with_repository("serai-dev-serai").pull_policy(PullPolicy::Never),
  )
  .replace_env(
    [("SERAI_NAME".to_owned(), name.to_lowercase()), ("KEY".to_owned(), " ".to_owned())].into(),
  )
  .set_publish_all_ports(true)
}

#[expect(dead_code)]
#[derive(Clone)]
pub struct EvrfPublicKeys {
  substrate: [u8; 32],
  network: Vec<u8>,
}

pub fn processor_instance(
  name: &str,
  network: ExternalNetworkId,
  port: u32,
  message_queue_key: <Ristretto as WrappedGroup>::F,
) -> (Vec<TestBodySpecification>, EvrfPublicKeys) {
  let substrate_evrf_key = insecure_arbitrary_key_from_name::<Embedwards25519>(name);
  let substrate_evrf_pub_key = (Embedwards25519::generator() * substrate_evrf_key).to_bytes();
  let substrate_evrf_key = substrate_evrf_key.to_repr();

  let (network_evrf_key, network_evrf_pub_key) = match network {
    ExternalNetworkId::Bitcoin | ExternalNetworkId::Ethereum => {
      let evrf_key = insecure_arbitrary_key_from_name::<Secq256k1>(name);
      let pub_key = (Secq256k1::generator() * evrf_key).to_bytes().to_vec();
      (evrf_key.to_repr().as_ref().to_vec(), pub_key)
    }
    ExternalNetworkId::Monero => {
      let evrf_key = insecure_arbitrary_key_from_name::<Embedwards25519>(name);
      let pub_key = (Embedwards25519::generator() * evrf_key).to_bytes().to_vec();
      (evrf_key.to_repr().as_ref().to_vec(), pub_key)
    }
  };

  let network_str = match network {
    ExternalNetworkId::Bitcoin => "bitcoin",
    ExternalNetworkId::Ethereum => "ethereum",
    ExternalNetworkId::Monero => "monero",
  };
  let image = format!("{network_str}-processor");
  serai_docker_tests::build(image.clone());

  let mut res = vec![TestBodySpecification::with_image(
    Image::with_repository(format!("serai-dev-{image}")).pull_policy(PullPolicy::Never),
  )
  .replace_env(
    [
      ("MESSAGE_QUEUE_KEY".to_owned(), hex::encode(message_queue_key.to_repr())),
      ("SUBSTRATE_EVRF_KEY".to_owned(), hex::encode(substrate_evrf_key)),
      ("NETWORK_EVRF_KEY".to_owned(), hex::encode(network_evrf_key)),
      ("NETWORK".to_owned(), network_str.to_string()),
      ("NETWORK_RPC_LOGIN".to_owned(), format!("{RPC_USER}:{RPC_PASS}")),
      ("NETWORK_RPC_PORT".to_owned(), port.to_string()),
      ("DB_PATH".to_owned(), "./processor-db".to_owned()),
      (
        "RUST_LOG".to_owned(),
        "info,serai_processor=trace,serai_processor_key_gen=trace,messages=trace".to_owned(),
      ),
    ]
    .into(),
  )];

  if network == ExternalNetworkId::Ethereum {
    serai_docker_tests::build("ethereum-relayer".to_owned());
    res.push(
      TestBodySpecification::with_image(
        Image::with_repository("serai-dev-ethereum-relayer".to_owned())
          .pull_policy(PullPolicy::Never),
      )
      .replace_env(
        [
          ("DB_PATH".to_owned(), "./ethereum-relayer-db".to_owned()),
          ("RUST_LOG".to_owned(), "serai_ethereum_relayer=trace,".to_owned()),
        ]
        .into(),
      )
      .set_publish_all_ports(true),
    );
  }

  (res, EvrfPublicKeys { substrate: substrate_evrf_pub_key, network: network_evrf_pub_key })
}

const BTC_PORT: u32 = 8332;
const ETH_PORT: u32 = 8545;
const XMR_PORT: u32 = 18081;

pub fn network_instance(network: ExternalNetworkId) -> (TestBodySpecification, u32) {
  pub fn bitcoin_instance() -> (TestBodySpecification, u32) {
    serai_docker_tests::build("bitcoin".to_owned());

    let composition = TestBodySpecification::with_image(
      Image::with_repository("serai-dev-bitcoin").pull_policy(PullPolicy::Never),
    )
    .set_publish_all_ports(true);

    (composition, BTC_PORT)
  }

  pub fn ethereum_instance() -> (TestBodySpecification, u32) {
    serai_docker_tests::build("ethereum".to_owned());

    let composition = TestBodySpecification::with_image(
      Image::with_repository("serai-dev-ethereum").pull_policy(PullPolicy::Never),
    )
    .set_start_policy(StartPolicy::Strict)
    .set_publish_all_ports(true);
    (composition, ETH_PORT)
  }

  pub fn monero_instance() -> (TestBodySpecification, u32) {
    serai_docker_tests::build("monero".to_owned());

    let composition = TestBodySpecification::with_image(
      Image::with_repository("serai-dev-monero").pull_policy(PullPolicy::Never),
    )
    .set_start_policy(StartPolicy::Strict)
    .set_publish_all_ports(true);
    (composition, XMR_PORT)
  }
  match network {
    ExternalNetworkId::Bitcoin => bitcoin_instance(),
    ExternalNetworkId::Ethereum => ethereum_instance(),
    ExternalNetworkId::Monero => monero_instance(),
  }
}

type MessageQueuePrivateKey = <Ristretto as WrappedGroup>::F;
pub fn message_queue_instance() -> (
  MessageQueuePrivateKey,
  HashMap<ExternalNetworkId, MessageQueuePrivateKey>,
  TestBodySpecification,
) {
  serai_docker_tests::build("message-queue".to_owned());

  let coord_key = <Ristretto as WrappedGroup>::F::random(&mut OsRng);
  let priv_keys = ExternalNetworkId::all()
    .map(|n| (n, <Ristretto as WrappedGroup>::F::random(&mut OsRng)))
    .collect::<HashMap<_, _>>();

  let composition = TestBodySpecification::with_image(
    Image::with_repository("serai-dev-message-queue").pull_policy(PullPolicy::Never),
  )
  .set_log_options(Some(LogOptions {
    action: LogAction::Forward,
    policy: LogPolicy::Always,
    source: LogSource::Both,
  }))
  .replace_env(
    [
      ("COORDINATOR_KEY".to_owned(), hex::encode((Ristretto::generator() * coord_key).to_bytes())),
      (
        "BITCOIN_KEY".to_owned(),
        hex::encode((Ristretto::generator() * priv_keys[&ExternalNetworkId::Bitcoin]).to_bytes()),
      ),
      (
        "ETHEREUM_KEY".to_owned(),
        hex::encode((Ristretto::generator() * priv_keys[&ExternalNetworkId::Ethereum]).to_bytes()),
      ),
      (
        "MONERO_KEY".to_owned(),
        hex::encode((Ristretto::generator() * priv_keys[&ExternalNetworkId::Monero]).to_bytes()),
      ),
      ("DB_PATH".to_owned(), "./message-queue-db".to_owned()),
      ("RUST_LOG".to_owned(), "serai_message_queue=trace,".to_owned()),
    ]
    .into(),
  )
  .set_publish_all_ports(true);

  (coord_key, priv_keys, composition)
}
