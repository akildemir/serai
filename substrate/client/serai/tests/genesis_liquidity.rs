use std::{collections::HashMap, time::Duration, u64};

use rand_core::{RngCore, OsRng};

use sp_core::{Pair as _, sr25519::Pair};

use serai_client_serai::{
  Serai,
  abi::{
    primitives::{
      BlockHash,
      coin::ExternalCoin,
      address::SeraiAddress,
      balance::{ExternalBalance, Amount},
      network_id::{ExternalNetworkId, NetworkId},
      instructions::{InInstructionWithBalance, InInstruction, Batch},
      validator_sets::ValidatorSet,
      genesis_liquidity::GenesisValues,
    },
    Call, Transaction,
    genesis_liquidity::Call as GenesisLiquidityCall,
  },
};

mod common;
use common::{provide_batch, publish_tx, musig_sign, wait_until_genesis_block_completed};

pub async fn set_up_genesis(serai: &Serai) {
  // make accounts with amounts
  let mut accounts = HashMap::new();
  for coin in ExternalCoin::all() {
    // make 5 accounts per coin
    let mut amounts = vec![];
    for i in 0 .. 5 {
      let address = if i == 0 {
        SeraiAddress([
          78, 8, 16, 157, 111, 15, 126, 163, 155, 125, 161, 74, 246, 71, 181, 89, 252, 91, 42, 241,
          182, 122, 43, 61, 42, 63, 64, 122, 199, 214, 8, 93,
        ])
      } else {
        let mut address = SeraiAddress([0u8; 32]);
        OsRng.fill_bytes(&mut address.0);
        address
      };

      let one_coin = 10u64.pow(coin.decimals());
      let amount = one_coin + OsRng.next_u64() % (10 * one_coin);
      amounts.push((address, Amount(amount)));
    }
    accounts.insert(coin, amounts);
  }

  // send a batch per coin
  let mut batch_ids: HashMap<ExternalNetworkId, u32> = HashMap::new();
  for coin in ExternalCoin::all() {
    // set up instructions
    let instructions = accounts[&coin]
      .iter()
      .map(|(addr, amount)| InInstructionWithBalance {
        instruction: InInstruction::GenesisLiquidity(*addr),
        balance: ExternalBalance { coin, amount: *amount },
      })
      .collect::<Vec<_>>();

    // set up bloch hash
    let mut external_network_block_hash = BlockHash([0; 32]);
    OsRng.fill_bytes(&mut external_network_block_hash.0);

    // set up batch id
    batch_ids
      .entry(coin.network())
      .and_modify(|v| {
        *v += 1;
      })
      .or_insert(0);

    let mut batch =
      Batch::new(coin.network(), batch_ids[&coin.network()], external_network_block_hash);
    for i in instructions {
      batch.push_instruction(i).unwrap();
    }

    provide_batch(serai, batch).await;
  }

  // set oraclization values
  let values = GenesisValues { ether: Amount(3097630), dai: Amount(1417), monero: Amount(488472) };
  set_values(serai, values).await;
}

async fn set_values(serai: &Serai, values: GenesisValues) {
  let aux_keys = Pair::from_string("//Alice", None).unwrap();
  let session =
    serai.state().await.unwrap().current_session(NetworkId::Serai).await.unwrap().unwrap();
  let set = ValidatorSet { session, network: NetworkId::Serai };

  let signature = musig_sign(set.into(), &[aux_keys], &values.oraclize_values_message());
  let mut signature_participants = bitvec::vec::BitVec::new();
  signature_participants.push(true);

  // oraclize values
  let _ = publish_tx(
    serai,
    &Transaction::Unsigned {
      call: Call::GenesisLiquidity(GenesisLiquidityCall::oraclize_values {
        values,
        signature_participants: signature_participants.try_into().unwrap(),
        signature,
      })
      .try_into()
      .unwrap(),
    },
  )
  .await;
}

#[tokio::test]
async fn genesis_liquidity() {
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

      wait_until_genesis_block_completed(&serai).await;
      set_up_genesis(&serai).await;

      // assert that genesis state is completed now
      assert!(serai.state().await.unwrap().genesis_completed().await.unwrap());

      println!("test is complete. Waiting forever..");
      tokio::time::sleep(Duration::from_secs(u64::MAX)).await;
    })
    .await;
}
