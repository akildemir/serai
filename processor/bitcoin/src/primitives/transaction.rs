use std::io;

use rand_core::{RngCore, CryptoRng};

use ciphersuite_kp256::Secp256k1;
use frost::{dkg::ThresholdKeys, sign::PreprocessMachine};

use bitcoin_serai::{
  bitcoin::{
    consensus::{Encodable as _, Decodable as _},
    ScriptBuf, Transaction as BTransaction,
  },
  wallet::{
    ReceivedOutput, TransactionError, SignableTransaction as BSignableTransaction,
    TransactionMachine,
  },
};

use borsh::{BorshSerialize, BorshDeserialize};

use serai_client_bitcoin::Address;

use crate::output::OutputId;

#[derive(Clone, Debug)]
pub(crate) struct Transaction(pub(crate) BTransaction);

impl From<BTransaction> for Transaction {
  fn from(tx: BTransaction) -> Self {
    Self(tx)
  }
}

impl scheduler::Transaction for Transaction {
  fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    let tx =
      BTransaction::consensus_decode(&mut io::BufReader::new(reader)).map_err(io::Error::other)?;
    Ok(Self(tx))
  }
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    let mut writer = io::BufWriter::new(writer);
    self.0.consensus_encode(&mut writer)?;
    writer.into_inner()?;
    Ok(())
  }
}

#[derive(Clone, Debug)]
pub(crate) struct SignableTransaction {
  pub(crate) inputs: Vec<ReceivedOutput>,
  pub(crate) payments: Vec<(ScriptBuf, u64)>,
  pub(crate) change: Option<Address>,
  pub(crate) fee_per_vbyte: u64,
}

impl SignableTransaction {
  fn signable(self) -> Result<BSignableTransaction, TransactionError> {
    BSignableTransaction::new(
      &self.inputs,
      &self.payments,
      self.change.map(ScriptBuf::from),
      None,
      self.fee_per_vbyte,
    )
  }
}

#[derive(Clone)]
pub(crate) struct ClonableTransctionMachine(SignableTransaction, ThresholdKeys<Secp256k1>);
impl PreprocessMachine for ClonableTransctionMachine {
  type Preprocess = <TransactionMachine as PreprocessMachine>::Preprocess;
  type Signature = <TransactionMachine as PreprocessMachine>::Signature;
  type SignMachine = <TransactionMachine as PreprocessMachine>::SignMachine;

  fn preprocess<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
  ) -> (Self::SignMachine, Self::Preprocess) {
    self
      .0
      .signable()
      .expect("signing an invalid SignableTransaction")
      .multisig(&self.1)
      .expect("incorrect keys used for SignableTransaction")
      .preprocess(rng)
  }
}

impl scheduler::SignableTransaction for SignableTransaction {
  type Transaction = Transaction;
  type Ciphersuite = Secp256k1;
  type PreprocessMachine = ClonableTransctionMachine;

  fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    let inputs = {
      let mut input_len = [0; 4];
      reader.read_exact(&mut input_len)?;
      let mut inputs = vec![];
      for _ in 0 .. u32::from_le_bytes(input_len) {
        inputs.push(ReceivedOutput::read(reader)?);
      }
      inputs
    };

    let payments = Vec::<(Vec<u8>, u64)>::deserialize_reader(reader)?;
    let change = <_>::deserialize_reader(reader)?;
    let fee_per_vbyte = <_>::deserialize_reader(reader)?;

    Ok(Self {
      inputs,
      payments: payments
        .into_iter()
        .map(|(address, amount)| (ScriptBuf::from_bytes(address), amount))
        .collect(),
      change,
      fee_per_vbyte,
    })
  }
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    writer.write_all(&u32::try_from(self.inputs.len()).unwrap().to_le_bytes())?;
    for input in &self.inputs {
      input.write(writer)?;
    }

    // The payments are read as a borsh `Vec`, which is length-prefixed, so we prefix the length.
    writer.write_all(&u32::try_from(self.payments.len()).unwrap().to_le_bytes())?;
    for payment in &self.payments {
      (payment.0.as_script().as_bytes(), payment.1).serialize(writer)?;
    }
    self.change.serialize(writer)?;
    self.fee_per_vbyte.serialize(writer)?;

    Ok(())
  }

  fn id(&self) -> [u8; 32] {
    self.clone().signable().unwrap().txid()
  }

  fn sign(self, keys: ThresholdKeys<Self::Ciphersuite>) -> Self::PreprocessMachine {
    ClonableTransctionMachine(self, keys)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn signable_transaction_serialization() {
    use scheduler::SignableTransaction as _;

    // A P2TR payment, as the first transaction to exercise this serialization had
    let p2tr_script = ScriptBuf::from_bytes([vec![0x51, 0x20], vec![0xe0; 32]].concat());
    let p2wpkh_script = ScriptBuf::from_bytes([vec![0x00, 0x14], vec![0x01; 20]].concat());

    let tx = SignableTransaction {
      inputs: vec![],
      payments: vec![(p2tr_script, 100_698_409), (p2wpkh_script, 10_000)],
      change: Some(
        Address::new(ScriptBuf::from_bytes([vec![0x51, 0x20], vec![0x02; 32]].concat())).unwrap(),
      ),
      fee_per_vbyte: 5,
    };

    let mut buf = vec![];
    tx.write(&mut buf).unwrap();
    let mut reader = buf.as_slice();
    let read = SignableTransaction::read(&mut reader).unwrap();
    assert!(reader.is_empty());

    assert!(read.inputs.is_empty());
    assert_eq!(read.payments, tx.payments);
    assert_eq!(read.change, tx.change);
    assert_eq!(read.fee_per_vbyte, tx.fee_per_vbyte);
  }
}

#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub(crate) struct Eventuality {
  pub(crate) txid: [u8; 32],
  pub(crate) singular_spent_output: Option<OutputId>,
}

impl primitives::Eventuality for Eventuality {
  type OutputId = OutputId;

  fn id(&self) -> [u8; 32] {
    self.txid
  }

  // We define the lookup as our ID since the resolving transaction only has a singular possible ID
  fn lookup(&self) -> Vec<u8> {
    self.txid.to_vec()
  }

  fn singular_spent_output(&self) -> Option<Self::OutputId> {
    self.singular_spent_output.clone()
  }

  fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    Self::deserialize_reader(reader)
  }
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    self.serialize(writer)
  }
}
