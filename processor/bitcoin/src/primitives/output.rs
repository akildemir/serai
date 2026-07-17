use std::io;

use ciphersuite::{group::GroupEncoding as _, *};
use ciphersuite_kp256::Secp256k1;

use bitcoin_serai::{
  bitcoin::{hashes::Hash as _, consensus::Encodable as _, transaction::Transaction},
  wallet::ReceivedOutput as WalletOutput,
};

use borsh::{BorshSerialize, BorshDeserialize};
use serai_db::Get;

use serai_primitives::{
  coin::ExternalCoin,
  balance::{Amount, ExternalBalance},
  address::ExternalAddress,
};
use serai_client_bitcoin::Address;

use primitives::{OutputType, ReceivedOutput};

use crate::scan::{OFFSETS, presumed_origin, extract_serai_data};

#[derive(Clone, PartialEq, Eq, Hash, Debug, BorshSerialize, BorshDeserialize)]
pub(crate) struct OutputId([u8; 36]);
impl Default for OutputId {
  fn default() -> Self {
    Self([0; 36])
  }
}
impl AsRef<[u8]> for OutputId {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}
impl AsMut<[u8]> for OutputId {
  fn as_mut(&mut self) -> &mut [u8] {
    self.0.as_mut()
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Output {
  kind: OutputType,
  // The root key this output was scanned for.
  key: <Secp256k1 as WrappedGroup>::G,
  presumed_origin: Option<Address>,
  pub(crate) output: WalletOutput,
  data: Vec<u8>,
}

impl Output {
  pub(crate) fn new(
    getter: &impl Get,
    tx: &Transaction,
    output: WalletOutput,
    key: <Secp256k1 as WrappedGroup>::G,
  ) -> Self {
    Self {
      kind: OFFSETS
        .iter()
        .find_map(|(kind, offset)| (offset == &output.offset()).then_some(*kind))
        .expect("scanned output for unknown offset"),
      key,
      presumed_origin: presumed_origin(getter, tx),
      output,
      data: extract_serai_data(tx),
    }
  }

  pub(crate) fn new_with_presumed_origin(
    tx: &Transaction,
    presumed_origin: Option<Address>,
    output: WalletOutput,
    key: <Secp256k1 as WrappedGroup>::G,
  ) -> Self {
    Self {
      kind: OFFSETS
        .iter()
        .find_map(|(kind, offset)| (offset == &output.offset()).then_some(*kind))
        .expect("scanned output for unknown offset"),
      key,
      presumed_origin,
      output,
      data: extract_serai_data(tx),
    }
  }
}

impl ReceivedOutput<<Secp256k1 as WrappedGroup>::G, Address> for Output {
  type Id = OutputId;
  type TransactionId = [u8; 32];

  fn kind(&self) -> OutputType {
    self.kind
  }

  fn id(&self) -> Self::Id {
    let mut id = OutputId::default();
    self.output.outpoint().consensus_encode(&mut id.as_mut()).unwrap();
    id
  }

  fn transaction_id(&self) -> Self::TransactionId {
    let mut res = self.output.outpoint().txid.to_raw_hash().to_byte_array();
    res.reverse();
    res
  }

  fn key(&self) -> <Secp256k1 as WrappedGroup>::G {
    self.key
  }

  fn presumed_origin(&self) -> Option<Address> {
    self.presumed_origin.clone()
  }

  fn balance(&self) -> ExternalBalance {
    ExternalBalance { coin: ExternalCoin::Bitcoin, amount: Amount(self.output.value()) }
  }

  fn data(&self) -> &[u8] {
    &self.data
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    self.kind.write(writer)?;
    writer.write_all(self.key.to_bytes().as_ref())?;
    let presumed_origin: Option<ExternalAddress> = self.presumed_origin.clone().map(Into::into);
    presumed_origin.serialize(writer)?;
    self.output.write(writer)?;
    writer.write_all(&u16::try_from(self.data.len()).unwrap().to_le_bytes())?;
    writer.write_all(&self.data)
  }

  fn read<R: io::Read>(mut reader: &mut R) -> io::Result<Self> {
    Ok(Output {
      kind: OutputType::read(reader)?,
      key: Secp256k1::read_G(reader)?,
      presumed_origin: {
        Option::<ExternalAddress>::deserialize_reader(&mut reader)
          .map_err(|e| io::Error::other(format!("couldn't decode ExternalAddress: {e:?}")))?
          .map(|address| {
            Address::try_from(address)
              .map_err(|()| io::Error::other("couldn't decode Address from ExternalAddress"))
          })
          .transpose()?
      },
      output: WalletOutput::read(reader)?,
      data: {
        let mut data_len = [0; 2];
        reader.read_exact(&mut data_len)?;

        let mut data = vec![0; usize::from(u16::from_le_bytes(data_len))];
        reader.read_exact(&mut data)?;
        data
      },
    })
  }
}
