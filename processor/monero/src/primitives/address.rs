use monero_wallet::{
  ed25519::CompressedPoint,
  address::{Network, AddressType as MoneroAddressType, MoneroAddress},
};

use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::address::ExternalAddress;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Address {
  /// An address derived for the Serai multisig.
  Internal(MoneroAddress),
  /// An address supplied by a user within an instruction.
  Instruction(serai_client_monero::Address),
}

impl BorshSerialize for Address {
  fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
    match self {
      Address::Internal(address) => {
        // `Internal` is only constructed with `GuaranteedViewPair::address` results, which are
        // always mainnet featured addresses with the guaranteed flag set and no payment ID
        let flags = match address.kind() {
          MoneroAddressType::Featured { subaddress, payment_id: None, guaranteed } => {
            u8::from(*subaddress) | (u8::from(*guaranteed) << 2)
          }
          MoneroAddressType::Legacy |
          MoneroAddressType::LegacyIntegrated(_) |
          MoneroAddressType::Subaddress |
          MoneroAddressType::Featured { .. } => {
            unreachable!("`Internal` address which wasn't from a `GuaranteedViewPair`")
          }
        };
        writer.write_all(&[0, flags])?;
        writer.write_all(&address.spend().compress().to_bytes())?;
        writer.write_all(&address.view().compress().to_bytes())
      }
      Address::Instruction(address) => {
        writer.write_all(&[1])?;
        address.serialize(writer)
      }
    }
  }
}
impl BorshDeserialize for Address {
  fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
    let mut kind = [0xff];
    reader.read_exact(&mut kind)?;
    match kind[0] {
      0 => {
        let mut flags = [0xff];
        reader.read_exact(&mut flags)?;
        let flags = flags[0];
        // Bit 0 is subaddress, bit 2 is guaranteed. Bit 1 (payment ID) is never set
        if (flags & !0b101) != 0 {
          Err(borsh::io::Error::other("unrecognized flags for an internal address"))?;
        }
        let point = |reader: &mut R| -> borsh::io::Result<_> {
          let mut buf = [0; 32];
          reader.read_exact(&mut buf)?;
          CompressedPoint::from(buf)
            .decompress()
            .ok_or_else(|| borsh::io::Error::other("invalid point within an internal address"))
        };
        let spend = point(reader)?;
        let view = point(reader)?;
        Ok(Address::Internal(MoneroAddress::new(
          Network::Mainnet,
          MoneroAddressType::Featured {
            subaddress: (flags & 1) != 0,
            payment_id: None,
            guaranteed: (flags & (1 << 2)) != 0,
          },
          spend,
          view,
        )))
      }
      1 => Ok(Address::Instruction(serai_client_monero::Address::deserialize_reader(reader)?)),
      _ => Err(borsh::io::Error::other("unrecognized address kind")),
    }
  }
}

impl TryFrom<ExternalAddress> for Address {
  type Error = ();
  fn try_from(data: ExternalAddress) -> Result<Address, ()> {
    serai_client_monero::Address::try_from(data).map(Address::Instruction)
  }
}
impl From<Address> for ExternalAddress {
  fn from(address: Address) -> ExternalAddress {
    match address {
      Address::Instruction(address) => address.into(),
      Address::Internal(_) => {
        panic!("representing an internal address on Serai")
      }
    }
  }
}

impl From<Address> for MoneroAddress {
  fn from(address: Address) -> MoneroAddress {
    match address {
      Address::Internal(address) => address,
      Address::Instruction(address) => address.into(),
    }
  }
}
