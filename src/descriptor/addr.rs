//! # Standalone address descriptor
//!
//! Implementation of Address Descriptors which make use of the top-level `addr(ADDR)`
//! function where `ADDR` is any valid bech32, bech32m, or base58 Bitcoin address.
//!
//! See the Bitcoin Core [descriptors doc](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#reference)
//! for more.
//!

use core::{fmt, str::FromStr};

use bitcoin::{
    util::address::{Payload, WitnessVersion},
    Address, AddressType, Script,
};

use crate::{
    expression::{self, FromTree},
    Error, MiniscriptKey, TranslatePk,
};

use super::checksum::{desc_checksum, verify_checksum};

/// A standalone address descriptor
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Addr {
    address: Address,
}

impl Addr {
    /// Create a new address descriptor
    pub fn new(address: Address) -> Self {
        // We will always assume that address has been checked as valid
        // during construction.
        Addr { address }
    }

    /// Get the inner address
    pub fn into_inner(self) -> Address {
        self.address
    }

    /// Get the inner address
    pub fn as_inner(&self) -> &Address {
        &self.address
    }

    /// Checks whether the descriptor is safe.
    pub fn sanity_check(&self) -> Result<(), Error> {
        Ok(())
    }

    /// Get the descriptor without the checksum
    pub fn to_string_no_checksum(&self) -> String {
        format!("addr({})", self.address)
    }

    /// Obtains the corresponding script pubkey for this descriptor.
    pub fn script_pubkey(&self) -> Script {
        self.address.script_pubkey()
    }

    /// Obtains the corresponding script pubkey for this descriptor.
    pub fn address(&self) -> Address {
        self.address.clone()
    }

    /// Obtains the segwit version for the contained address
    pub fn segwit_version(&self) -> Option<WitnessVersion> {
        match self.address.payload {
            Payload::WitnessProgram { version, .. } => Some(version),
            _ => None,
        }
    }

    /// Obtains the explicit script for the inner address
    pub fn explicit_script(&self) -> Result<Script, Error> {
        match self.address.address_type() {
            Some(AddressType::P2pkh | AddressType::P2wpkh) => {
                Ok(self.address.payload.script_pubkey())
            }
            _ => Err(Error::AddrNoExplicitScript),
        }
    }

    /// Obtains the script code for this descriptor.
    pub fn script_code(&self) -> Result<Script, Error> {
        match self.address.address_type() {
            Some(AddressType::P2tr) => Err(Error::AddrNoScriptCode),
            _ => Ok(self.script_pubkey()),
        }
    }
}

impl FromTree for Addr {
    fn from_tree(top: &expression::Tree) -> Result<Self, Error> {
        if top.name == "addr" && top.args.len() == 1 {
            Ok(Addr::new(Address::from_str(top.args[0].name)?))
        } else {
            Err(Error::Unexpected(format!(
                "{}({} args) while parsing addr descriptor",
                top.name,
                top.args.len(),
            )))
        }
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.address)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let desc = self.to_string_no_checksum();
        let checksum = desc_checksum(&desc).map_err(|_| fmt::Error)?;
        write!(f, "{}#{}", &desc, &checksum)
    }
}

impl FromStr for Addr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let desc_str = verify_checksum(s)?;
        let top = expression::Tree::from_str(desc_str)?;
        Self::from_tree(&top)
    }
}

impl<P, Q> TranslatePk<P, Q> for Addr
where
    P: MiniscriptKey,
    Q: MiniscriptKey,
{
    type Output = Addr;

    fn translate_pk<Fpk, Fpkh, E>(&self, _fpk: Fpk, _fpkh: Fpkh) -> Result<Self::Output, E>
    where
        Fpk: FnMut(&P) -> Result<Q, E>,
        Fpkh: FnMut(&P::Hash) -> Result<Q::Hash, E>,
    {
        Ok(Addr::new(self.address.clone()))
    }
}
