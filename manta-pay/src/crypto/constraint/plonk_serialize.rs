// Copyright 2019-2022 Manta Network.
// This file is part of manta-rs.
//
// manta-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

//! PLONK Serialization and Deserialization Implementations

use alloc::vec::Vec;
use ark_std::fmt::{Debug};

use ark_ff::{PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};
use crate::crypto::constraint::arkworks::{
    self,
    codec::{SerializationError},
};
use manta_util::codec::{self, DecodeError};
use zk_garage_plonk::{
    commitment::HomomorphicCommitment,
    proof_system::{self, interface::ProvingKey, VerifierKey, arithmetic},
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize, Serializer};

/// Proof System Error
///
/// This is the error state of the [`PLONK`] proof system methods. This type is intentionally
/// opaque so that error details are not revealed.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Error;

/// Plonk Proof
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(deserialize = "", serialize = ""),
        crate = "manta_util::serde",
        deny_unknown_fields,
        try_from = "Vec<u8>"
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "PC::Commitment: Clone, PC::Proof: Clone"),
    // TODO: Some path issue with std::fmt::Debug
    // Debug(
    //     bound = "PC::Commitment: std::fmt::Debug, PC::Proof: std::fmt::Debug"
    // ),
    Default(bound = "PC::Commitment: Default, PC::Proof: Default"),
    Eq(bound = "PC::Commitment: Eq, PC::Proof: Eq"),
    PartialEq(bound = "PC::Commitment: PartialEq, PC::Proof: PartialEq")
)]
pub struct Proof<F, PC>(
    /// Plonk Proof
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_proof::<F, PC, _>"))]
    pub proof_system::Proof<F, PC>,
)
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>;

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<F, PC> scale_codec::Decode for Proof<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    #[inline]
    fn decode<I>(input: &mut I) -> Result<Self, scale_codec::Error>
    where
        I: scale_codec::Input,
    {
        Ok(Self(
            CanonicalDeserialize::deserialize(arkworks::codec::ScaleCodecReader(input))
                .map_err(|_| "Deserialization Error")?,
        ))
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<F, PC> scale_codec::Encode for Proof<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    #[inline]
    fn using_encoded<R, Encoder>(&self, f: Encoder) -> R
    where
        Encoder: FnOnce(&[u8]) -> R,
    {
        f(&proof_as_bytes::<F, PC>(&self.0))
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<F, PC> scale_codec::EncodeLike for Proof<F, PC> 
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<F, PC> scale_codec::MaxEncodedLen for Proof<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    #[inline]
    fn max_encoded_len() -> usize {
        0
        // 9 * PC::Commitment::max_encoded_len()
        // + 2 * PC::Proof::max_encoded_len()
        // TODO: expose ProofEvaluations::<F>. Currently ProofEvaluation comes from a private module linearisation_poly in zk-garage
        // + ProofEvaluations::<F>::max_encoded_len()
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<F, PC> scale_info::TypeInfo for Proof<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    type Identity = [u8];

    #[inline]
    fn type_info() -> scale_info::Type {
        Self::Identity::type_info()
    }
}

impl<F, PC> TryFrom<Vec<u8>> for Proof<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    type Error = SerializationError;

    #[inline]
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        CanonicalDeserialize::deserialize(&mut bytes.as_slice()).map(Self)
    }
}

/// Converts `proof` into its canonical byte-representation.
#[inline]
pub fn proof_as_bytes<F, PC>(proof: &proof_system::Proof<F, PC>) -> Vec<u8>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    let mut buffer = Vec::new();
    proof
        .serialize(&mut buffer)
        .expect("Serialization is not allowed to fail.");
    buffer
}

/// Uses `serializer` to serialize `proof`.
#[cfg(feature = "serde")]
#[inline]
fn serialize_proof<F, PC, S>(proof: &proof_system::Proof<F, PC>, serializer: S) -> Result<S::Ok, S::Error>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
    S: Serializer,
{
    serializer.serialize_bytes(&proof_as_bytes::<F, PC>(proof))
}

/// Proving Context
// #[derive(derivative::Derivative)]
// #[derivative(Clone, Eq)]
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
)]
pub struct ProvingContext<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    proving_key: ProvingKey<F, PC>
}

impl<F, PC> codec::Decode for ProvingContext<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    type Error = SerializationError;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: codec::Read,
    {
        let mut reader = arkworks::codec::ArkReader::new(reader);
        match CanonicalDeserialize::deserialize_unchecked(&mut reader) {
            Ok(value) => reader
                .finish()
                .map(move |_| value)
                .map_err(DecodeError::Read),
            Err(err) => Err(DecodeError::Decode(err)),
        }
    }
}

impl<F, PC> codec::Encode for ProvingContext<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        let mut writer = arkworks::codec::ArkWriter::new(writer);
        let _ = self.serialize(&mut writer);
        writer.finish().map(move |_| ())
    }
}

/// VerifyingContext
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    // TODO: Some path issue with std::fmt::Debug
    // Debug(
    //     bound = "arithmetic::VerifierKey<F,PC>: std::fmt::Debug, PC::Commitment: std::fmt::Debug"
    // ),
)]
pub struct VerifyingContext<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    verifier_key: VerifierKey<F, PC>,
}

impl<F, PC> codec::Decode for VerifyingContext<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    type Error = SerializationError;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: codec::Read,
    {
        let mut reader = arkworks::codec::ArkReader::new(reader);
        match CanonicalDeserialize::deserialize_unchecked(&mut reader) {
            Ok(value) => reader
                .finish()
                .map(move |_| value)
                .map_err(DecodeError::Read),
            Err(err) => Err(DecodeError::Decode(err)),
        }
    }
}

impl<F, PC> codec::Encode for VerifyingContext<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        let mut writer = arkworks::codec::ArkWriter::new(writer);
        let _ = self.serialize(&mut writer);
        writer.finish().map(move |_| ())
    }
}

mod test {
    
    #[test]
    fn serialize_proof() {
    }
}
