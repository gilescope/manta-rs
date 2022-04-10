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
use core::marker::PhantomData;
use ark_std::fmt::{Formatter, Debug};

use ark_ec::{ModelParameters, TEModelParameters};
use ark_ff::{PrimeField, FftField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};
use crate::crypto::constraint::arkworks::{
    self,
    codec::{HasDeserialization, HasSerialization, SerializationError},
    R1CS,
};
use manta_util::codec::{self, DecodeError};
use manta_crypto::{
    constraint::{
        measure::Measure, Add, ConditionalSelect, Constant, ConstraintSystem, Equal, ProofSystem,
        Public, Secret, Variable,
    },
    rand::{CryptoRng, RngCore, SizedRng},
};
use merlin::Transcript;
use zk_garage_plonk::{
    commitment::HomomorphicCommitment,
    constraint_system::{self, StandardComposer},
    proof_system::{self, Prover, ProverKey, Verifier, VerifierKey},
};

// struct AlignedKeccakState([u8; 200]);

// pub struct Strobe128 {
//     state: AlignedKeccakState,
//     pos: u8,
//     pos_begin: u8,
//     cur_flags: u8,
// }

// pub struct Transcript {
//     strobe: Strobe128,
// }

// pub struct Proof<F, PC>
// where
//     F: PrimeField,
//     PC: HomomorphicCommitment<F>,
// {
//     /// Commitment to the witness polynomial for the left wires.
//     pub(crate) a_comm: PC::Commitment,

//     /// Commitment to the witness polynomial for the right wires.
//     pub(crate) b_comm: PC::Commitment,

//     /// Commitment to the witness polynomial for the output wires.
//     pub(crate) c_comm: PC::Commitment,

//     /// Commitment to the witness polynomial for the fourth wires.
//     pub(crate) d_comm: PC::Commitment,

//     /// Commitment to the permutation polynomial.
//     pub(crate) z_comm: PC::Commitment,

//     /// Commitment to the quotient polynomial.
//     pub(crate) t_1_comm: PC::Commitment,

//     /// Commitment to the quotient polynomial.
//     pub(crate) t_2_comm: PC::Commitment,

//     /// Commitment to the quotient polynomial.
//     pub(crate) t_3_comm: PC::Commitment,

//     /// Commitment to the quotient polynomial.
//     pub(crate) t_4_comm: PC::Commitment,

//     /// Batch opening proof of the aggregated witnesses
//     pub aw_opening: PC::Proof,

//     /// Batch opening proof of the shifted aggregated witnesses
//     pub saw_opening: PC::Proof,

//     /// Subset of all of the evaluations added to the proof.
//     pub(crate) evaluations: ProofEvaluations<F>,
// }

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
#[derivative(Clone, Eq)]
pub struct Proof<F, PC>(
    /// Plonk Proof
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_proof::<E, _>"))]
    pub proof_system::Proof<F, PC>,
)
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>;

impl<F, PC> Debug for Proof<F, PC> 
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>
{
    fn fmt(&self, _: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        todo!() 
       }
}

impl<F, PC> Default for Proof<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    fn default() -> Self {
        todo!()
    }
}

impl<F, PC> PartialEq for Proof<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    fn eq(&self, other: &Proof<F,PC>) -> bool {
        todo!()
    }

    fn ne(&self, other: &Proof<F, PC>) -> bool {
        todo!()
    }
}

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
        todo!()
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<E> scale_codec::Encode for Proof<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    #[inline]
    fn using_encoded<R, Encoder>(&self, f: Encoder) -> R
    where
        Encoder: FnOnce(&[u8]) -> R,
    {
        todo!()
    }
}


#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<E> scale_codec::EncodeLike for Proof<F, PC> 
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<E> scale_codec::MaxEncodedLen for Proof<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    #[inline]
    fn max_encoded_len() -> usize {
        todo!()
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<E> scale_info::TypeInfo for Proof<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    type Identity = [u8];

    #[inline]
    fn type_info() -> scale_info::Type {
        todo!()
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
        todo!()
    }
}

/// Converts `proof` into its canonical byte-representation.
#[inline]
pub fn proof_as_bytes<F, PC>(proof: &proof_system::Proof<F, PC>) -> Vec<u8>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    todo!()
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
    todo!()
}

/// Proving Context
#[derive(derivative::Derivative)]
#[derivative(Clone, Eq)]
pub struct ProvingContext<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    prover_key: ProverKey<F>,
    pc_commit_key: <PC as PolynomialCommitment<F, DensePolynomial<F>>>::CommitterKey,
    transcript: Transcript,
}

impl<F, PC> Debug for ProvingContext<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    fn fmt(&self, _: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
         todo!() 
        }
}

impl<F, PC> PartialEq for ProvingContext<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    fn eq(&self, other: &ProvingContext<F,PC>) -> bool {
        todo!()
    }

    fn ne(&self, other: &ProvingContext<F, PC>) -> bool {
        todo!()
    }
}

impl<F, PC> CanonicalSerialize for ProvingContext<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    #[inline]
    fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        todo!()
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        todo!()
    }

    #[inline]
    fn serialize_uncompressed<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        todo!()
    }

    #[inline]
    fn serialize_unchecked<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        todo!()
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        todo!()
    }
}

impl<F, PC> CanonicalDeserialize for ProvingContext<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    #[inline]
    fn deserialize<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        todo!()
    }

    #[inline]
    fn deserialize_uncompressed<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        todo!()
    }

    #[inline]
    fn deserialize_unchecked<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        todo!()
    }
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
        todo!()
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
        todo!()
    }
}

/// VerifyingContext
#[derive(derivative::Derivative)]
#[derivative(Clone)]
pub struct VerifyingContext<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    verifier_key: VerifierKey<F, PC>,
    pc_verifier_key: <PC as PolynomialCommitment<F, DensePolynomial<F>>>::VerifierKey,
    public_inputs: Vec<F>,
    transcript: Transcript,
}

impl<F, PC> Default for VerifyingContext<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    fn default() -> Self {
        todo!()
    }
}

impl<F, PC> Debug for VerifyingContext<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    fn fmt(&self, _: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
         todo!() 
        }
}

impl<F, PC> CanonicalSerialize for VerifyingContext<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    #[inline]
    fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        todo!()
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        todo!()
    }

    #[inline]
    fn serialize_uncompressed<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        todo!()
    }

    #[inline]
    fn serialize_unchecked<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        todo!()
    }

    #[inline]
    fn uncompressed_size(&self) -> usize {
        todo!()
    }
}

impl<F, PC> CanonicalDeserialize for VerifyingContext<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    #[inline]
    fn deserialize<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        todo!()
    }

    #[inline]
    fn deserialize_uncompressed<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        todo!()
    }

    #[inline]
    fn deserialize_unchecked<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        todo!()
    }
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
        todo!()
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
        todo!()
    }
}




mod test {
    
    #[test]
    fn serialize_proof() {
    }
}
