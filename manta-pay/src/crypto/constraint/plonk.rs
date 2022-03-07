
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

//! PLONK Constraint System and Proof System Implementations

use crate::crypto::constraint::arkworks::{
    self,
    codec::{HasDeserialization, HasSerialization, SerializationError},
};
use alloc::vec::Vec;
use ark_ff::{Field, PrimeField};
use blake2::digest::core_api::CtVariableCoreWrapper;
use zk_garage_plonk::{circuit::PublicInputBuilder, prelude::*, constraint_system::Variable as PlonkVriable, commitment::HomomorphicCommitment, proof_system::{Prover, Verifier}};
use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::{TEModelParameters, PairingEngine};
use ark_ed_on_bls12_381::EdwardsParameters as JubJubParameters;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::sonic_pc::SonicKZG10;
use ark_poly_commit::PolynomialCommitment;
use ark_std::{test_rng, UniformRand};
use core::marker::PhantomData;
use manta_crypto::{
    constraint::{
        measure::Measure, Add, ConditionalSelect, Constant, ConstraintSystem, Equal, Public,
        Secret, Variable,ProofSystem,
    },
    rand::{CryptoRng, RngCore, Sample, Standard},
};
use manta_util::codec::{self, DecodeError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};
use ark_poly::Polynomial;


#[cfg(feature = "scale")]
use crate::crypto::ece::arkworks::Group;

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize, Serializer};

use super::arkworks::SynthesisResult;

/// Proof System Error
///
/// This is the error state of the [`Groth16`] proof system methods. This type is intentionally
/// opaque so that error details are not revealed.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Error;

/// ZK-Garage Plonk Constraint System
pub struct PlonkConstraintSystem<F,P>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    /// Constraint System
    pub(crate) cs: StandardComposer<F,P>,
}

impl<F,P> PlonkConstraintSystem<F,P>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    /// Constructs a new constraint system which is ready for unknown variables.
    #[inline]
    pub fn for_unknown() -> Self {
        // TODO: Please review. Not found new_ref() in zk-garage-plonk.
        let cs = StandardComposer::new();
        // TODO: Not found set_optimization_goal() and set_mode() in zk-garage-plonk
        // cs.set_optimization_goal(ark_r1cs::OptimizationGoal::Constraints);
        // cs.set_mode(ark_r1cs::SynthesisMode::Setup);
        Self { cs }
    }

    /// Constructs a new constraint system which is ready for known variables.
    #[inline]
    pub fn for_known() -> Self {
        // TODO: Please review. Not found new_ref() in zk-garage-plonk.
        let cs = StandardComposer::new();
        // TODO: Not found set_optimization_goal() in zk-garage-plonk
        // cs.set_optimization_goal(ark_r1cs::OptimizationGoal::Constraints);
        Self { cs }
    }
}

impl<F,P> ConstraintSystem for PlonkConstraintSystem<F,P>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    // zk-garage does not have dedicated boolean variable
    type Bool = PlonkVriable;

    #[inline]
    fn assert(&mut self, b: Self::Bool) {
        // Assuming b is either 0 or 1.
        let one = self.cs.add_input(F::one());
        self.cs.assert_equal(b, one);
    }
}

impl<F,P> Measure for PlonkConstraintSystem<F,P>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    #[inline]
    fn constraint_count(&self) -> usize {
        self.cs.circuit_size()
    }

    #[inline]
    fn public_variable_count(&self) -> Option<usize> {
        // Not found in zk-garage
        unimplemented!();
    }

    #[inline]
    fn secret_variable_count(&self) -> Option<usize> {
        // Not found in zk-garage
        unimplemented!();
    }
}

// TODO: Skip constant, public variable, secret variable, and equal for Boolean. There is no Boolean in zk-garage-plonk

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
#[derivative(Clone)]
pub struct Proof<F, PC>(
    /// Plonk Proof
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_proof::<E, _>"))]
    pub zk_garage_plonk::proof_system::proof::Proof<F, PC>,
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
        f(&proof_as_bytes::<E>(&self.0))
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<F, PC> scale_codec::EncodeLike for Proof<F, PC> where 
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{}

// TODO: Not sure whether this is correct.
#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<F, PC> scale_codec::MaxEncodedLen for Proof<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    #[inline]
    fn max_encoded_len() -> usize {
        unimplemented!()
    }
}

// TODO: Not sure whether this is correct.
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

// TODO
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

// TODO
/// Converts `proof` into its canonical byte-representation.
#[inline]
pub fn proof_as_bytes<F, PC>(proof: &zk_garage_plonk::proof_system::proof::Proof<F, PC>) -> Vec<u8>
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
fn serialize_proof<E, S>(proof: &zk_garage_plonk::proof_system::proof::Proof<F, PC>, serializer: S) -> Result<S::Ok, S::Error>
where
    E: PairingEngine,
    S: Serializer,
{
    serializer.serialize_bytes(&proof_as_bytes::<E>(proof))
}

/// Proving Context
#[derive(derivative::Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(Clone, Debug)] // TODO: Add Eq and PartialEq
pub struct ProvingContext<F, PL, PC>(pub <PC as PolynomialCommitment<F,PL>>::CommitterKey)
where
    F: PrimeField,
    PL: Polynomial<F>,
    PC: HomomorphicCommitment<F> + ark_poly_commit::PolynomialCommitment<F, PL>;

impl<F, PL, PC> ProvingContext<F, PL, PC>
where
    F: PrimeField,
    PL: Polynomial<F>,
    PC: HomomorphicCommitment<F> + ark_poly_commit::PolynomialCommitment<F, PL>
{
    /// Build a new [`ProvingContext`] from `proving_key`.
    #[inline]
    pub fn new(proving_key: <PC as PolynomialCommitment<F,PL>>::CommitterKey) -> Self {
        Self(proving_key)
    }
}

impl<F, PL, PC> codec::Decode for ProvingContext<F, PL, PC>
where
    F: PrimeField,
    PL: Polynomial<F>,
    PC: HomomorphicCommitment<F> + ark_poly_commit::PolynomialCommitment<F, PL>
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
                .map(move |_| Self(value))
                .map_err(DecodeError::Read),
            Err(err) => Err(DecodeError::Decode(err)),
        }
    }
}

impl<F, P, PC> codec::Encode for ProvingContext<F, P, PC>
where
    F: PrimeField,
    P: Polynomial<F>,
    PC: HomomorphicCommitment<F> + ark_poly_commit::PolynomialCommitment<F, P>
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        let mut writer = arkworks::codec::ArkWriter::new(writer);
        let _ = self.0.serialize_unchecked(&mut writer);
        writer.finish().map(move |_| ())
    }
}

/// Verifying Context
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug)]
pub struct VerifyingContext<F, PL, PC>(pub <PC as PolynomialCommitment<F,PL>>::VerifierKey)
where
    F: PrimeField,
    PL: Polynomial<F>,
    PC: HomomorphicCommitment<F> + ark_poly_commit::PolynomialCommitment<F, PL>;

impl<F, PL, PC> CanonicalSerialize for VerifyingContext<F, PL, PC>
where 
    F: PrimeField,
    PL: Polynomial<F>,
    PC: HomomorphicCommitment<F> + ark_poly_commit::PolynomialCommitment<F, PL>
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

impl<F, PL, PC> CanonicalDeserialize for VerifyingContext<F, PL, PC>
where 
    F: PrimeField,
    PL: Polynomial<F>,
    PC: HomomorphicCommitment<F> + ark_poly_commit::PolynomialCommitment<F, PL>
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

impl<F, PL, PC> codec::Decode for VerifyingContext<F, PL, PC>
where
    F: PrimeField,
    PL: Polynomial<F>,
    PC: HomomorphicCommitment<F> + ark_poly_commit::PolynomialCommitment<F, PL>
{
    type Error = SerializationError;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: codec::Read,
    {
        let mut reader = arkworks::codec::ArkReader::new(reader);
        match CanonicalDeserialize::deserialize(&mut reader) {
            Ok(value) => reader
                .finish()
                .map(move |_| value)
                .map_err(DecodeError::Read),
            Err(err) => Err(DecodeError::Decode(err)),
        }
    }
}

impl<F, PL, PC> codec::Encode for VerifyingContext<F, PL, PC>
where
    F: PrimeField,
    PL: Polynomial<F>,
    PC: HomomorphicCommitment<F> + ark_poly_commit::PolynomialCommitment<F, PL>
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

// ZK-Garage Plonk Proof System
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Plonk<F, P, PL, PC>(PhantomData<F>, PhantomData<P>, PhantomData<PL>, PhantomData<PC>)
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
    PL: Polynomial<F>,
    PC: HomomorphicCommitment<F> + ark_poly_commit::PolynomialCommitment<F, PL>;

impl<F, P, PL, PC> ProofSystem for Plonk<F, P, PL, PC>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
    PL: Polynomial<F>,
    PC: HomomorphicCommitment<F> + ark_poly_commit::PolynomialCommitment<F, PL>
{
    type ConstraintSystem = PlonkConstraintSystem<F, P>;
    type PublicParameters = <PC as PolynomialCommitment<F, DensePolynomial<F>>>::UniversalParams;
    type ProvingContext = ProvingContext<F, PL, PC>;
    type VerifyingContext = VerifyingContext<F, PL, PC>;
    type Input = Vec<F>;
    type Proof = Proof<F, PC>;
    type Error = Error;

    #[inline]
    fn for_unknown() -> Self::ConstraintSystem {
        Self::ConstraintSystem::for_unknown()
    }

    #[inline]
    fn for_known() -> Self::ConstraintSystem {
        Self::ConstraintSystem::for_known()
    }

    #[inline]
    fn generate_context<R>(
        public_parameters: &Self::PublicParameters,
        cs: Self::ConstraintSystem,
        rng: &mut R,
    ) -> Result<(Self::ProvingContext, Self::VerifyingContext), Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        // Commit Key
        // Note: supported_degree may be changed according to our circuit.
        let (ck, vk) = PC::trim(&public_parameters, 2 * 20, 0, None).map_err(|_| Error)?;
        Ok((
            ProvingContext(ck),
            VerifyingContext(vk),
        ))
    }

    #[inline]
    fn prove<R>(
        context: &Self::ProvingContext,
        cs: Self::ConstraintSystem,
        rng: &mut R,
     ) -> Result<Self::Proof, Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        // Create a prover struct
        let mut prover: Prover<F, P, PC> = Prover::new(b"plonk prover");




    }

}


