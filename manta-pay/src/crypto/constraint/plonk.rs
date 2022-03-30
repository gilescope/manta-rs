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

use std::marker::PhantomData;

use ark_ec::{ModelParameters, TEModelParameters};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use manta_crypto::{
    constraint::{
        measure::Measure, Add, ConditionalSelect, Constant, ConstraintSystem, Equal, ProofSystem,
        Public, Secret, Variable,
    },
    rand::{CryptoRng, RngCore, SizedRng},
};
use zk_garage_plonk::{
    commitment::HomomorphicCommitment,
    constraint_system::{self, StandardComposer},
    proof_system::{Proof, ProverKey, VerifierKey},
};

/// A StandardComposer Variable constrained to have
/// the value 0 or 1 at allocation.
#[derive(Clone, Copy)]
pub struct Boolean(constraint_system::Variable);

impl Boolean {
    fn with_constraint<F, P>(
        variable: constraint_system::Variable,
        compiler: &mut Compiler<F, P>,
    ) -> Self
    where
        F: PrimeField,
        P: TEModelParameters<BaseField = F>,
    {
        let zero = compiler.0.zero_var();
        // Constrain to boolean: v*v - v = 0
        // TODO: input selector coeffs directly
        compiler.0.arithmetic_gate(|g| {
            g.witness(variable, variable, Some(zero))
                .mul(F::from(1u8))
                .add(-F::from(1u8), F::from(0u8))
        });
        Self(variable)
    }
}

/// A wrapper around StandardComposer Variables
/// that may carry any field element.
#[derive(Clone, Copy)]
pub struct FpVar(constraint_system::Variable);

/// A wrapper around StandardComposer to allow us to define
/// the ConstraintSystem trait on a struct from outside
/// this crate.
#[derive(derivative::Derivative)]
#[derivative(Default(bound = ""))]
pub struct Compiler<F, P>(StandardComposer<F, P>)
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>;

impl<F, P> Compiler<F, P>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    fn constrain_to_public_input(&mut self, var: constraint_system::Variable, val: F) {
        let zero = self.0.zero_var();
        self.0.arithmetic_gate(|g| {
            g.witness(var, var, Some(zero))
                .add(-F::from(1u8), F::from(0u8))
                .pi(val)
        });
    }

    fn constrain_to_constant(&mut self, var: constraint_system::Variable, val: F) {
        let zero = self.0.zero_var();
        self.0.arithmetic_gate(|g| {
            g.witness(var, var, Some(zero))
                .add(-F::from(1u8), F::from(0u8))
                .constant(val)
        });
    }
}

impl<F, P> ConstraintSystem for Compiler<F, P>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    type Bool = Boolean;

    fn assert(&mut self, b: Self::Bool) {
        let zero = self.0.zero_var();
        self.0.arithmetic_gate(|g| {
            g.witness(b.0, b.0, Some(zero))
                .add(-F::from(1u8), F::from(0u8))
                .constant(F::from(1u8))
        });
    }
}

impl<F, P> Measure for Compiler<F, P>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    fn constraint_count(&self) -> usize {
        self.0.circuit_size()
    }

    fn public_variable_count(&self) -> Option<usize> {
        Some(self.0.pi_positions().len())
    }

    fn secret_variable_count(&self) -> Option<usize> {
        None
    }
}

impl<F, P> Variable<Secret, Compiler<F, P>> for Boolean
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    type Type = bool;

    fn new_known(this: &Self::Type, compiler: &mut Compiler<F, P>) -> Self {
        Boolean::with_constraint(compiler.0.add_input(F::from(*this as u8)), compiler)
    }

    fn new_unknown(compiler: &mut Compiler<F, P>) -> Self {
        <Self as Variable<Secret, _>>::new_known(&Self::Type::default(), compiler)
    }
}

impl<F, P> Variable<Public, Compiler<F, P>> for Boolean
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    type Type = bool;

    fn new_known(this: &Self::Type, compiler: &mut Compiler<F, P>) -> Self {
        let v = compiler.0.add_input(F::from(*this as u8));
        // Constrain to public value
        compiler.constrain_to_public_input(v, F::from(*this as u8));
        // Constrain to boolean: v*v - v = 0
        let zero = compiler.0.zero_var();
        compiler.0.arithmetic_gate(|g| {
            g.witness(v, v, Some(zero))
                .mul(F::from(1u8))
                .add(-F::from(1u8), F::from(0u8))
        });
        Boolean(v)
    }

    fn new_unknown(compiler: &mut Compiler<F, P>) -> Self {
        <Self as Variable<Public, _>>::new_known(&Self::Type::default(), compiler)
    }
}

impl<F, P> Constant<Compiler<F, P>> for Boolean
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    type Type = bool;

    fn new_constant(this: &Self::Type, compiler: &mut Compiler<F, P>) -> Self {
        let v = compiler.0.add_input(F::from(*this as u8));
        let zero = compiler.0.zero_var();
        // Constrain to constant value
        compiler.0.arithmetic_gate(|g| {
            g.witness(v, v, Some(zero))
                .add(-F::from(1u8), F::from(0u8))
                .constant(F::from(*this as u8))
        });
        Boolean(v)
    }
}

impl<F, P> Equal<Compiler<F, P>> for Boolean
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    fn eq(lhs: &Self, rhs: &Self, compiler: &mut Compiler<F, P>) -> Self {
        let res = compiler.0.is_eq_with_output(lhs.0, rhs.0);
        Boolean(res)
    }
}

// repeat for field

impl<F, P> Variable<Secret, Compiler<F, P>> for FpVar
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    type Type = F;

    fn new_known(this: &Self::Type, compiler: &mut Compiler<F, P>) -> Self {
        let v = compiler.0.add_input(*this);
        FpVar(v)
    }

    fn new_unknown(compiler: &mut Compiler<F, P>) -> Self {
        <Self as Variable<Secret, _>>::new_known(&Self::Type::default(), compiler)
    }
}

impl<F, P> Variable<Public, Compiler<F, P>> for FpVar
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    type Type = F;

    fn new_known(this: &Self::Type, compiler: &mut Compiler<F, P>) -> Self {
        let v = compiler.0.add_input(*this);
        let zero = compiler.0.zero_var();
        // Constrain to public value
        compiler.0.arithmetic_gate(|g| {
            g.witness(v, v, Some(zero))
                .add(-F::from(1u8), F::from(0u8))
                .pi(*this)
        });
        FpVar(v)
    }

    fn new_unknown(compiler: &mut Compiler<F, P>) -> Self {
        <Self as Variable<Public, _>>::new_known(&Self::Type::default(), compiler)
    }
}

impl<F, P> Constant<Compiler<F, P>> for FpVar
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    type Type = F;

    fn new_constant(this: &Self::Type, compiler: &mut Compiler<F, P>) -> Self {
        let v = compiler.0.add_input(*this);
        let zero = compiler.0.zero_var();
        // Constrain to constant value
        compiler.0.arithmetic_gate(|g| {
            g.witness(v, v, Some(zero))
                .add(-F::from(1u8), F::from(0u8))
                .constant(*this)
        });
        FpVar(v)
    }
}

impl<F, P> Equal<Compiler<F, P>> for FpVar
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    fn eq(lhs: &Self, rhs: &Self, compiler: &mut Compiler<F, P>) -> Boolean {
        let res = compiler.0.is_eq_with_output(lhs.0, rhs.0);
        Boolean(res)
    }
}

impl<F, P> Add<Compiler<F, P>> for FpVar
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    fn add(lhs: Self, rhs: Self, compiler: &mut Compiler<F, P>) -> Self {
        let res = compiler.0.arithmetic_gate(|g| {
            g.witness(lhs.0, rhs.0, None)
                .add(F::from(1u8), F::from(1u8))
        });
        FpVar(res)
    }
}

impl<F, P> ConditionalSelect<Compiler<F, P>> for FpVar
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    fn select(
        bit: &Boolean,
        true_value: &Self,
        false_value: &Self,
        compiler: &mut Compiler<F, P>,
    ) -> Self {
        let res = compiler
            .0
            .conditional_select(bit.0, true_value.0, false_value.0);
        FpVar(res)
    }
}

/// ProofSystem
pub struct Plonk<F, P, PC>(PhantomData<(F, P, PC)>)
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
    PC: HomomorphicCommitment<F>;

impl<F, P, PC> ProofSystem for Plonk<F, P, PC>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
    PC: HomomorphicCommitment<F>,
{
    type ConstraintSystem = Compiler<F, P>;
    type PublicParameters = <PC as PolynomialCommitment<F, DensePolynomial<F>>>::UniversalParams;
    type ProvingContext = ProverKey<F>;
    type VerifyingContext = VerifierKey<F, PC>;
    type Input = Vec<F>;
    type Proof = Proof<F, PC>;
    type Error = ();

    fn for_unknown() -> Self::ConstraintSystem {
        Self::ConstraintSystem::default()
    }

    fn for_known() -> Self::ConstraintSystem {
        Self::ConstraintSystem::default()
    }

    fn generate_context<R>(
        public_parameters: &Self::PublicParameters,
        cs: Self::ConstraintSystem,
        rng: &mut R,
    ) -> Result<(Self::ProvingContext, Self::VerifyingContext), Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        todo!()
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
        todo!()
    }

    #[inline]
    fn verify(
        context: &Self::VerifyingContext,
        input: &Self::Input,
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error> {
        // Verifier::default().verify(proof, _, input)
        todo!()
    }
}
