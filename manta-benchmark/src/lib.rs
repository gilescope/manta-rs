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

use manta_accounting::transfer::test::assert_valid_proof;
use manta_crypto::rand::{OsRng, Rand};
use manta_pay::{
    config::{
        MultiProvingContext, MultiVerifyingContext, Parameters, TransferPost, UtxoAccumulatorModel,
    },
    parameters,
    test::payment,
};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct Context {
    proving_context: MultiProvingContext,
    verifying_context: MultiVerifyingContext,
    parameters: Parameters,
    utxo_accumulator_model: UtxoAccumulatorModel,
}

#[wasm_bindgen]
impl Context {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
            parameters::generate().unwrap();
        Self {
            proving_context,
            verifying_context,
            parameters,
            utxo_accumulator_model,
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
pub struct Proof(TransferPost);

#[wasm_bindgen]
pub fn prove_mint(context: &Context) -> Proof {
    let mut rng = OsRng;
    Proof(payment::prove_mint(
        &context.proving_context.mint,
        &context.parameters,
        &context.utxo_accumulator_model,
        rng.gen(),
        &mut rng,
    ))
}

#[wasm_bindgen]
pub fn prove_private_transfer(context: &Context) -> Proof {
    let mut rng = OsRng;
    Proof(payment::prove_private_transfer(
        &context.proving_context,
        &context.parameters,
        &context.utxo_accumulator_model,
        &mut rng,
    ))
}

#[wasm_bindgen]
pub fn prove_reclaim(context: &Context) -> Proof {
    let mut rng = OsRng;
    Proof(payment::prove_reclaim(
        &context.proving_context,
        &context.parameters,
        &context.utxo_accumulator_model,
        &mut rng,
    ))
}

#[wasm_bindgen]
pub fn verify_mint(context: &Context, proof: &Proof) {
    assert_valid_proof(&context.verifying_context.mint, &proof.0);
}

#[wasm_bindgen]
pub fn verify_private_transfer(context: &Context, proof: &Proof) {
    assert_valid_proof(&context.verifying_context.private_transfer, &proof.0);
}

#[wasm_bindgen]
pub fn verify_reclaim(context: &Context, proof: &Proof) {
    assert_valid_proof(&context.verifying_context.reclaim, &proof.0);
}
