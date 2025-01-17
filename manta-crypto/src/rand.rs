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

//! Random Number Generators

// TODO: Add a `Sample` derive trait.

use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash, iter::repeat, marker::PhantomData};
use manta_util::into_array_unchecked;

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

pub use rand_core::{block, CryptoRng, Error, RngCore, SeedableRng};

#[cfg(feature = "getrandom")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "getrandom")))]
#[doc(inline)]
pub use rand_core::OsRng;

#[cfg(feature = "rand")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "rand")))]
#[doc(inline)]
pub use rand::distributions::{
    uniform::{SampleRange, SampleUniform},
    Distribution,
};

/// Random Number Generator Sized Wrapper
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SizedRng<'r, R>(
    /// Mutable Reference to Random Number Generator
    pub &'r mut R,
)
where
    R: ?Sized;

impl<'r, R> CryptoRng for SizedRng<'r, R> where R: CryptoRng + ?Sized {}

impl<'r, R> RngCore for SizedRng<'r, R>
where
    R: RngCore + ?Sized,
{
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl<'r, R> block::BlockRngCore for SizedRng<'r, R>
where
    R: block::BlockRngCore + ?Sized,
{
    type Item = R::Item;
    type Results = R::Results;

    #[inline]
    fn generate(&mut self, results: &mut Self::Results) {
        self.0.generate(results);
    }
}

/// Seed Into Random Number Generator
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SeedIntoRng<S, R> {
    /// Inner Rng
    inner: R,

    /// Type Parameter Marker
    __: PhantomData<S>,
}

impl<S, R> SeedIntoRng<S, R> {
    /// Builds a new [`SeedIntoRng`] from an existing `inner` random number generator.
    #[inline]
    fn new(inner: R) -> Self {
        Self {
            inner,
            __: PhantomData,
        }
    }
}

impl<S, R> CryptoRng for SeedIntoRng<S, R> where R: CryptoRng {}

impl<S, R> RngCore for SeedIntoRng<S, R>
where
    R: RngCore,
{
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.inner.try_fill_bytes(dest)
    }
}

impl<S, R> block::BlockRngCore for SeedIntoRng<S, R>
where
    R: block::BlockRngCore,
{
    type Item = R::Item;
    type Results = R::Results;

    #[inline]
    fn generate(&mut self, results: &mut Self::Results) {
        self.inner.generate(results);
    }
}

impl<S, R> SeedableRng for SeedIntoRng<S, R>
where
    S: Into<R::Seed> + Default + AsMut<[u8]>,
    R: SeedableRng,
{
    type Seed = S;

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        Self::new(R::from_seed(seed.into()))
    }

    #[inline]
    fn seed_from_u64(state: u64) -> Self {
        Self::new(R::seed_from_u64(state))
    }

    #[inline]
    fn from_rng<T: RngCore>(rng: T) -> Result<Self, Error> {
        R::from_rng(rng).map(Self::new)
    }

    #[cfg(feature = "getrandom")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "getrandom")))]
    #[inline]
    fn from_entropy() -> Self {
        Self::new(R::from_entropy())
    }
}

/// Entropy Seedable PRNG
///
/// This `trait` is automatically implemented for all [`SeedableRng`] whenever the `getrandom` crate
/// is in scope. This `trait` is used to capture the behavior of seeding from an entropy source even
/// if the `getrandom` crate is not imported.
pub trait FromEntropy {
    /// Creates a new instance of `Self` seeded via some entropy source.
    fn from_entropy() -> Self;
}

#[cfg(feature = "getrandom")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "getrandom")))]
impl<R> FromEntropy for R
where
    R: SeedableRng,
{
    #[inline]
    fn from_entropy() -> Self {
        SeedableRng::from_entropy()
    }
}

/// Sampling Trait
pub trait Sample<D = ()>: Sized {
    /// Returns a random value of type `Self`, sampled according to the given `distribution`,
    /// generated from the `rng`.
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized;

    /// Returns a random value of type `Self`, sampled according to the default distribution of
    /// type `D`, generated from the `rng`.
    #[inline]
    fn gen<R>(rng: &mut R) -> Self
    where
        D: Default,
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::sample(Default::default(), rng)
    }
}

/// Generates [`Sample`] implementation for `$type` using conversion from `u32`.
macro_rules! impl_sample_from_u32 {
    ($($type:ty),+) => {
        $(
            impl Sample for $type {
                #[inline]
                fn sample<R>(_: (), rng: &mut R) -> Self
                where
                    R: RngCore + ?Sized,
                {
                    rng.next_u32() as Self
                }
            }
        )+
    };
}

impl_sample_from_u32!(i8, i16, i32, u8, u16, u32);

impl Sample for u64 {
    #[inline]
    fn sample<R>(_: (), rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        rng.next_u64()
    }
}

impl Sample for u128 {
    #[inline]
    fn sample<R>(_: (), rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        (u128::from(rng.next_u64()) << 64) | u128::from(rng.next_u64())
    }
}

impl<D, T, const N: usize> Sample<D> for [T; N]
where
    D: Clone,
    T: Sample<D>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        into_array_unchecked(
            rng.sample_iter(repeat(distribution).take(N))
                .collect::<Vec<_>>(),
        )
    }
}

/// Distribution Sampled Value
///
/// This wrapper type automatically implements [`Sample`] whenever the `rand` crate is in scope by
/// sampling from a `rand::Distribution<T>`.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sampled<T>(
    /// Sampled Value
    pub T,
);

#[cfg(feature = "rand")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "rand")))]
impl<T, D> Sample<D> for Sampled<T>
where
    D: Distribution<T>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self(distribution.sample(rng))
    }
}

/// Distribution Iterator
pub struct DistIter<'r, D, T, R>
where
    D: Iterator,
    T: Sample<D::Item>,
    R: CryptoRng + RngCore + ?Sized,
{
    /// Distribution Iterator
    iter: D,

    /// Random Number Generator
    rng: &'r mut R,

    /// Type Parameter Marker
    __: PhantomData<T>,
}

impl<'r, D, T, R> DistIter<'r, D, T, R>
where
    D: Iterator,
    T: Sample<D::Item>,
    R: CryptoRng + RngCore + ?Sized,
{
    /// Builds a new [`DistIter`] from `iter` and `rng`.
    #[inline]
    fn new(iter: D, rng: &'r mut R) -> Self {
        Self {
            iter,
            rng,
            __: PhantomData,
        }
    }
}

impl<'r, D, T, R> Iterator for DistIter<'r, D, T, R>
where
    D: Iterator,
    T: Sample<D::Item>,
    R: CryptoRng + RngCore + ?Sized,
{
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|d| self.rng.sample(d))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

/// Fallible Sampling Trait
pub trait TrySample<D = ()>: Sized {
    /// Error Type
    type Error;

    /// Tries to return a random value of type `Self`, sampled according to the given
    /// `distribution`, generated from the `rng`.
    fn try_sample<R>(distribution: D, rng: &mut R) -> Result<Self, Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized;

    /// Tries to return a random value of type `Self`, sampled according to the default
    /// distribution of type `D`, generated from the `rng`.
    #[inline]
    fn try_gen<R>(rng: &mut R) -> Result<Self, Self::Error>
    where
        D: Default,
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::try_sample(Default::default(), rng)
    }
}

/// Random Number Generator
pub trait Rand: CryptoRng + RngCore {
    /// Returns a random value of type `Self`, sampled according to the given `distribution`,
    /// generated from `self`.
    #[inline]
    fn sample<D, T>(&mut self, distribution: D) -> T
    where
        T: Sample<D>,
    {
        T::sample(distribution, self)
    }

    /// Returns an iterator over `iter` which samples from `self`.
    #[inline]
    fn sample_iter<D, T>(&mut self, iter: D) -> DistIter<D, T, Self>
    where
        D: Iterator,
        T: Sample<D::Item>,
    {
        DistIter::new(iter, self)
    }

    /// Tries to return a random value of type `Self`, sampled according to the given
    /// `distribution`, generated from `self`.
    #[inline]
    fn try_sample<D, T>(&mut self, distribution: D) -> Result<T, T::Error>
    where
        T: TrySample<D>,
    {
        T::try_sample(distribution, self)
    }

    /// Returns a random value of type `Self`, sampled according to the default distribution of
    /// type `D`, generated from `rng`.
    #[inline]
    fn gen<D, T>(&mut self) -> T
    where
        D: Default,
        T: Sample<D>,
    {
        T::gen(self)
    }

    /// Tries to return a random value of type `Self`, sampled according to the default
    /// distribution of type `D`, generated from the `rng`.
    #[inline]
    fn try_gen<D, T>(&mut self) -> Result<T, T::Error>
    where
        D: Default,
        T: TrySample<D>,
    {
        T::try_gen(self)
    }

    /// Fills a buffer of `N` bytes randomly.
    #[inline]
    fn gen_bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut bytes = [0; N];
        self.fill_bytes(&mut bytes);
        bytes
    }

    /// Generates a random value in the given `range`.
    #[cfg(feature = "rand")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "rand")))]
    #[inline]
    fn gen_range<T, R>(&mut self, range: R) -> T
    where
        T: SampleUniform,
        R: SampleRange<T>,
    {
        rand::Rng::gen_range(self, range)
    }

    /// Selects a random item from `iter` by sampling an index less than or equal to the length of
    /// `iter` and then traversing to that element, returning it if it exists.
    #[cfg(feature = "rand")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "rand")))]
    #[inline]
    fn select_item<I>(&mut self, iter: I) -> Option<I::Item>
    where
        I: IntoIterator,
        I::IntoIter: ExactSizeIterator,
    {
        let mut iter = iter.into_iter();
        match iter.len() {
            0 => None,
            n => iter.nth(self.gen_range(0..n)),
        }
    }

    /// Seeds another random number generator `R` using entropy from `self`.
    #[inline]
    fn seed_rng<R>(&mut self) -> Result<R, Error>
    where
        R: SeedableRng,
    {
        R::from_rng(self)
    }
}

impl<R> Rand for R where R: CryptoRng + RngCore + ?Sized {}
