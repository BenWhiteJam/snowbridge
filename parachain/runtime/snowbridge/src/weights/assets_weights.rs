
//! Autogenerated weights for assets
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 3.0.0
//! DATE: 2021-05-08, STEPS: `[50, ]`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("/tmp/artemis-benchmark-tce/spec.json"), DB CACHE: 128

// Executed Command:
// target/release/artemis
// benchmark
// --chain
// /tmp/artemis-benchmark-tce/spec.json
// --execution
// wasm
// --wasm-execution
// compiled
// --pallet
// assets
// --extrinsic
// *
// --repeat
// 20
// --steps
// 50
// --output
// runtime/snowbridge/src/weights/assets_weights.rs


#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions for assets.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> assets::WeightInfo for WeightInfo<T> {
	fn transfer() -> Weight {
		(23_882_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(2 as Weight))
			.saturating_add(T::DbWeight::get().writes(2 as Weight))
	}
}
