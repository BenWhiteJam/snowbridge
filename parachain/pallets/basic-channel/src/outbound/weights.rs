//! Autogenerated weights for basic_channel::outbound
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2021-11-25, STEPS: `50`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("spec.json"), DB CACHE: 128

// Executed Command:
// target/release/snowbridge
// benchmark
// --chain
// spec.json
// --execution
// wasm
// --wasm-execution
// compiled
// --pallet
// basic_channel::outbound
// --extra
// --extrinsic
// *
// --repeat
// 20
// --steps
// 50
// --output
// pallets/basic-channel/src/outbound/weights.rs
// --template
// module-weight-template.hbs


#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use sp_std::marker::PhantomData;

/// Weight functions needed for basic_channel::outbound.
pub trait WeightInfo {
	fn on_initialize(m: u32, p: u32, ) -> Weight;
	fn on_initialize_non_interval() -> Weight;
	fn on_initialize_no_messages() -> Weight;
}

/// Weights for basic_channel::outbound using the Snowbridge node and recommended hardware.
pub struct SnowbridgeWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SnowbridgeWeight<T> {
	fn on_initialize(m: u32, p: u32, ) -> Weight {
		(0 as Weight)
			// Standard Error: 31_000
			.saturating_add((10_849_000 as Weight).saturating_mul(m as Weight))
			// Standard Error: 1_000
			.saturating_add((388_000 as Weight).saturating_mul(p as Weight))
			.saturating_add(T::DbWeight::get().reads(3 as Weight))
			.saturating_add(T::DbWeight::get().writes(2 as Weight))
	}
	fn on_initialize_non_interval() -> Weight {
		(3_294_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(1 as Weight))
	}
	fn on_initialize_no_messages() -> Weight {
		(5_228_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(2 as Weight))
	}
}

// For backwards compatibility and tests
impl WeightInfo for () {
	fn on_initialize(m: u32, p: u32, ) -> Weight {
		(0 as Weight)
			// Standard Error: 31_000
			.saturating_add((10_849_000 as Weight).saturating_mul(m as Weight))
			// Standard Error: 1_000
			.saturating_add((388_000 as Weight).saturating_mul(p as Weight))
			.saturating_add(RocksDbWeight::get().reads(3 as Weight))
			.saturating_add(RocksDbWeight::get().writes(2 as Weight))
	}
	fn on_initialize_non_interval() -> Weight {
		(3_294_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(1 as Weight))
	}
	fn on_initialize_no_messages() -> Weight {
		(5_228_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(2 as Weight))
	}
}
