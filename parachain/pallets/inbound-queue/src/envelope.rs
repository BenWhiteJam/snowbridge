// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Snowfork <hello@snowfork.com>
use snowbridge_core::{inbound::Log, ParaId};

use sp_core::{RuntimeDebug, H160, H256};
use sp_std::{convert::TryFrom, prelude::*};

use alloy_primitives::B256;
use alloy_sol_types::{sol, SolEvent};

sol! {
	event OutboundMessageAccepted(uint256 indexed destination, uint64 nonce, bytes32 indexed messageID, bytes payload);
}

/// An inbound message that has had its outer envelope decoded.
#[derive(Clone, RuntimeDebug)]
pub struct Envelope {
	/// The address of the outbound queue on Ethereum that emitted this message as an event log
	pub gateway: H160,
	/// The destination parachain.
	pub dest: ParaId,
	/// A nonce for enforcing replay protection and ordering.
	pub nonce: u64,
	/// An id for tracing the message on its route (has no role in bridge consensus)
	pub message_id: H256,
	/// The inner payload generated from the source application.
	pub payload: Vec<u8>,
}

#[derive(Copy, Clone, RuntimeDebug)]
pub struct EnvelopeDecodeError;

impl TryFrom<Log> for Envelope {
	type Error = EnvelopeDecodeError;

	fn try_from(log: Log) -> Result<Self, Self::Error> {
		let topics: Vec<B256> = log.topics.iter().map(|x| B256::from_slice(x.as_ref())).collect();

		let event = OutboundMessageAccepted::decode_log(topics, &log.data, true)
			.map_err(|_| EnvelopeDecodeError)?;

		Ok(Self {
			gateway: log.address,
			dest: event.destination.saturating_to::<u32>().into(),
			nonce: event.nonce,
			message_id: H256::from(event.messageID.as_ref()),
			payload: event.payload,
		})
	}
}
