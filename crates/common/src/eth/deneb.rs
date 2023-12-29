pub use ethereum_consensus::{builder::SignedValidatorRegistration, deneb::mainnet as spec};

use ethereum_consensus::{
    deneb::{mainnet::{MAX_BLOBS_PER_BLOCK, MAX_BLOB_COMMITMENTS_PER_BLOCK}, polynomial_commitments::{KzgCommitment, KzgProof}},
    primitives::{BlsPublicKey, BlsSignature, Root, U256},
    ssz::prelude::*,
    serde::as_str,
};

pub type ExecutionPayload = spec::ExecutionPayload;
pub type ExecutionPayloadHeader = spec::ExecutionPayloadHeader;
pub type SignedBlindedBeaconBlock = spec::SignedBlindedBeaconBlock;
pub type SignedBlindedBlobSidecar = spec::SignedBlindedBlobSidecar;
pub type Blob = spec::Blob;

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct BuilderBid {
    pub header: spec::ExecutionPayloadHeader,
    pub blinded_blobs_bundle: BlindedBlobsBundle,
    #[serde(with = "as_str")]
    pub value: U256,
    #[serde(rename = "pubkey")]
    pub public_key: BlsPublicKey,
}

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct BlindedBlobsBundle {
    pub commitments: List<KzgCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    pub proofs: List<KzgProof, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    pub blob_roots: List<Root, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
}

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct SignedBuilderBid {
    pub message: BuilderBid,
    pub signature: BlsSignature,
}

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct SignedBlindedBlockAndBlobSidecars {
    pub signed_blinded_block: SignedBlindedBeaconBlock,
    pub signed_blinded_blob_sidecars: List<SignedBlindedBlobSidecar, MAX_BLOBS_PER_BLOCK>,
}

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct BlobsBundle {
    pub commitments: List<KzgCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    pub proofs: List<KzgProof, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    pub blobs: List<Blob, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
}

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct ExecutionPayloadAndBlobsBundle {
    pub execution_payload: ExecutionPayload,
    pub blobs_bundle: BlobsBundle,
}
