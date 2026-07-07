use crate::signature::utils::errors::SignatureError;
use ark_ec::PairingEngine;
use ark_serialize::SerializationError;
use thiserror::Error;

/// Errors for the pairing-free VSS modules (`mss`, `pedersen`, `encryption`,
/// `complaint`, `neji`). These are generic over a plain `ProjectiveCurve` and so
/// must not depend on `PairingEngine` (unlike [`DKGError`]). Carries only small
/// scalars/strings — never a group element — so it needs no type parameter.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum VssError {
    #[error("Share check failed for receiver {0}")]
    ShareCheck(usize),
    #[error("VSS distribution malformed: {0}")]
    Malformed(&'static str),
    #[error("Lagrange recovery received duplicate or insufficient evaluation indices")]
    BadIndices,
    #[error("Polynomial degree too small: {0}")]
    InsufficientDegree(usize),
}

impl<E: PairingEngine> From<VssError> for DKGError<E> {
    fn from(e: VssError) -> Self {
        match e {
            VssError::ShareCheck(j) => DKGError::PedersenShareCheckError(j),
            VssError::Malformed(s) => DKGError::PedersenMalformed(s),
            VssError::BadIndices => DKGError::MSSBadIndices,
            VssError::InsufficientDegree(d) => DKGError::MSSInsufficientDegree(d),
        }
    }
}

#[derive(Error, Debug)]
pub enum DKGError<E: PairingEngine> {
    #[error("Ratio incorrect")]
    RatioIncorrect,
    #[error("Evaluations are wrong: product = {0}")]
    EvaluationsCheckError(E::G1Affine),
    #[error("Could not generate evaluation domain")]
    EvaluationDomainError,
    #[error("Config, dealer and nodes had different SRSes")]
    DifferentSRS,
    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("Invalid participant ID: {0}")]
    InvalidParticipantId(usize),
    #[error("Transcripts have different degree or number of participants: self.degree={0}, other.degree={1}, self.num_participants={2}, self.num_participants={3}")]
    TranscriptDifferentConfig(usize, usize, usize, usize),
    #[error("Transcripts have different commitments")]
    TranscriptDifferentCommitments,
    #[error("MSS polynomial degree too small (need >= 1 to pin two points): {0}")]
    MSSInsufficientDegree(usize),
    #[error("MSS recovery received duplicate or insufficient evaluation indices")]
    MSSBadIndices,
    #[error("Pedersen share check (Eq. 1) failed for receiver {0}")]
    PedersenShareCheckError(usize),
    #[error("Pedersen distribution malformed: {0}")]
    PedersenMalformed(&'static str),
    #[error("Feldman share check (g^s = prod C_k^{{j^k}}) failed for receiver {0}")]
    FeldmanShareCheckError(usize),
    #[error("Feldman/Shamir polynomial degree too small (need >= 1): {0}")]
    FeldmanInsufficientDegree(usize),
}
