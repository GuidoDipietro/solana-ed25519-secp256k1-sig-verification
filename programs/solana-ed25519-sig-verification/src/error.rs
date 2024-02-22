use anchor_lang::prelude::*;

/// Custom error codes
#[error_code]
pub enum ErrorCode {
    #[msg("Signature verification failed.")]
    SigVerificationFailed,
}
