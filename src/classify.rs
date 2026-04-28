//! Classifier: map (CommitRecord, allowed_principals) -> Outcome.
//!
//! Distinguishing `principal-not-in-allowed-signers` from `key-principal-
//! mismatch` is done by looking up the committer email in the allowed-signers
//! file ourselves, git's `%G?` collapses both into `U` (good signature,
//! untrusted). When the committer email is in the file (with some other key),
//! the failure is a key/principal mismatch. When it isn't, the principal is
//! unauthorized.

use std::collections::HashSet;

use crate::types::{CommitRecord, FailureReason, GpgStatusCode, Outcome};

pub fn classify(record: &CommitRecord, allowed_principals: &HashSet<String>) -> Outcome {
    match record.gpg_status {
        GpgStatusCode::Good => Outcome::Pass,
        GpgStatusCode::NoSignature => Outcome::Fail(FailureReason::Unsigned),
        GpgStatusCode::Bad
        | GpgStatusCode::GoodKeyExpiredAtSigning
        | GpgStatusCode::GoodKeyExpired
        | GpgStatusCode::GoodKeyRevoked
        | GpgStatusCode::CannotCheck => Outcome::Fail(FailureReason::SignatureInvalid),
        GpgStatusCode::GoodUntrusted => {
            // Disambiguate via committer email lookup
            let principal_present = record
                .committer_email
                .as_deref()
                .map(|e| allowed_principals.contains(&e.to_ascii_lowercase()))
                .unwrap_or(false);
            if principal_present {
                Outcome::Fail(FailureReason::KeyPrincipalMismatch)
            } else {
                Outcome::Fail(FailureReason::PrincipalNotInAllowedSigners)
            }
        }
    }
}
