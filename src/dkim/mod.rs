pub mod types;
pub(crate) mod parser;
pub mod key;
pub mod canon;

pub use types::{
    Algorithm, CanonicalizationMethod, DkimResult, DkimSignature, FailureKind, HashAlgorithm,
    KeyFlag, KeyType, PermFailKind,
};
pub use key::DkimPublicKey;
