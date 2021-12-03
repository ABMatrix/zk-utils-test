use sha3::{Digest, Keccak256};
use failure::Fail;

/// Trait of a replaceable hash algorithm.
pub trait Hash {
    fn hash<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Vec<u8>;
}

/// Implements Keccak256 as a Hash instance.
#[derive(Default, Debug, Clone)]
pub struct ZKeccak256 {}

impl Hash for ZKeccak256 {
    fn hash<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Vec<u8> {
        let mut hash_algorithm = Keccak256::default();
        hash_algorithm.input(input);
        hash_algorithm.result().to_vec()
    }
}

lazy_static! {
    /// Shared hash algorithm reference for quick implementation replacement.
    /// Other code should use this reference, and not directly use a specific implementation.
    pub static ref HASH: ZKeccak256 = ZKeccak256::default();
}

#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum ZKError {
    #[fail(display = "Verification failed")]
    VerificationError,
    #[fail(display = "Argument is invalid")]
    ArgumentError,
    #[fail(display = "Data cannot be parsed")]
    FormatError,
    #[fail(display = "Data cannot be decoded")]
    DecodeError,
    #[fail(display = "Indy Crypto error")]
    IndyCryptoError,
}