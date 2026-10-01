//! sangward-core: everything that touches crypto, HTTP or the cache.
//!
//! Frontends must never depend on this crate; they talk to `sangward-agent`
//! over `sangward-ipc` instead.

pub mod api;
pub mod cache;
pub mod crypto;
pub mod mlock;
pub mod models;
pub mod vault;

#[cfg(feature = "test-support")]
pub mod test_support;

pub use api::{ApiClient, ApiError, Endpoints};
pub use crypto::{CryptoError, EncString, Kdf, MasterKey, SymmetricKey};
