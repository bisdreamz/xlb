mod fixed;
mod kubernetes;
// `provider.rs` holds the shared API; its sibling modules are implementations.
#[allow(clippy::module_inception)]
mod provider;

pub use fixed::*;
pub use kubernetes::*;
pub use provider::*;
