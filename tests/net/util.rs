//! Utility functions
//!
//! A collection of miscellaneous functions that are used in the tests, but are generic enough to be
//! factored out.

use env_logger;

/// Try-return a result, wrapped in `Some`.
///
/// Like `try!`, but wraps into an `Option::Some` as well. Useful for iterators
/// that return `Option<Result<_, _>>`.
#[macro_export]
macro_rules! try_some {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return Some(Err(From::from(e))),
        }
    };
}

/// Initialize logging.
///
/// Sets up logging to stdout.
pub fn init_logging() {
    // FIXME: Consider slog for logging instead.
    // FIXME: Support multiple calls of `init_logging`.
    env_logger::try_init().unwrap();
    info!("Logging initialized");
}
