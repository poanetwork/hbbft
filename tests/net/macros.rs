/// Try-return a result, wrapped in `Some`.
///
/// Like `try!`, but wraps into an `Option::Some` as well. Useful for iterators
/// that return `Option<Result<_, _>>`.
macro_rules! try_some {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return Some(Err(From::from(e))),
        }
    };
}
