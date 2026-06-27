//! Logging init and `-v` verbosity mapping (approximates klog verbosity levels).

use tracing::level_filters::LevelFilter;

/// Map the upstream `-v` numeric verbosity string to a tracing level.
///
/// klog convention: 0 = info, higher = more verbose. Anything non-numeric or
/// empty falls back to `INFO`.
pub fn verbosity_to_level(v: &str) -> LevelFilter {
    match v.trim().parse::<u32>() {
        Ok(0) => LevelFilter::INFO,
        Ok(1) => LevelFilter::DEBUG,
        Ok(_) => LevelFilter::TRACE,
        Err(_) => LevelFilter::INFO,
    }
}

/// Initialize the global tracing subscriber at the given verbosity. Idempotent:
/// a second call is a no-op (returns without error).
pub fn init(v: &str) {
    let _ = tracing_subscriber::fmt()
        .with_max_level(verbosity_to_level(v))
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_verbosity_levels() {
        assert_eq!(verbosity_to_level("0"), LevelFilter::INFO);
        assert_eq!(verbosity_to_level("1"), LevelFilter::DEBUG);
        assert_eq!(verbosity_to_level("2"), LevelFilter::TRACE);
        assert_eq!(verbosity_to_level("9"), LevelFilter::TRACE);
    }

    #[test]
    fn non_numeric_defaults_to_info() {
        assert_eq!(verbosity_to_level(""), LevelFilter::INFO);
        assert_eq!(verbosity_to_level("debug"), LevelFilter::INFO);
    }

    #[test]
    fn init_is_idempotent() {
        init("0");
        init("1");
    }
}
