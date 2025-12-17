//! Silent logging module
//!
//! Quando a feature "silent" está ativa, os logs são desativados
//! para evitar strings detectáveis no binário.

/// Macro que só faz log se a feature "silent" NÃO estiver ativa
#[macro_export]
#[cfg(not(feature = "silent"))]
macro_rules! log_info {
    ($($arg:tt)*) => {
        tracing::info!($($arg)*)
    };
}

#[macro_export]
#[cfg(feature = "silent")]
macro_rules! log_info {
    ($($arg:tt)*) => {
        // Noop - sem logs
        let _ = || { format!($($arg)*) };
    };
}

#[macro_export]
#[cfg(not(feature = "silent"))]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        tracing::warn!($($arg)*)
    };
}

#[macro_export]
#[cfg(feature = "silent")]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        let _ = || { format!($($arg)*) };
    };
}

#[macro_export]
#[cfg(not(feature = "silent"))]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        tracing::debug!($($arg)*)
    };
}

#[macro_export]
#[cfg(feature = "silent")]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        let _ = || { format!($($arg)*) };
    };
}

#[macro_export]
#[cfg(not(feature = "silent"))]
macro_rules! log_error {
    ($($arg:tt)*) => {
        tracing::error!($($arg)*)
    };
}

#[macro_export]
#[cfg(feature = "silent")]
macro_rules! log_error {
    ($($arg:tt)*) => {
        let _ = || { format!($($arg)*) };
    };
}
