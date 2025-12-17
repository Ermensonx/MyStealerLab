//! Utils and environment checks

pub mod anti_analysis;
pub mod anti_debug;
pub mod evasion;
pub mod helpers;
pub mod obfuscated_strings;

#[allow(unused_imports)]
pub use anti_analysis::EnvironmentChecker;
#[allow(unused_imports)]
pub use anti_debug::{is_debugger_attached, guarded_execute, junk_code_block, opaque_true};
#[allow(unused_imports)]
pub use evasion::{EvasionResult, initial_delay, run_all_checks};
#[allow(unused_imports)]
pub use helpers::{expand_path, format_size, sanitize_filename};
#[allow(unused_imports)]
pub use obfuscated_strings::*;

