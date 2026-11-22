use std::path::Path;

use muxtastic_core::config::{LogLevel, LoggingConfig};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

/// Daily log files kept on disk; older ones are deleted on rotation.
const MAX_LOG_FILES: usize = 14;

/// Install tracing. The returned guard must stay alive for file logging.
pub fn init(config: &LoggingConfig) -> Option<WorkerGuard> {
    let level = match config.level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warning => "warn",
        LogLevel::Error => "error",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    let appender = config
        .file
        .as_deref()
        .map(str::trim)
        .filter(|file| !file.is_empty())
        .and_then(open_appender);

    match (appender, config.console) {
        (Some(appender), true) => {
            let (writer, guard) = tracing_appender::non_blocking(appender);
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().with_writer(std::io::stdout))
                .with(fmt::layer().with_writer(writer).with_ansi(false))
                .init();
            Some(guard)
        }
        (Some(appender), false) => {
            let (writer, guard) = tracing_appender::non_blocking(appender);
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().with_writer(writer).with_ansi(false))
                .init();
            Some(guard)
        }
        (None, true) => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().with_writer(std::io::stdout))
                .init();
            None
        }
        (None, false) => {
            tracing_subscriber::registry().with(filter).init();
            None
        }
    }
}

/// Open the daily-rotated log file, keeping at most [`MAX_LOG_FILES`] files.
/// On failure, report it on stderr and continue without file logging.
fn open_appender(file: &str) -> Option<RollingFileAppender> {
    let path = Path::new(file);
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("muxtastic.log");

    if let Err(error) = std::fs::create_dir_all(directory) {
        eprintln!(
            "muxtastic: cannot create log directory {}: {error}; continuing without file logging",
            directory.display()
        );
        return None;
    }

    match RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(filename)
        .max_log_files(MAX_LOG_FILES)
        .build(directory)
    {
        Ok(appender) => Some(appender),
        Err(error) => {
            eprintln!(
                "muxtastic: cannot open log file in {}: {error}; continuing without file logging",
                directory.display()
            );
            None
        }
    }
}
