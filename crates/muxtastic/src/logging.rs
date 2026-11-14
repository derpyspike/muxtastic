use std::path::Path;

use muxtastic_core::config::{LogLevel, LoggingConfig};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

/// Install tracing. The returned guard must stay alive for file logging.
pub fn init(config: &LoggingConfig) -> Option<WorkerGuard> {
    let level = match config.level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warning => "warn",
        LogLevel::Error => "error",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    let file = config
        .file
        .as_deref()
        .map(str::trim)
        .filter(|file| !file.is_empty());

    if let Some(file) = file {
        let path = Path::new(file);
        let directory = path.parent().unwrap_or_else(|| Path::new("."));
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("muxtastic.log");

        if let Err(error) = std::fs::create_dir_all(directory) {
            eprintln!(
                "muxtastic: cannot create log directory {}: {error}; continuing console-only",
                directory.display()
            );
        } else if config.console {
            let appender = tracing_appender::rolling::daily(directory, filename);
            let (writer, guard) = tracing_appender::non_blocking(appender);
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().with_writer(std::io::stdout))
                .with(fmt::layer().with_writer(writer).with_ansi(false))
                .init();
            return Some(guard);
        } else {
            let appender = tracing_appender::rolling::daily(directory, filename);
            let (writer, guard) = tracing_appender::non_blocking(appender);
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().with_writer(writer).with_ansi(false))
                .init();
            return Some(guard);
        }
    }

    if config.console {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_writer(std::io::stdout))
            .init();
    } else {
        tracing_subscriber::registry().with(filter).init();
    }
    None
}
