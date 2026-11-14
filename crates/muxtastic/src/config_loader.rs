use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use muxtastic_core::config::Config;

pub struct LoadedConfig {
    pub config: Config,
    pub path: Option<PathBuf>,
}

/// Load a config file. `.yaml`/`.yml` is the legacy schema, `.toml` is the
/// native schema, and both deserialize into the same [`Config`].
pub fn load(explicit: Option<&Path>, mock: bool) -> Result<LoadedConfig> {
    let path = explicit.map(Path::to_path_buf).or_else(default_path);

    let Some(path) = path else {
        if mock {
            return Ok(LoadedConfig {
                config: Config::default(),
                path: None,
            });
        }
        anyhow::bail!(
            "no config found; pass --config PATH or create muxtastic.toml / configs/config.yaml"
        );
    };

    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    let config = parse(&path, &text)?;
    config.validate()?;

    Ok(LoadedConfig {
        config,
        path: Some(path),
    })
}

fn default_path() -> Option<PathBuf> {
    [
        "muxtastic.toml",
        "configs/muxtastic.toml",
        "configs/config.yaml",
        "configs/config.yml",
        "config.yaml",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|path| path.exists())
}

fn parse(path: &Path, text: &str) -> Result<Config> {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match extension.as_str() {
        "toml" => {
            toml::from_str(text).with_context(|| format!("invalid TOML config {}", path.display()))
        }
        "yaml" | "yml" => serde_yaml_ng::from_str(text)
            .with_context(|| format!("invalid YAML config {}", path.display())),
        _ => toml::from_str(text)
            .or_else(|toml_error| {
                serde_yaml_ng::from_str(text).map_err(|yaml_error| {
                    anyhow::anyhow!("could not parse as TOML ({toml_error}) or YAML ({yaml_error})")
                })
            })
            .with_context(|| format!("invalid config {}", path.display())),
    }
}
