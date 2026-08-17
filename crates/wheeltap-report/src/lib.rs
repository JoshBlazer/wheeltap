//! Output formats: JSON (Phase 2), Markdown and SARIF 2.1.0 (Phase 4), GitHub
//! Actions workflow commands (Phase 5).

pub mod github;
pub mod json;
pub mod markdown;
pub mod sarif;

#[cfg(test)]
mod tests_support;

/// The output formats Wheeltap emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Markdown,
    Sarif,
    /// GitHub Actions workflow commands, for inline pull-request annotations.
    Github,
}

/// Every format, for exhaustive iteration in tests and `--help`.
pub const ALL_FORMATS: [Format; 4] = [
    Format::Json,
    Format::Markdown,
    Format::Sarif,
    Format::Github,
];

impl Format {
    /// The format's canonical CLI spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Markdown => "markdown",
            Self::Sarif => "sarif",
            Self::Github => "github",
        }
    }
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Self::Json),
            "markdown" | "md" => Ok(Self::Markdown),
            "sarif" => Ok(Self::Sarif),
            "github" => Ok(Self::Github),
            other => Err(format!(
                "unknown format `{other}` (expected one of: {})",
                ALL_FORMATS
                    .iter()
                    .map(|f| f.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_round_trips_through_its_cli_spelling() {
        for format in ALL_FORMATS {
            assert_eq!(format.as_str().parse(), Ok(format));
        }
        assert!("yaml".parse::<Format>().is_err());
    }

    /// The error is what someone sees after a typo in a workflow file, where
    /// they cannot ask the binary for `--help` without editing and pushing.
    #[test]
    fn an_unknown_format_names_the_ones_that_exist() {
        let err = "yaml".parse::<Format>().unwrap_err();
        for format in ALL_FORMATS {
            assert!(err.contains(format.as_str()), "{err}");
        }
    }
}
