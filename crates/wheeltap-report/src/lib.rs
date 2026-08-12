//! Output formats: JSON (Phase 2), Markdown and SARIF 2.1.0 (Phase 4).

pub mod json;

/// The output formats Wheeltap emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Markdown,
    Sarif,
}

impl Format {
    /// The format's canonical CLI spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Markdown => "markdown",
            Self::Sarif => "sarif",
        }
    }
}

impl std::str::FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Self::Json),
            "markdown" | "md" => Ok(Self::Markdown),
            "sarif" => Ok(Self::Sarif),
            other => Err(format!("unknown format `{other}`")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_round_trips_through_its_cli_spelling() {
        for format in [Format::Json, Format::Markdown, Format::Sarif] {
            assert_eq!(format.as_str().parse(), Ok(format));
        }
        assert!("yaml".parse::<Format>().is_err());
    }
}
