//! Lexical profile declarations for the Phantom Safety Net (Layer 1).
//!
//! A [`LexicalProfile`] describes the comment introducers, string literal forms,
//! and bracket delimiter pairs for a language so that the host's Phantom Safety Net
//! can validate delimiter balancing and literal health with sub-millisecond native speed
//! and zero FFI roundtrips during editing.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Current lexical profile schema version understood by Basalt Core.
pub const LEXICAL_PROFILE_VERSION: u32 = 1;

/// String literal specification (delimiters, escape char, and optional interpolation).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StringSpec {
    pub open: String,
    pub close: String,
    pub escape: Option<char>,
    pub interpolation: Option<(String, String)>,
}

impl StringSpec {
    /// Create a standard string literal with matching open and close delimiters and `\` escape.
    pub fn simple(delimiter: &str) -> Self {
        Self {
            open: delimiter.to_string(),
            close: delimiter.to_string(),
            escape: Some('\\'),
            interpolation: None,
        }
    }

    /// Create a raw string literal with no escape character.
    pub fn raw(delimiter: &str) -> Self {
        Self {
            open: delimiter.to_string(),
            close: delimiter.to_string(),
            escape: None,
            interpolation: None,
        }
    }

    /// Create a string literal with custom interpolation syntax (e.g. `${...}` in JS/TS).
    pub fn with_interpolation(delimiter: &str, open_interp: &str, close_interp: &str) -> Self {
        Self {
            open: delimiter.to_string(),
            close: delimiter.to_string(),
            escape: Some('\\'),
            interpolation: Some((open_interp.to_string(), close_interp.to_string())),
        }
    }
}

/// Irregular lexemes handled by dedicated Core scanning logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SpecialLexeme {
    /// Rust `r"..."`, `r#"..."#`, `br##"..."##` (variable `#` depth).
    RustRawString,
    /// Rust `'a` lifetimes disambiguated from character literals `'a'`.
    RustLifetime,
    /// Lua `[[...]]`, `[==[...]==]` long brackets and `--[[ ... ]]` long comments.
    LuaLongBracket,
}

impl SpecialLexeme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RustRawString => "RustRawString",
            Self::RustLifetime => "RustLifetime",
            Self::LuaLongBracket => "LuaLongBracket",
        }
    }
}

/// Declarative language profile for Phantom Safety Net delimiter validation.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LexicalProfile {
    pub version: u32,
    pub extensions: Vec<String>,
    pub line_comments: Vec<String>,
    pub block_comment: Option<(String, String)>,
    pub nested_block_comments: bool,
    pub strings: Vec<StringSpec>,
    pub special: Vec<SpecialLexeme>,
    pub delimiters: Vec<(char, char)>,
    pub multiline_strings: bool,
}

impl Default for LexicalProfile {
    fn default() -> Self {
        Self {
            version: LEXICAL_PROFILE_VERSION,
            extensions: Vec::new(),
            line_comments: Vec::new(),
            block_comment: None,
            nested_block_comments: false,
            strings: Vec::new(),
            special: Vec::new(),
            delimiters: vec![('(', ')'), ('[', ']'), ('{', '}')],
            multiline_strings: true,
        }
    }
}

impl LexicalProfile {
    /// Create a new blank lexical profile.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an extra file extension handled by this profile.
    pub fn with_extension(mut self, ext: impl Into<String>) -> Self {
        self.extensions.push(ext.into());
        self
    }

    /// Add a line comment introducer (e.g. `"//"`, `"#"`).
    pub fn with_line_comment(mut self, comment: impl Into<String>) -> Self {
        self.line_comments.push(comment.into());
        self
    }

    /// Set block comment delimiters (e.g. `("/*", "*/")`).
    pub fn with_block_comment(mut self, open: impl Into<String>, close: impl Into<String>) -> Self {
        self.block_comment = Some((open.into(), close.into()));
        self
    }

    /// Enable support for nested block comments (e.g. Rust, Swift, Haskell).
    pub fn with_nested_block_comments(mut self, nested: bool) -> Self {
        self.nested_block_comments = nested;
        self
    }

    /// Add a string literal specification.
    pub fn with_string(mut self, spec: StringSpec) -> Self {
        self.strings.push(spec);
        self
    }

    /// Enable a special irregular lexeme scanner.
    pub fn with_special(mut self, special: SpecialLexeme) -> Self {
        self.special.push(special);
        self
    }

    /// Set custom bracket delimiters to check (defaults to `()`, `[]`, `{}`).
    pub fn with_delimiters(mut self, delimiters: Vec<(char, char)>) -> Self {
        self.delimiters = delimiters;
        self
    }

    /// Standard C-family language template (`//`, `/* */`, `"..."`, `'...'`).
    pub fn c_like() -> Self {
        Self::default()
            .with_line_comment("//")
            .with_block_comment("/*", "*/")
            .with_string(StringSpec::simple("\""))
            .with_string(StringSpec::simple("'"))
    }

    /// Hash-comment language template (`#`, `"""`, `'''`, `"`, `'`).
    pub fn hash_like() -> Self {
        Self::default()
            .with_line_comment("#")
            .with_string(StringSpec::simple("\"\"\""))
            .with_string(StringSpec::simple("'''"))
            .with_string(StringSpec::simple("\""))
            .with_string(StringSpec::simple("'"))
    }

    /// JavaScript / TypeScript template (C-family + backtick template literals with `${...}`).
    pub fn js_like() -> Self {
        let mut prof = Self::c_like();
        prof.strings.push(StringSpec::with_interpolation("`", "${", "}"));
        prof
    }

    /// Convert profile to JSON string without requiring the `serde` crate dependency.
    pub fn to_json(&self) -> String {
        let mut out = String::from("{\n");
        out.push_str(&format!("  \"version\": {},\n", self.version));

        // extensions
        out.push_str("  \"extensions\": [");
        for (i, ext) in self.extensions.iter().enumerate() {
            if i > 0 { out.push_str(", "); }
            out.push_str(&format!("\"{}\"", escape_json(ext)));
        }
        out.push_str("],\n");

        // line_comments
        out.push_str("  \"line_comments\": [");
        for (i, lc) in self.line_comments.iter().enumerate() {
            if i > 0 { out.push_str(", "); }
            out.push_str(&format!("\"{}\"", escape_json(lc)));
        }
        out.push_str("],\n");

        // block_comment
        if let Some((o, c)) = &self.block_comment {
            out.push_str(&format!("  \"block_comment\": [\"{}\", \"{}\"],\n", escape_json(o), escape_json(c)));
        } else {
            out.push_str("  \"block_comment\": null,\n");
        }

        // nested_block_comments
        out.push_str(&format!("  \"nested_block_comments\": {},\n", self.nested_block_comments));

        // strings
        out.push_str("  \"strings\": [\n");
        for (i, s) in self.strings.iter().enumerate() {
            if i > 0 { out.push_str(",\n"); }
            out.push_str("    {\n");
            out.push_str(&format!("      \"open\": \"{}\",\n", escape_json(&s.open)));
            out.push_str(&format!("      \"close\": \"{}\",\n", escape_json(&s.close)));
            if let Some(esc) = s.escape {
                let esc_str = if esc == '\\' { "\\\\" } else { &esc.to_string() };
                out.push_str(&format!("      \"escape\": \"{}\",\n", esc_str));
            } else {
                out.push_str("      \"escape\": null,\n");
            }
            if let Some((io, ic)) = &s.interpolation {
                out.push_str(&format!("      \"interpolation\": [\"{}\", \"{}\"]\n", escape_json(io), escape_json(ic)));
            } else {
                out.push_str("      \"interpolation\": null\n");
            }
            out.push_str("    }");
        }
        out.push_str("\n  ],\n");

        // special
        out.push_str("  \"special\": [");
        for (i, sp) in self.special.iter().enumerate() {
            if i > 0 { out.push_str(", "); }
            out.push_str(&format!("\"{}\"", sp.as_str()));
        }
        out.push_str("],\n");

        // delimiters
        out.push_str("  \"delimiters\": [");
        for (i, (o, c)) in self.delimiters.iter().enumerate() {
            if i > 0 { out.push_str(", "); }
            out.push_str(&format!("[\"{}\", \"{}\"]", escape_json(&o.to_string()), escape_json(&c.to_string())));
        }
        out.push_str("],\n");

        // multiline_strings
        out.push_str(&format!("  \"multiline_strings\": {}\n", self.multiline_strings));

        out.push('}');
        out
    }
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_like_profile_to_json() {
        let p = LexicalProfile::c_like();
        let json = p.to_json();
        assert!(json.contains("\"version\": 1"));
        assert!(json.contains("\"//\""));
        assert!(json.contains("[\"/*\", \"*/\"]"));
    }

    #[test]
    fn js_like_profile_with_interpolation() {
        let p = LexicalProfile::js_like();
        let json = p.to_json();
        assert!(json.contains("\"interpolation\": [\"${\", \"}\"]"));
    }
}
