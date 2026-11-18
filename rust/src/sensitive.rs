//! The narrow list of files an agent should never read raw, and `env-keys`, which shows what such a
//! file holds without its values. The broad `redact::is_sensitive_path` stays the rule for
//! indexing and searching; this list is what other tools refuse to open.

use std::fs;

use crate::redact;

/// A folder with one of these names anywhere in the path.
pub const DIRS: &[&str] = &[".ssh", ".aws", ".gnupg", ".kube"];
/// File names, matched exactly. A trailing `*` means "starts with".
pub const NAMES: &[&str] = &[
    ".env*", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".netrc", ".npmrc", ".pypirc", ".pgpass", ".git-credentials",
];
/// File extensions, without the dot.
pub const EXTENSIONS: &[&str] = &["pem", "key", "p12", "pfx", "jks", "keystore", "ppk", "kdbx", "tfvars", "tfstate"];
/// A name ending in one of these is a template with no secrets, so it is not on the list.
pub const EXEMPT_SUFFIXES: &[&str] = &[".example", ".sample", ".template"];

/// The list as JSON, one line, keys in a fixed order.
pub fn json() -> String {
    let array = |items: &[&str]| format!("[{}]", items.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(","));
    format!(
        "{{\"dirs\":{},\"names\":{},\"extensions\":{},\"exempt_suffixes\":{}}}\n",
        array(DIRS),
        array(NAMES),
        array(EXTENSIONS),
        array(EXEMPT_SUFFIXES)
    )
}

/// The list's meaning, for tests. Other tools reimplement it from the JSON.
#[cfg(test)]
pub fn matches(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    let mut parts = lower.split(['/', '\\']).collect::<Vec<_>>();
    let Some(name) = parts.pop() else { return false };
    if parts.iter().any(|p| DIRS.contains(p)) {
        return true;
    }
    if EXEMPT_SUFFIXES.iter().any(|s| name.ends_with(s)) {
        return false;
    }
    NAMES.iter().any(|n| match n.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == *n,
    }) || name.rsplit_once('.').is_some_and(|(_, ext)| EXTENSIONS.contains(&ext))
}

/// The longest key name printed. Real names are short; a long one is probably not a name.
const MAX_KEY_CHARS: usize = 64;
const MAX_ENV_BYTES: u64 = 500_000;

/// The key names in a `.env`-style file, in order, each once. Never a value, an `=`, or a line
/// that is not `NAME=...`. Values that run over several lines (a quote, a key block, a trailing
/// backslash) are skipped whole.
pub fn env_keys(text: &str) -> Vec<String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut keys: Vec<String> = Vec::new();
    // The previous line ended in a backslash, so this one is still its value.
    let mut continued = false;
    // The quote that opened a value still running on later lines.
    let mut open: Option<char> = None;
    // An unquoted PEM block runs until its END line; its base64 lines can look like `NAME=`.
    let mut in_pem = false;
    for line in text.lines() {
        if in_pem {
            if line.contains("-----END") {
                in_pem = false;
                // A quoted block can close its quote on the END line.
                open = open.filter(|q| !closes(line, *q));
            }
            continue;
        }
        if let Some(q) = open {
            if closes(line, q) {
                open = None;
            }
            continue;
        }
        let was_continued = continued;
        continued = ends_in_backslash(line);
        if was_continued {
            // Still part of the value: a quote opened here runs on to later lines.
            open = unclosed_quote(line);
            if open.is_some() {
                continued = false;
            }
            continue;
        }
        // Whatever the line is, a key block it opens hides the lines up to its end.
        in_pem = line.contains("-----BEGIN") && !line.contains("-----END");
        let line = line.trim();
        if line.starts_with('#') {
            continued = false;
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim();
        let value = value.trim_start();
        // A quote that opens a value and doesn't close on this line runs on to later lines,
        // whether or not the name before it is one this prints.
        open = value.chars().next().filter(|c| matches!(c, '"' | '\'' | '`')).filter(|q| !closes(&value[1..], *q));
        if open.is_some() || in_pem {
            continued = false;
        }
        // `abc==` is base64 padding, not a key with a value.
        if !is_key(key) || value.starts_with('=') || (value.is_empty() && looks_encoded(key)) {
            continue;
        }
        if redact::clean(key).as_deref() == Some(key) && !keys.iter().any(|k| k == key) {
            keys.push(key.to_string());
        }
    }
    keys
}

/// The quote left open at the end of `line`, if any.
fn unclosed_quote(line: &str) -> Option<char> {
    let mut open: Option<char> = None;
    let mut escaped = false;
    for c in line.chars() {
        match (c, open) {
            ('\\', Some(q)) if q != '\'' => escaped = !escaped,
            (q @ ('"' | '\'' | '`'), None) => open = Some(q),
            (c, Some(q)) if c == q && !escaped => open = None,
            _ => escaped = false,
        }
        if c != '\\' {
            escaped = false;
        }
    }
    open
}

/// True when `line` holds an unescaped `quote`.
fn closes(line: &str, quote: char) -> bool {
    let mut escaped = false;
    for c in line.chars() {
        match c {
            '\\' if quote != '\'' => escaped = !escaped,
            c if c == quote && !escaped => return true,
            _ => escaped = false,
        }
    }
    false
}

/// An identifier: `[A-Za-z_][A-Za-z0-9_.]*`, not too long.
fn is_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && key.chars().count() <= MAX_KEY_CHARS
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
}

/// Upper case, lower case and digits mixed with no separator: base64 like `c2VjcmV0cGFzc3dvcmQ=`,
/// not a name like `API_KEY` or `port2`.
fn looks_encoded(key: &str) -> bool {
    key.bytes().any(|b| b.is_ascii_uppercase())
        && key.bytes().any(|b| b.is_ascii_lowercase())
        && key.bytes().any(|b| b.is_ascii_digit())
        && !key.contains(['_', '.'])
}

/// True when `line` ends in an odd number of backslashes, which carries the value to the next line.
fn ends_in_backslash(line: &str) -> bool {
    line.trim_end_matches(['\r', ' ', '\t']).bytes().rev().take_while(|b| *b == b'\\').count() % 2 == 1
}

/// `quarry env-keys <file>`: the key names, one per line.
pub fn run_env_keys(file: &str) -> Result<(), String> {
    let meta = fs::metadata(file).map_err(|e| format!("quarry: can't read {}: {e}", clean_name(file)))?;
    if !meta.is_file() || meta.len() > MAX_ENV_BYTES {
        return Err(format!("quarry: {} is not a file of a size env-keys reads", clean_name(file)));
    }
    let bytes = fs::read(file).map_err(|e| format!("quarry: can't read {}: {e}", clean_name(file)))?;
    let text = String::from_utf8_lossy(&bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    // A key file's lines are secret text that can look like `NAME=`, so it is not read at all. A
    // .env value holding a key starts after `NAME=`, never at the start of a line.
    if text.lines().any(|l| l.trim_start().starts_with("-----BEGIN")) || text.contains('\0') {
        return Err(format!("quarry: {} is a key file, not an env file", clean_name(file)));
    }
    let keys = env_keys(text);
    crate::emit(&keys.iter().map(|k| format!("{k}\n")).collect::<String>());
    Ok(())
}

fn clean_name(path: &str) -> String {
    redact::clean(path).unwrap_or_else(|| redact::MARK.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_matches_what_the_plan_says() {
        for yes in [
            ".env", ".env.local", ".ENV.production", "app/.env", "a.pem", "x/server.KEY", "c.p12", "c.pfx", "s.jks",
            "s.keystore", "k.ppk", "db.kdbx", "prod.tfvars", "terraform.tfstate", "id_rsa", "ssh/id_ed25519",
            ".netrc", ".npmrc", ".pypirc", ".pgpass", ".git-credentials", ".ssh/config", "home/.aws/credentials",
            "x/.gnupg/a", ".kube/config",
        ] {
            assert!(matches(yes), "{yes}");
        }
        for no in [
            ".env.example", ".env.local.sample", ".env.template", "src/app.ts", "PasswordResetForm.tsx", "id_rsa.pub",
            "secrets_manager.py", "env.ts", "keys.ts", "README.md", ".github/workflows/ci.yml", "a/ssh/config",
        ] {
            assert!(!matches(no), "{no}");
        }
    }

    #[test]
    fn grep_withholds_everything_on_the_narrow_list() {
        // grep refuses files by the broad rule, so the broad rule must cover the narrow list.
        let mut paths: Vec<String> = DIRS.iter().map(|d| format!("x/{d}/f.txt")).collect();
        paths.extend(NAMES.iter().map(|n| n.replace('*', ".local")));
        paths.extend(EXTENSIONS.iter().map(|e| format!("a/f.{e}")));
        for p in paths {
            assert!(matches(&p), "{p}");
            assert!(redact::is_sensitive_path(&p), "{p}");
        }
    }

    #[test]
    fn json_has_the_four_keys_in_order() {
        let j = json();
        let at = |k: &str| j.find(&format!("\"{k}\"")).unwrap();
        assert!(at("dirs") < at("names") && at("names") < at("extensions") && at("extensions") < at("exempt_suffixes"));
        assert!(j.ends_with("}\n") && j.matches('\n').count() == 1);
        assert!(j.contains("\".env*\""));
    }

    #[test]
    fn env_keys_prints_names_only() {
        let text = "# comment\nA=1\nexport B = \"two words\"\n\nA=again\nC.D_E=x\nD-E=x\n=bad\n1BAD=x\nnot a pair\nE=\n";
        assert_eq!(env_keys(text), ["A", "B", "C.D_E", "E"]);
    }

    #[test]
    fn a_value_that_runs_over_several_lines_hides_its_inner_lines() {
        let text = "BEFORE=1\nKEY=\"first line\nSECRET_LOOKING=abc==\nlast line\"\nAFTER='x\ny=z\n'\nEND=1\n";
        assert_eq!(env_keys(text), ["BEFORE", "KEY", "AFTER", "END"]);
    }

    #[test]
    fn an_unquoted_key_block_hides_its_lines() {
        let k = ["RSA PRIVATE", " KEY-----"].concat();
        let text = format!("A=1\nPRIV=-----BEGIN {k}\nMIIBOgIBAAJBAKj34Gkx=\nAb3xQ==\n-----END {k}\nB=2\n");
        assert_eq!(env_keys(&text), ["A", "PRIV", "B"]);
        // One that never ends hides the rest of the file.
        assert_eq!(env_keys(&format!("A=1\nPRIV=-----BEGIN {k}\nAb3xQ==\nB=2\n")), ["A", "PRIV"]);
        assert_eq!(env_keys(&format!("A=-----BEGIN {k}x-----END {k}\nB=2\n")), ["A", "B"]);
        assert_eq!(env_keys(&format!("Q=\"-----BEGIN {k}\nAb3xQ==\n-----END {k}\"\nB=2\n")), ["Q", "B"]);
        assert_eq!(env_keys(&format!("Q=\"-----BEGIN {k}\nAb3xQ==\n-----END {k}\nx=\"\nB=2\n")), ["Q", "B"]);
        assert_eq!(env_keys(&format!("not a key: -----BEGIN {k}\nAb3xQ==\n-----END {k}\nB=2\n")), ["B"]);
    }

    #[test]
    fn base64_and_continued_lines_are_not_keys() {
        let text = "A=1\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC==\nc2VjcmV0cGFzc3dvcmQ=\ndGVzdA==\nB=one \\\ncontinuedSECRETpart=more \\\nalsoSecret=x\nC=2\nD=ends in escaped \\\\\nE=3\n";
        assert_eq!(env_keys(text), ["A", "B", "C", "D", "E"]);
        // A quote opened after a name this does not print still hides the lines inside it.
        assert_eq!(env_keys("my-key=\"first\nsecretPart=x\n\"\nF=1\n"), ["F"]);
    }

    #[test]
    fn a_quote_opened_on_a_continued_line_still_hides_its_lines() {
        assert_eq!(env_keys("A=\\\n\"first\nLEAKkeyA=1\nlast\"\nB=2\n"), ["A", "B"]);
        assert_eq!(env_keys("A=\\\n\"one line\"\nB=2\n"), ["A", "B"]);
    }

    #[test]
    fn a_bom_and_crlf_lines_are_read() {
        assert_eq!(env_keys("\u{feff}FIRST=1\r\nSECOND=\"a\r\nb\"\r\nTHIRD=3\r\n"), ["FIRST", "SECOND", "THIRD"]);
    }

    #[test]
    fn an_escaped_quote_does_not_close_a_value() {
        assert_eq!(env_keys("A=\"x\\\"\nB=1\"\nC=1\n"), ["A", "C"]);
    }

    #[test]
    fn a_key_that_looks_like_a_token_or_is_too_long_is_skipped() {
        let token = ["gh", "p_", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7aB3dE6gH9"].concat();
        let long = "A".repeat(MAX_KEY_CHARS + 1);
        assert_eq!(env_keys(&format!("{token}=1\n{long}=1\nOK=1\n")), ["OK"]);
    }
}
