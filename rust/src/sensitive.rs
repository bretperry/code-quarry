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
/// that is not `NAME=...`. Values that run over several lines are skipped whole.
pub fn env_keys(text: &str) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    // The quote that opened a value still running on later lines.
    let mut open: Option<char> = None;
    for line in text.lines() {
        if let Some(q) = open {
            if closes(line, q) {
                open = None;
            }
            continue;
        }
        let line = line.trim();
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim();
        if !is_key(key) {
            continue;
        }
        let value = value.trim_start();
        // A quote that opens a value and doesn't close on this line runs on to later lines.
        open = value.chars().next().filter(|c| matches!(c, '"' | '\'' | '`')).filter(|q| !closes(&value[1..], *q));
        if redact::clean(key).as_deref() == Some(key) && !keys.iter().any(|k| k == key) {
            keys.push(key.to_string());
        }
    }
    keys
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

fn is_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && key.chars().count() <= MAX_KEY_CHARS
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// `quarry env-keys <file>`: the key names, one per line.
pub fn run_env_keys(file: &str) -> Result<(), String> {
    let meta = fs::metadata(file).map_err(|e| format!("quarry: can't read {}: {e}", clean_name(file)))?;
    if !meta.is_file() || meta.len() > MAX_ENV_BYTES {
        return Err(format!("quarry: {} is not a file of a size env-keys reads", clean_name(file)));
    }
    let bytes = fs::read(file).map_err(|e| format!("quarry: can't read {}: {e}", clean_name(file)))?;
    let text = String::from_utf8_lossy(&bytes);
    // A key file's lines are secret text that can look like `NAME=`, so it is not read at all. A
    // .env value holding a key starts after `NAME=`, never at the start of a line.
    if text.lines().any(|l| l.trim_start().starts_with("-----BEGIN")) || text.contains('\0') {
        return Err(format!("quarry: {} is a key file, not an env file", clean_name(file)));
    }
    let keys = env_keys(&text);
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
    fn json_has_the_four_keys_in_order() {
        let j = json();
        let at = |k: &str| j.find(&format!("\"{k}\"")).unwrap();
        assert!(at("dirs") < at("names") && at("names") < at("extensions") && at("extensions") < at("exempt_suffixes"));
        assert!(j.ends_with("}\n") && j.matches('\n').count() == 1);
        assert!(j.contains("\".env*\""));
    }

    #[test]
    fn env_keys_prints_names_only() {
        let text = "# comment\nA=1\nexport B = \"two words\"\n\nA=again\nC.D-E=x\n=bad\n1BAD=x\nnot a pair\nE=\n";
        assert_eq!(env_keys(text), ["A", "B", "C.D-E", "E"]);
    }

    #[test]
    fn a_value_that_runs_over_several_lines_hides_its_inner_lines() {
        let text = "BEFORE=1\nKEY=\"first line\nSECRET_LOOKING=abc==\nlast line\"\nAFTER='x\ny=z\n'\nEND=1\n";
        assert_eq!(env_keys(text), ["BEFORE", "KEY", "AFTER", "END"]);
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
