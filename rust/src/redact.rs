//! Finds secrets in text and replaces them. Every byte that reaches the embedder or stdout goes
//! through `clean`. Detection-based: a secret with no known shape can get through (see README).
//!
//! Each detector returns byte ranges over the original text. Ranges always start and end on ASCII
//! delimiters, so slicing stays on char boundaries. Newlines inside a range survive, so line
//! numbers still match the file.

use std::ops::Range;
use std::panic::{self, AssertUnwindSafe};

pub const MARK: &str = "[REDACTED]";

/// Bump when detection changes: `search` refuses an index built by an older redactor, because its
/// vectors came from text this version would have cleaned differently.
pub const VERSION: u32 = 1;

type Spans = Vec<Range<usize>>;

/// Prefix, minimum characters after it, and whether `.` is part of the token.
const TOKEN_PREFIXES: &[(&str, usize, bool)] = &[
    ("AKIA", 16, false), // AWS access key id
    ("ASIA", 16, false),
    ("AGPA", 16, false),
    ("AIDA", 16, false),
    ("AROA", 16, false),
    ("ghp_", 20, false), // GitHub
    ("gho_", 20, false),
    ("ghu_", 20, false),
    ("ghs_", 20, false),
    ("ghr_", 20, false),
    ("github_pat_", 20, false),
    ("glpat-", 16, false), // GitLab
    ("glrt-", 16, false),
    ("xoxa-", 10, false), // Slack
    ("xoxb-", 10, false),
    ("xoxp-", 10, false),
    ("xoxr-", 10, false),
    ("xoxs-", 10, false),
    ("xoxe-", 10, false),
    ("xapp-", 10, false),
    ("sk_live_", 10, false), // Stripe
    ("rk_live_", 10, false),
    ("pk_live_", 10, false),
    ("sk_test_", 10, false),
    ("rk_test_", 10, false),
    ("whsec_", 10, false),
    ("sk-ant-", 16, false), // Anthropic
    ("sk-proj-", 16, false), // OpenAI
    ("sk-", 20, false),
    ("AIza", 30, false), // Google API key
    ("ya29.", 20, true), // Google OAuth
    ("GOCSPX-", 16, false),
    ("npm_", 30, false),
    ("pypi-", 30, false),
    ("hf_", 30, false),      // Hugging Face
    ("dop_v1_", 30, false),  // DigitalOcean
    ("doo_v1_", 30, false),
    ("shpat_", 20, false), // Shopify
    ("shpss_", 20, false),
    ("SG.", 30, true), // SendGrid
    ("sq0atp-", 16, false), // Square
    ("sq0csp-", 16, false),
    ("EAAA", 40, false),
    ("sbp_", 30, false),     // Supabase
    ("dapi", 28, false),     // Databricks
    ("lin_api_", 20, false), // Linear
    ("PMAK-", 20, false),    // Postman
    ("dp.pt.", 20, true),    // Doppler
    ("AGE-SECRET-KEY-", 20, false),
    ("vercel_", 20, false),
    ("tskey-", 16, false), // Tailscale
];

const WEBHOOK_HOSTS: &[&str] = &["hooks.slack.com/", "discord.com/api/webhooks/", "discordapp.com/api/webhooks/"];

/// Name words that make a value sensitive on their own.
const SENSITIVE_WORDS: &[&str] = &[
    "password", "passwords", "passwd", "pwd", "pw", "passphrase", "passcode", "pass", "secret", "secrets", "token",
    "tokens", "apikey", "credential", "credentials", "cred", "creds", "authorization", "auth", "bearer", "cookie",
    "privatekey", "accesskey", "secretkey", "dsn", "salt", "pin",
];
/// Fragments that count inside a run-together word (`dbpassword`, `clientsecret`).
const SENSITIVE_FRAGMENTS: &[&str] = &["password", "passwd", "secret", "apikey", "authtoken"];
/// Adjacent name words that do the same (`api_key`, `signingKey`).
const SENSITIVE_PAIRS: &[(&str, &str)] = &[
    ("api", "key"),
    ("private", "key"),
    ("access", "key"),
    ("secret", "key"),
    ("signing", "key"),
    ("encryption", "key"),
    ("auth", "key"),
    ("account", "key"),
    ("master", "key"),
    ("jwt", "key"),
    ("hmac", "key"),
    ("app", "key"),
    ("aes", "key"),
    ("crypto", "key"),
    ("client", "key"),
    ("license", "key"),
    ("shared", "key"),
    ("session", "id"),
    ("session", "key"),
    ("connection", "string"),
    ("conn", "str"),
    ("database", "url"),
    ("db", "url"),
];
const SENSITIVE_QUERY_PARAMS: &[&str] = &[
    "token", "access_token", "refresh_token", "id_token", "auth", "api_key", "apikey", "key", "secret", "password",
    "pwd", "sig", "signature",
];
/// Unquoted words in code that are clearly not a literal value.
const CODE_WORDS: &[&str] = &["none", "null", "nil", "undefined", "true", "false", "self", "this", "string", "str"];

const SENSITIVE_DIRS: &[&str] = &[".ssh", ".aws", ".gnupg", ".gpg", ".kube", ".azure", ".gcloud", ".docker", "gcloud", ".env", "secret", "secrets", ".secrets", "credentials", "keys", "private", "vault"];
const SENSITIVE_NAMES: &[&str] = &[
    ".envrc", ".netrc", "_netrc", ".npmrc", ".pypirc", ".pgpass", ".htpasswd", ".git-credentials", ".dockercfg",
    "auth.json", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "wp-config.php",
];
const SENSITIVE_EXTENSIONS: &[&str] =
    &["env", "pem", "key", "p12", "pfx", "jks", "keystore", "ppk", "asc", "gpg", "kdbx", "tfvars", "tfstate"];
const SENSITIVE_NAME_PARTS: &[&str] = &[
    "secret", "credential", "password", "passwd", "privatekey", "private_key", "private-key", "apikey", "api_key",
    "api-key", "serviceaccount", "service_account", "service-account", ".tfstate",
];

/// True when a repo-relative path should never be read, whatever it contains.
pub fn is_sensitive_path(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    let mut parts = lower.split(['/', '\\']).collect::<Vec<_>>();
    let Some(name) = parts.pop() else { return true };
    if parts.iter().any(|p| SENSITIVE_DIRS.contains(p) || *p == "..") {
        return true;
    }
    name.starts_with(".env")
        || SENSITIVE_NAMES.contains(&name)
        || name.rsplit_once('.').is_some_and(|(_, ext)| SENSITIVE_EXTENSIONS.contains(&ext))
        || SENSITIVE_NAME_PARTS.iter().any(|p| name.contains(p))
}

/// Cleans text, or returns None when it can't vouch for the result. Callers must withhold on None.
pub fn clean(text: &str) -> Option<String> {
    guarded(|| {
        let mut out = apply(text, find_all(text));
        // Replacing can expose a new match; a few passes settle it, and if not, withhold.
        for _ in 0..3 {
            let spans = find_all(&out);
            if spans.is_empty() {
                return Some(out);
            }
            out = apply(&out, spans);
        }
        None
    })
}

/// Runs a redaction step so that a panic withholds the text instead of ending the search.
pub fn guarded<T>(step: impl FnOnce() -> Option<T>) -> Option<T> {
    panic::catch_unwind(AssertUnwindSafe(step)).ok().flatten()
}

fn find_all(text: &str) -> Spans {
    let mut spans = Spans::new();
    private_key_blocks(text, &mut spans);
    url_secrets(text, &mut spans);
    userinfo_secrets(text, &mut spans);
    symbol_strings(text, &mut spans);
    tokens_and_high_entropy(text, &mut spans);
    assignments(text, &mut spans);
    spans.retain(|s| !text[s.clone()].chars().all(|c| MARK.contains(c) || c.is_whitespace()));
    spans
}

fn apply(text: &str, mut spans: Spans) -> String {
    spans.sort_by_key(|s| s.start);
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for s in spans {
        if s.end <= at {
            continue;
        }
        let start = s.start.max(at);
        out.push_str(&text[at..start]);
        out.push_str(MARK);
        out.extend(text[start..s.end].chars().filter(|c| *c == '\n'));
        at = s.end;
    }
    out.push_str(&text[at..]);
    out
}

fn private_key_blocks(text: &str, spans: &mut Spans) {
    let mut from = 0;
    while let Some(i) = text[from..].find("-----BEGIN ") {
        let start = from + i;
        let header_end = text[start + 11..].find("-----").map(|e| start + 11 + e);
        from = start + 11;
        let Some(header_end) = header_end else { continue };
        let header = &text[start..header_end];
        if !header.contains("PRIVATE KEY") {
            continue;
        }
        // No END marker means a cut-off key: take everything after it.
        let end = text[header_end + 5..]
            .find("-----END ")
            .and_then(|e| {
                let close = header_end + 5 + e + 9;
                text[close..].find("-----").map(|c| close + c + 5)
            })
            .unwrap_or(text.len());
        spans.push(start..end);
        from = end;
    }
}

fn is_url_end(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b'"' | b'\'' | b'`' | b'<' | b'>' | b'\\')
}

fn url_secrets(text: &str, spans: &mut Spans) {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(i) = text[from..].find("://") {
        let scheme_end = from + i;
        let start = scheme_end + 3;
        let end = bytes[start..].iter().position(|b| is_url_end(*b)).map_or(text.len(), |e| start + e);
        let url = &text[start..end];
        // Credentials: everything up to the last @ before the query.
        let before_query = url.split(['?', '#']).next().unwrap_or(url);
        if let Some(at) = before_query.rfind('@') {
            spans.push(start..start + at);
        }
        if WEBHOOK_HOSTS.iter().any(|h| url.starts_with(h)) {
            spans.push(start..end);
        }
        if let Some(q) = url.find('?') {
            let mut pos = start + q + 1;
            for pair in url[q + 1..].split('&') {
                if let Some((k, _)) = pair.split_once('=') {
                    if SENSITIVE_QUERY_PARAMS.contains(&k.to_ascii_lowercase().as_str()) {
                        spans.push(pos + k.len() + 1..pos + pair.len());
                    }
                }
                pos += pair.len() + 1;
            }
        }
        from = end.max(start);
    }
}

/// `bob:hunter2@tcp(db)`: the part between `:` and `@`, with no scheme to mark it as a URL.
fn userinfo_secrets(text: &str, spans: &mut Spans) {
    let bytes = text.as_bytes();
    for (at, _) in text.match_indices('@') {
        if !bytes.get(at + 1).is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'(' | b'[')) {
            continue;
        }
        let start = bytes[..at].iter().rposition(|b| is_url_end(*b) || matches!(b, b'/' | b'@')).map_or(0, |p| p + 1);
        if let Some(colon) = text[start..at].find(':') {
            if colon + 1 < at - start {
                spans.push(start + colon + 1..at);
            }
        }
    }
}

/// Quoted strings with no spaces that look like generated passwords: symbols split these into
/// short pieces, so the word-based check never sees them whole. Regexes and format strings are
/// mostly excluded by the characters they need.
fn symbol_strings(text: &str, spans: &mut Spans) {
    const MIN_LEN: usize = 16;
    const MIN_BITS: f64 = 3.5;
    const MIN_CLASSES: usize = 3;
    for (offset, line) in text.split_inclusive('\n').scan(0, |at, l| {
        let start = *at;
        *at += l.len();
        Some((start, l))
    }) {
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if !matches!(bytes[i], b'"' | b'\'' | b'`') {
                i += 1;
                continue;
            }
            let Some(len) = line[i + 1..].find(bytes[i] as char) else { break };
            let body = &line[i + 1..i + 1 + len];
            let plain = !body.contains(|c: char| c.is_whitespace() || "/\\([{<".contains(c));
            let classes = [
                body.bytes().any(|b| b.is_ascii_lowercase()),
                body.bytes().any(|b| b.is_ascii_uppercase()),
                body.bytes().any(|b| b.is_ascii_digit()),
                body.bytes().any(|b| b.is_ascii_punctuation()),
            ];
            if body.len() >= MIN_LEN
                && plain
                && classes[3]
                && classes.iter().filter(|c| **c).count() >= MIN_CLASSES
                && shannon_bits(body) >= MIN_BITS
                && wordy_share(body) < 0.5
            {
                spans.push(offset + i + 1..offset + i + 1 + len);
            }
            i += len + 2;
        }
    }
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+' | b'/' | b'=' | b'.' | b':')
}

fn tokens_and_high_entropy(text: &str, spans: &mut Spans) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !is_token_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_token_byte(bytes[i]) {
            i += 1;
        }
        scan_run(&text[start..i], start, spans);
    }
}

fn scan_run(run: &str, offset: usize, spans: &mut Spans) {
    // `.` and `:` separate most code (`a.b`, `x:y`), so tokens are looked for between them, with
    // the shapes that need them handled first.
    if let Some(len) = jwt_len(run).or_else(|| telegram_len(run)) {
        spans.push(offset..offset + len);
        return;
    }
    let mut at = 0;
    for piece in run.split_inclusive(['.', ':']) {
        let word = piece.trim_end_matches(['.', ':']);
        let pos = offset + at;
        at += piece.len();
        if let Some(len) = known_token_len(&run[at - piece.len()..]) {
            spans.push(pos..pos + len);
            continue;
        }
        // A token inside a longer word, like `key=AKIA...` or `/ghp_...`.
        for (i, _) in word.match_indices(['=', '/', '+']) {
            if let Some(len) = known_token_len(&word[i + 1..]) {
                spans.push(pos + i + 1..pos + i + 1 + len);
            }
        }
        if looks_random(word) {
            spans.push(pos..pos + word.len());
        }
    }
}

fn known_token_len(s: &str) -> Option<usize> {
    TOKEN_PREFIXES.iter().find_map(|(prefix, min, dotted)| {
        let rest = s.strip_prefix(prefix)?;
        let body = rest
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-') || (*dotted && *b == b'.'))
            .count();
        (body >= *min).then_some(prefix.len() + body)
    })
}

/// `eyJ...` header, payload, and signature.
fn jwt_len(s: &str) -> Option<usize> {
    if !s.starts_with("eyJ") {
        return None;
    }
    let is_b64 = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'=');
    let len = s.bytes().take_while(|b| is_b64(*b) || *b == b'.').count();
    let parts: Vec<&str> = s[..len].split('.').collect();
    (parts.len() >= 2 && parts.iter().take(2).all(|p| p.len() >= 8)).then_some(len)
}

/// Telegram bot token: `123456789:AA...`.
fn telegram_len(s: &str) -> Option<usize> {
    let (id, rest) = s.split_once(':')?;
    if !(8..=12).contains(&id.len()) || !id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let body = rest.bytes().take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')).count();
    (body >= 30).then_some(id.len() + 1 + body)
}

fn shannon_bits(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts.iter().filter(|c| **c > 0).map(|c| *c as f64 / n).map(|p| -p * p.log2()).sum()
}

fn is_uuid(word: &str) -> bool {
    word.len() == 36
        && word.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// Share of a word sitting in lowercase runs of 3 or more, which camelCase names are made of.
fn wordy_share(word: &str) -> f64 {
    const MIN_RUN: usize = 3;
    let in_runs: usize = word.split(|c: char| !c.is_ascii_lowercase()).map(str::len).filter(|n| *n >= MIN_RUN).sum();
    in_runs as f64 / word.len() as f64
}

/// Random-looking: long, varied, and switching between upper, lower, and digit far more often than
/// a name or path does. Hex is judged by length alone, since its alphabet caps its entropy.
pub fn looks_random(word: &str) -> bool {
    const MIN_LEN: usize = 20;
    const MIN_HEX_LEN: usize = 24;
    const MIN_FLAT_LEN: usize = 24;
    const MIN_BITS: f64 = 3.5;
    const MIN_SWITCH_RATE: f64 = 0.28;
    const MAX_WORDY_SHARE: f64 = 0.5;

    if word.len() < MIN_LEN {
        return false;
    }
    let body = word.trim_end_matches('=');
    if body.len() >= MIN_HEX_LEN && body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return body.bytes().any(|b| b.is_ascii_digit())
            && body.bytes().any(|b| b.is_ascii_alphabetic())
            && shannon_bits(body) >= 2.5;
    }
    if is_uuid(body) {
        return true;
    }
    // One case with no separators: a name this long would have `_` or capitals in it.
    let flat = body.split(|c: char| !c.is_ascii_alphanumeric()).any(|seg| {
        seg.len() >= MIN_FLAT_LEN
            && !seg.bytes().any(|b| b.is_ascii_uppercase())
            && seg.bytes().any(|b| b.is_ascii_lowercase())
            && shannon_bits(seg) >= MIN_BITS
    });
    if flat {
        return true;
    }
    let class = |b: u8| match b {
        b'a'..=b'z' => 1,
        b'A'..=b'Z' => 2,
        b'0'..=b'9' => 3,
        _ => 0,
    };
    let (mut switches, mut last) = (0, 0);
    for b in body.bytes() {
        let c = class(b);
        if c != 0 && last != 0 && c != last {
            switches += 1;
        }
        last = c;
    }
    let rate = switches as f64 / body.len() as f64;
    shannon_bits(body) >= MIN_BITS && rate >= MIN_SWITCH_RATE && wordy_share(body) < MAX_WORDY_SHARE
}

fn name_words(name: &str) -> Vec<String> {
    let mut words = vec![String::new()];
    let bytes = name.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if !b.is_ascii_alphanumeric() {
            words.push(String::new());
            continue;
        }
        let camel = b.is_ascii_uppercase()
            && i > 0
            && (bytes[i - 1].is_ascii_lowercase()
                || bytes[i - 1].is_ascii_digit()
                || (bytes[i - 1].is_ascii_uppercase() && bytes.get(i + 1).is_some_and(u8::is_ascii_lowercase)));
        if camel {
            words.push(String::new());
        }
        if let Some(w) = words.last_mut() {
            w.push(b.to_ascii_lowercase() as char);
        }
    }
    words.retain(|w| !w.is_empty());
    words
}

pub fn is_sensitive_name(name: &str) -> bool {
    let words = name_words(name);
    words.iter().any(|w| SENSITIVE_WORDS.contains(&w.as_str()) || SENSITIVE_FRAGMENTS.iter().any(|f| w.contains(f)))
        || words.windows(2).any(|p| SENSITIVE_PAIRS.contains(&(p[0].as_str(), p[1].as_str())))
}

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')
}

fn line_end(bytes: &[u8], from: usize) -> usize {
    bytes[from..].iter().position(|b| *b == b'\n').map_or(bytes.len(), |e| from + e)
}

fn skip_inline_space(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    i
}

/// Moves past an assignment, comparison, or fallback operator.
fn skip_operator(bytes: &[u8], i: usize) -> Option<usize> {
    for op in [":=", "=>", "===", "!==", "==", "!=", "+=", "||=", "&&=", "??=", "||", "??", "=", ":"] {
        if bytes[i..].starts_with(op.as_bytes()) {
            return Some(i + op.len());
        }
    }
    None
}

/// Range of a quoted value starting at `i` (past any `b`, `r`, `f`, `u` prefix), quotes included.
/// One that never closes runs to the end of its line, or for a multi-line quote, of the text.
fn quoted_value(bytes: &[u8], i: usize) -> Option<Range<usize>> {
    let prefix = bytes[i..].iter().take(2).take_while(|b| matches!(b, b'b' | b'r' | b'f' | b'u' | b'B' | b'R' | b'F' | b'U')).count();
    let hashes = bytes[i + prefix..].iter().take_while(|b| **b == b'#').count();
    let open = i + prefix + hashes;
    let quote = *bytes.get(open).filter(|q| matches!(q, b'"' | b'\'' | b'`'))?;
    let triple = bytes[open..].starts_with(&[quote; 3]);
    let body = if triple { open + 3 } else { open + 1 };
    if hashes > 0 {
        // Rust raw string: closes only at the quote plus as many `#`.
        let mut close = vec![b'"'];
        close.resize(hashes + 1, b'#');
        let end = bytes[body..].windows(close.len()).position(|w| w == close).map_or(bytes.len(), |e| body + e + close.len());
        return Some(i + prefix..end);
    }
    let multiline = triple || quote == b'`';
    let mut j = body;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' => j += 1,
            b'\n' if !multiline => return Some(open..j),
            b if b == quote && (!triple || bytes[j..].starts_with(&[quote; 3])) => {
                return Some(open..j + if triple { 3 } else { 1 });
            }
            _ => {}
        }
        j += 1;
    }
    Some(open..bytes.len())
}

/// Every quoted literal from `from` to the end of its line, to catch a value wrapped in a call or
/// a fallback: `Some("x".into())`, `env || "x"`, `basic_auth("user", "x")`. This over-redacts
/// (`request.form["password"]`), which only costs readability.
fn literals_to_line_end(bytes: &[u8], from: usize, spans: &mut Spans) -> usize {
    let mut i = from;
    let mut found = 0;
    while i < bytes.len() && bytes[i] != b'\n' {
        let raw = bytes[i] == b'r' && bytes.get(i + 1) == Some(&b'#');
        if raw || matches!(bytes[i], b'"' | b'\'' | b'`') {
            if let Some(mut r) = quoted_value(bytes, i) {
                // Past the first literal, an unclosed quote is likely prose or a comment, so it
                // must not swallow the lines below.
                if found > 0 || i > from {
                    r.end = r.end.min(line_end(bytes, i));
                }
                i = r.end.max(i + 1);
                if r.len() > 2 {
                    spans.push(r);
                    found += 1;
                }
                continue;
            }
        }
        i += 1;
    }
    found
}

/// Unquoted values are usually code (`token = get_token()`), so these take only what can't be an
/// expression: a digit in a plain word, or a symbol. `password = hunter` stays: it reads as a
/// variable (README, limits).
fn bare_value_looks_literal(name: &str, value: &str, tight: bool) -> bool {
    let lower = value.to_ascii_lowercase();
    if value.is_empty() || CODE_WORDS.contains(&lower.as_str()) {
        return false;
    }
    // `max_tokens = 100` is a count; `password = 100200` isn't.
    if value.bytes().all(|b| b.is_ascii_digit()) && name_words(name).iter().any(|w| w == "tokens" || w == "token") {
        return false;
    }
    // `Pwd=a.b2;` inside a connection string: no spaces around the `=`, and not a call.
    if tight && !value.contains('(') && (value.bytes().any(|b| b.is_ascii_digit()) || value.starts_with(['!', '*'])) {
        return !is_primitive(&lower);
    }
    if value.starts_with(['$', '{', '(', '[', '<', '&', '*', '!', '%', '#', '/', '\\', '|', '@'])
        || value.contains(['(', '[', '<', '{'])
        || value.contains("::")
        || value.contains("->")
        || value.contains('.')
    {
        return false;
    }
    if is_primitive(&lower) {
        return false;
    }
    value.bytes().any(|b| !b.is_ascii_alphabetic() && b != b'_')
}

fn is_primitive(lower: &str) -> bool {
    let numeric = lower.len() >= 2
        && matches!(lower.as_bytes()[0], b'i' | b'u' | b'f')
        && lower[1..].bytes().all(|b| b.is_ascii_digit());
    numeric || lower == "isize" || lower == "usize"
}

fn bare_end(bytes: &[u8], i: usize) -> usize {
    bytes[i..]
        .iter()
        .position(|b| b.is_ascii_whitespace() || matches!(b, b',' | b';' | b'&' | b')' | b'}' | b']' | b'"' | b'\'' | b'`'))
        .map_or(bytes.len(), |e| i + e)
}

fn is_env_name(name: &str) -> bool {
    name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn assignments(text: &str, spans: &mut Spans) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !is_name_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_name_byte(bytes[i]) {
            i += 1;
        }
        let name = &text[start..i];
        if name.eq_ignore_ascii_case("bearer") || name.eq_ignore_ascii_case("basic") {
            if let Some(value) = auth_scheme_value(bytes, i) {
                i = value.end;
                spans.push(value);
                continue;
            }
        }
        if name == "-u" || name == "--user" {
            let v = skip_inline_space(bytes, i);
            let end = bare_end(bytes, v);
            if let Some(colon) = text[v..end].find(':') {
                spans.push(v + colon + 1..end);
            }
            continue;
        }
        if name.len() >= 2 && is_sensitive_name(name) {
            assigned_values(text, start, i, spans);
        }
    }
}

/// The credential after `Bearer ` or `Basic `. A digit or `=` tells it apart from prose.
fn auth_scheme_value(bytes: &[u8], scheme_end: usize) -> Option<Range<usize>> {
    const MIN_LEN: usize = 8;
    let v = skip_inline_space(bytes, scheme_end);
    let is_cred = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-');
    let len = bytes[v..].iter().take_while(|b| is_cred(**b)).count();
    let value = &bytes[v..v + len];
    (v > scheme_end && len >= MIN_LEN && value.iter().any(|b| b.is_ascii_digit() || *b == b'=')).then_some(v..v + len)
}

/// `\"password\":\"x\"`, JSON inside a string.
fn escaped_json_value(bytes: &[u8], name_end: usize) -> Option<Range<usize>> {
    const ESCAPED_QUOTE: &[u8] = b"\\\"";
    let mut i = name_end + ESCAPED_QUOTE.len();
    i = skip_inline_space(bytes, i);
    i = skip_operator(bytes, i)?;
    i = skip_inline_space(bytes, i);
    let line = line_end(bytes, i);
    if !bytes[i..].starts_with(ESCAPED_QUOTE) {
        let end = bytes[i..line].iter().position(|b| matches!(b, b',' | b'}' | b'\\')).map_or(line, |e| i + e);
        return (end > i).then_some(i..end);
    }
    let body = i + ESCAPED_QUOTE.len();
    let close = bytes[body..line].windows(2).position(|w| w == ESCAPED_QUOTE).map_or(line, |e| body + e);
    Some(body..close)
}

/// Records literals assigned or passed to the sensitive name at `start..name_end`.
fn assigned_values(text: &str, start: usize, name_end: usize, spans: &mut Spans) {
    let bytes = text.as_bytes();
    let name = &text[start..name_end];
    if bytes[name_end..].starts_with(b"\\\"") {
        spans.extend(escaped_json_value(bytes, name_end));
        return;
    }
    let line_start = bytes[..start].iter().rposition(|b| *b == b'\n').map_or(0, |n| n + 1);
    let before = text[line_start..start].trim_start();
    let at_line_start = before.is_empty() || before == "export ";

    // Past a closing quote or bracket: `"password": ...`, `env["TOKEN"] = ...`.
    let mut i = name_end;
    let name_was_quoted = matches!(bytes.get(i), Some(b'"' | b'\'' | b'`'));
    if name_was_quoted {
        i += 1;
    }
    if bytes.get(i) == Some(&b']') {
        i += 1;
    }
    let after_name = skip_inline_space(bytes, i);

    // A quoted name marks the line: `option("--password", default="x")`, `json:"pw" default:"x"`.
    if name_was_quoted && literals_to_line_end(bytes, after_name, spans) > 0 {
        return;
    }
    // `setPassword("x")`, `basic_auth("u", "x")`, but not `auth.get("/route")`, where the sensitive
    // word is the object and not what's being called.
    if let Some(b'(' | b',') = bytes.get(after_name) {
        let called = name.rsplit('.').next().unwrap_or(name);
        if is_sensitive_name(called) {
            literals_to_line_end(bytes, after_name + 1, spans);
        }
        return;
    }
    // `--password hunter2`
    if name.starts_with("--") && bytes.get(after_name).is_some_and(|b| !matches!(b, b'=' | b'\n')) {
        let r = quoted_value(bytes, after_name).unwrap_or(after_name..bare_end(bytes, after_name));
        if r.len() > 1 {
            spans.push(r);
        }
        return;
    }

    let (after_op, op_byte) = match skip_operator(bytes, after_name) {
        Some(next) => (next, bytes[after_name]),
        None => {
            // Go: `var token string = "x"`.
            let end = line_end(bytes, after_name);
            let Some(eq) = text[after_name..end].find('=').map(|e| e + after_name) else { return };
            let between = text[after_name..eq].trim();
            let is_type = !between.is_empty()
                && between.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'[' | b']' | b'*' | b'.'));
            match skip_operator(bytes, eq) {
                Some(next) if is_type => (next, b'='),
                _ => return,
            }
        }
    };
    // A quoted value may sit on the next line: `password =\n    "x"`.
    let next_token = after_op + bytes[after_op..].iter().take_while(|b| b.is_ascii_whitespace()).count();
    let at_quote = matches!(bytes.get(next_token), Some(b'"' | b'\'' | b'`' | b'b' | b'r' | b'f' | b'u'))
        && quoted_value(bytes, next_token).is_some();
    if literals_to_line_end(bytes, if at_quote { next_token } else { after_op }, spans) > 0 {
        return;
    }
    let v = skip_inline_space(bytes, after_op);
    let end = bare_end(bytes, v);
    let value = &text[v..end];
    let tight = after_name == name_end && v == after_op;

    // `.env` shape: `PASSWORD=anything` at the start of a line, no spaces around the `=`.
    if at_line_start && !name_was_quoted && is_env_name(name) && tight && op_byte == b'=' {
        if !value.is_empty() && !value.starts_with('$') {
            spans.push(v..end);
        }
        return;
    }
    // `key: type = value`, in Rust, TypeScript, Python.
    if op_byte == b':' {
        let close = line_end(bytes, v);
        if let Some(eq) = text[v..close].find('=') {
            let ty = &text[v..v + eq];
            if ty.len() <= 40 && !ty.contains(['(', ',']) {
                let Some(after) = skip_operator(bytes, v + eq).map(|n| skip_inline_space(bytes, n)) else { return };
                let e = bare_end(bytes, after);
                if bare_value_looks_literal(name, &text[after..e], false) {
                    spans.push(after..e);
                }
                return;
            }
        }
    }
    if bare_value_looks_literal(name, value, tight && op_byte == b'=') {
        spans.push(v..end);
    }
}

#[cfg(test)]
#[path = "redact_tests.rs"]
mod tests;
