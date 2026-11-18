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
pub const VERSION: u32 = 5;

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
    "auth.json", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "wp-config.php", "env", "dotenv", ".vault-token",
    "kubeconfig", ".my.cnf", ".s3cfg", ".boto",
];
/// SSH private key names, also inside a longer name (`my_id_rsa`).
const SSH_KEY_NAMES: &[&str] = &["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"];
/// Endings of an editor or hand-made backup, checked against the name without them.
const BACKUP_SUFFIXES: &[&str] = &[".bak", ".old", ".orig", ".save", ".swp", "~"];
/// Source and doc extensions: `env.ts` or `env.d.ts` is code, while `env.local` or `env.json`
/// holds values.
const CODE_EXTENSIONS: &[&str] = &[
    "rs", "ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs", "py", "go", "java", "kt", "kts", "rb", "php", "cs", "swift",
    "c", "h", "cc", "cpp", "hpp", "scala", "sh", "bash", "zsh", "fish", "ps1", "md", "rst", "txt", "html", "vue",
    "svelte", "dart", "ex", "exs", "lua", "pl", "r", "jl", "nix", "zig",
];
const SENSITIVE_EXTENSIONS: &[&str] =
    &["env", "pem", "key", "p12", "pfx", "jks", "keystore", "ppk", "asc", "gpg", "kdbx", "tfvars", "tfstate"];
const SENSITIVE_NAME_PARTS: &[&str] = &[
    "secret", "credential", "password", "passwd", "privatekey", "private_key", "private-key", "apikey", "api_key",
    "api-key", "serviceaccount", "service_account", "service-account", ".tfstate",
];

/// A `.env` file's name ending in one of these is a template with no secrets.
const ENV_TEMPLATE_SUFFIXES: &[&str] = &[".example", ".sample", ".template"];

/// A name holding `.env` as a dotted part (`.env`, `.env.local`, `prod.env`, `app.env.txt`), or
/// Cloudflare's `.dev.vars`.
fn is_env_file_name(name: &str) -> bool {
    name.starts_with(".env") || name.ends_with(".env") || name.contains(".env.") || name.starts_with(".dev.vars")
}

/// True when a repo-relative path should never be read, whatever it contains.
pub fn is_sensitive_path(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    let mut parts = lower.split(['/', '\\']).collect::<Vec<_>>();
    let Some(name) = parts.pop() else { return true };
    if parts.iter().any(|p| SENSITIVE_DIRS.contains(p) || *p == "..") {
        return true;
    }
    // `id_rsa.bak`, `.npmrc.old`, `.env.swp` (vim's `.name.swp`), `config.yml~`.
    let mut base = name;
    while let Some(stripped) = BACKUP_SUFFIXES.iter().find_map(|s| base.strip_suffix(s)).filter(|b| !b.is_empty()) {
        if is_sensitive_name_of_file(stripped) || stripped.strip_prefix('.').is_some_and(is_sensitive_name_of_file) {
            return true;
        }
        base = stripped;
    }
    is_sensitive_name_of_file(name)
}

/// The file-name half of `is_sensitive_path`, lowercase.
fn is_sensitive_name_of_file(name: &str) -> bool {
    if is_env_file_name(name) {
        return !ENV_TEMPLATE_SUFFIXES.iter().any(|s| name.ends_with(s));
    }
    // `env.local`, `env.json`, `prod-env`, but not the code file `env.ts`.
    if let Some(ext) = name.strip_prefix("env.") {
        let last = ext.rsplit('.').next().unwrap_or(ext);
        if !CODE_EXTENSIONS.contains(&last) && !ENV_TEMPLATE_SUFFIXES.iter().any(|s| name.ends_with(s)) {
            return true;
        }
    }
    SENSITIVE_NAMES.contains(&name)
        || name.ends_with("-env")
        || name.ends_with(".tfvars.json")
        || (SSH_KEY_NAMES.iter().any(|k| name.contains(k))
            && !name.ends_with(".pub")
            && !name.rsplit_once('.').is_some_and(|(_, ext)| CODE_EXTENSIONS.contains(&ext)))
        || name.rsplit_once('.').is_some_and(|(_, ext)| SENSITIVE_EXTENSIONS.contains(&ext))
        || SENSITIVE_NAME_PARTS.iter().any(|p| name.contains(p))
}

/// Cleans text, or returns None when it can't vouch for the result. Callers must withhold on None.
pub fn clean(text: &str) -> Option<String> {
    if test_failure(text) {
        return None;
    }
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

/// Test hook: in debug builds, text containing the value of `QUARRY_TEST_FAIL_REDACTION` fails to
/// clean, so end-to-end tests can see what callers do when redaction fails. No real input is known
/// to fail. Release builds leave this out, and it can only withhold text, never reveal it.
#[cfg(debug_assertions)]
fn test_failure(text: &str) -> bool {
    static MARKER: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    MARKER
        .get_or_init(|| std::env::var("QUARRY_TEST_FAIL_REDACTION").ok().filter(|m| !m.is_empty()))
        .as_deref()
        .is_some_and(|m| text.contains(m))
}

#[cfg(not(debug_assertions))]
fn test_failure(_: &str) -> bool {
    false
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
    xml_pairs(text, &mut spans);
    toml_secret_tables(text, &mut spans);
    k8s_secret_data(text, &mut spans);
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
                if let Some((k, _)) = pair.split_once('=')
                    && SENSITIVE_QUERY_PARAMS.contains(&k.to_ascii_lowercase().as_str())
                {
                    spans.push(pos + k.len() + 1..pos + pair.len());
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
        if let Some(colon) = text[start..at].find(':')
            && colon + 1 < at - start
        {
            spans.push(start + colon + 1..at);
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

/// A name whose last word is the secret one (`secrets`, `db_password`, `api_key`, `tokens`), so
/// everything under it is a secret. `token_pattern` or `PUNCTUATION_TOKENS_LIST` only mention one.
fn names_a_secret(name: &str) -> bool {
    let words = name_words(name);
    // Helm's `existingSecret`, `existingPasswordSecretKey`, `imagePullSecrets`: names of
    // Kubernetes Secrets, not their contents.
    if words.first().is_some_and(|w| w == "existing") || words.iter().any(|w| w == "pull") {
        return false;
    }
    let Some(last) = words.last() else { return false };
    SENSITIVE_WORDS.contains(&last.as_str())
        || SENSITIVE_FRAGMENTS.iter().any(|f| last.contains(f))
        || words.windows(2).last().is_some_and(|p| SENSITIVE_PAIRS.contains(&(p[0].as_str(), p[1].as_str())))
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
        // `&'a str`, `<'a>`, `it's`: a lifetime or an apostrophe, not a literal.
        let apostrophe = bytes[i] == b'\'' && is_apostrophe(bytes, 0, i);
        if (raw || matches!(bytes[i], b'"' | b'\'' | b'`')) && !apostrophe
            && let Some(mut r) = quoted_value(bytes, i)
        {
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

/// Where a bare value starting at `i` ends. A backslash-escaped character (`abc\ def`) is part of
/// the value.
fn bare_end(bytes: &[u8], i: usize) -> usize {
    let mut j = i;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' if bytes.get(j + 1).is_some_and(|b| *b != b'\n') => j += 2,
            b if b.is_ascii_whitespace() || matches!(b, b',' | b';' | b'&' | b')' | b'}' | b']' | b'"' | b'\'' | b'`') => return j,
            _ => j += 1,
        }
    }
    bytes.len()
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
        if (name.eq_ignore_ascii_case("bearer") || name.eq_ignore_ascii_case("basic"))
            && let Some(value) = auth_scheme_value(bytes, i)
        {
            i = value.end;
            spans.push(value);
            continue;
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
    // Dockerfile `ENV` and `ARG` set variables like a shell's `export`.
    let docker = matches!(before, "ENV " | "ARG ");
    let at_line_start = before.is_empty() || before == "export " || docker;
    // `<password>x</password>`, closed on the same line. A `<` before the name is more often a
    // generic or JSX (`Option<Token>`, `<PasswordInput />`), which fall through to the rules below.
    if start > 0
        && bytes[start - 1] == b'<'
        && let Some(r) = xml_element_value(text, start, name_end)
    {
        spans.push(r);
        return;
    }
    // `ENV DB_PASSWORD value`: the rest of the line.
    if docker && is_env_name(name) && matches!(bytes.get(name_end), Some(b' ' | b'\t')) {
        let v = skip_inline_space(bytes, name_end);
        let end = trimmed_line_end(bytes, v);
        if end > v && !matches!(bytes[v], b'=' | b'$') {
            spans.push(v..end);
        }
        return;
    }
    // A YAML key: the name opens its line, past any indent, list dashes, or a quote.
    let yaml_key = before.bytes().all(|b| matches!(b, b'-' | b' ' | b'\t' | b'"' | b'\''));

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

    // Inside a string (`echo "db_password: x" >> f`, `-H "X-Api-Key: x"`), the value runs to the
    // string's closing quote. Without this, that quote reads as the start of a literal and the
    // value before it stays.
    // A `key=value` pair inside a connection string: `"dbname=t user=u password=x"`,
    // `"Server=db;Password=x;"`.
    if let Some((q, _)) = open_quote(bytes, line_start, start)
        && start > 0
        && matches!(bytes[start - 1], b' ' | b';')
        && bytes.get(name_end) == Some(&b'=')
        && (names_a_secret(name) || name.eq_ignore_ascii_case("pwd"))
    {
        let v = name_end + 1;
        let end = bytes[v..line_end(bytes, v)]
            .iter()
            .position(|b| *b == q || matches!(b, b' ' | b';' | b'\t'))
            .map_or(line_end(bytes, v), |p| v + p);
        if end > v && !text[v..].starts_with(MARK) {
            spans.push(v..end);
        }
        return;
    }
    // Only when the name opens the string: `"Invalid token: expected 3 parts"` is prose.
    if let Some((q, opened)) = open_quote(bytes, line_start, start)
        && text[opened + 1..start].trim().is_empty()
        && (names_a_secret_block(name) || name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("proxy-authorization"))
        && bytes.get(name_end) != Some(&q)
        && !bytes[after_name..].starts_with(b"::")
        // `"db_password: x"`, but not a `"dashboard_auth:sign_in"` identifier.
        && !(bytes.get(after_name) == Some(&b':') && !matches!(bytes.get(after_name + 1), Some(b' ' | b'\t')))
        && let Some(after_op) = skip_operator(bytes, after_name)
    {
        let v = skip_inline_space(bytes, after_op);
        match bytes.get(v) {
            // A nested literal, or a placeholder (`"token={token}"`, `"password=%s"`, `"key=$KEY"`):
            // the rules below decide.
            Some(b'"' | b'\'' | b'`' | b'{' | b'$' | b'%' | b'\n') | None => {}
            Some(_) => {
                let end = closing_quote(bytes, v, q);
                let end = v + text[v..end].trim_end().len();
                let value = &text[v..end];
                // Code in a string (`"tokens : & mut TokenStream"`, `` `token: ${x}` ``) or a
                // plain word like `true` is left to the rules below.
                // Already cleaned on an earlier pass, a plain word, or a count (`max_tokens = 100`).
                let count = value.bytes().all(|b| b.is_ascii_digit()) && name_words(name).iter().any(|w| w == "tokens" || w == "token");
                if value.starts_with(MARK) || is_plain_word(value) || count {
                    return;
                }
                // `"Authorization: Bearer $TOKEN"` names a variable: the whole value (past a scheme
                // word) is one `$VAR` or `${VAR}`. `"ab$cd"` is a value.
                let last = value.rsplit(' ').next().unwrap_or(value);
                let scheme_ok = value == last || value.split(' ').count() == 2;
                let variable = scheme_ok && is_variable_reference(last);
                if variable {
                    return;
                }
                if end > v && !is_code_value(value) {
                    spans.push(v..end);
                    return;
                }
            }
        }
    }

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
    // `secret = [\n "x",\n]`, `"secret": {\n "a": "x"\n}`: every literal value inside.
    let v = skip_inline_space(bytes, after_op);
    // One that closes on its own line is left to the line rules below (`[]byte("x")`).
    // An object only under a quoted (JSON) name: `secret = {` or `ScmCreds => {` opens code.
    // After a type (`keys: ApiKey[] = [`), the name is a type, not the variable.
    let typed = after_op > after_name && bytes[after_name] != op_byte;
    if let Some(&open @ (b'[' | b'{')) = bytes.get(v)
        && !typed
        && names_a_secret_block(name)
        // `tokens = [` in code is a tokenizer's list far more often than a list of secrets.
        && (name_was_quoted || !name_words(name).last().is_some_and(|w| w == "token" || w == "tokens"))
        // An object only under `"secrets": {` or `"credentials": {`, quoted alone
        // (`"node_modules/cookie": {` names a package; `"password": {` a schema field).
        && (open == b'['
            || (name_was_quoted && start > 0 && bytes[start - 1] == bytes[name_end] && names_a_secret_table(name)))
        && !bytes[v..line_end(bytes, v)].contains(&if open == b'[' { b']' } else { b'}' })
    {
        bracket_literals(bytes, v, spans);
        return;
    }
    // A quoted value may sit on the next line: `password =\n    "x"`.
    let next_token = after_op + bytes[after_op..].iter().take_while(|b| b.is_ascii_whitespace()).count();
    let at_quote = matches!(bytes.get(next_token), Some(b'"' | b'\'' | b'`' | b'b' | b'r' | b'f' | b'u'))
        && quoted_value(bytes, next_token).is_some();
    if literals_to_line_end(bytes, if at_quote { next_token } else { after_op }, spans) > 0 {
        return;
    }
    // `Authorization: Token x`, any scheme: the rest of the line.
    if op_byte == b':'
        && yaml_key
        && !name_was_quoted
        && (name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("proxy-authorization"))
    {
        let end = trimmed_line_end(bytes, v);
        // Code (`authorization: string = x`) is left to the `key: type = value` rule below.
        if end > v && !is_code_value(&text[v..end]) {
            spans.push(v..end);
            return;
        }
    }
    if yaml_key && op_byte == b':' && after_op == after_name + 1 && yaml_value(text, line_start, v, name, spans) {
        return;
    }
    let end = bare_end(bytes, v);
    let value = &text[v..end];
    let tight = after_name == name_end && v == after_op;

    // `.env` shape: `PASSWORD=anything` at the start of a line, no spaces around the `=`. The value
    // runs to the end of the line: `DB_PASSWORD=a b c`.
    if at_line_start && !name_was_quoted && is_env_name(name) && tight && op_byte == b'=' {
        if text[v..].starts_with(MARK) {
            return;
        }
        let end = env_value_end(text, v, end);
        if end > v && !value.starts_with('$') {
            spans.push(v..end);
        }
        return;
    }
    // `password = correct horse battery` at the start of a line: several words that aren't code,
    // up to a ` #` comment.
    if yaml_key && op_byte == b'=' && after_op == after_name + 1 && names_a_secret(name) {
        let end = trimmed_line_end(bytes, v);
        let end = text[v..end].find(" #").map_or(end, |c| v + text[v..v + c].trim_end().len());
        let rest = &text[v..end];
        if rest.contains([' ', '\t']) && !is_code_value(rest) {
            spans.push(v..end);
            return;
        }
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

/// Where an unquoted `.env` value starting at `v` ends: the end of the line, before a ` #`
/// comment. `PASSWORD=x ./run.sh` sets a variable for a command, so there it is one word
/// (`word_end`).
fn env_value_end(text: &str, v: usize, word_end: usize) -> usize {
    let bytes = text.as_bytes();
    let end = trimmed_line_end(bytes, v);
    let end = text[v..end].find(" #").map_or(end, |c| v + text[v..v + c].trim_end().len());
    let next = skip_inline_space(bytes, word_end);
    if next < end && text[next..end].starts_with(['.', '/', '~']) {
        return word_end;
    }
    end
}

/// The last non-space position of the line holding `from`, at or after `from`.
fn trimmed_line_end(bytes: &[u8], from: usize) -> usize {
    let end = line_end(bytes, from);
    from + bytes[from..end].iter().rposition(|b| !b.is_ascii_whitespace()).map_or(0, |p| p + 1)
}

/// The quote still open at `at`, scanning from `line_start`, if `at` is inside a string.
/// `$VAR`, `${VAR}` or `$(cmd)`: a reference, not a value.
fn is_variable_reference(word: &str) -> bool {
    let Some(rest) = word.strip_prefix('$') else { return false };
    if let Some(inner) = rest.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
        return !inner.is_empty() && !inner.contains('}');
    }
    if rest.starts_with('(') && rest.ends_with(')') {
        return true;
    }
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// True when the `'` at `i` is an apostrophe or a Rust lifetime (`it's`, `<'a>`, `&'a str`), not a
/// quote. A string prefix before it (`b'x'`, `rb'x'`, `f'x'`) still opens a literal.
fn is_apostrophe(bytes: &[u8], line_start: usize, i: usize) -> bool {
    if i <= line_start {
        return false;
    }
    let prev = bytes[i - 1];
    if matches!(prev, b'<' | b'&') {
        return true;
    }
    if !prev.is_ascii_alphanumeric() {
        return false;
    }
    let word_start = bytes[line_start..i].iter().rposition(|b| !(b.is_ascii_alphanumeric() || *b == b'_')).map_or(line_start, |p| line_start + p + 1);
    let word = bytes[word_start..i].to_ascii_lowercase();
    !matches!(word.as_slice(), b"b" | b"r" | b"u" | b"f" | b"rb" | b"br" | b"fr" | b"rf")
}

/// The quote still open at `at`, and where it opened, scanning from `line_start`. A `'` after a
/// letter, `<` or `&` is an apostrophe or a Rust lifetime (`it's`, `<'a>`, `&'a str`), not a quote.
fn open_quote(bytes: &[u8], line_start: usize, at: usize) -> Option<(u8, usize)> {
    let mut open: Option<(u8, usize)> = None;
    let mut i = line_start;
    while i < at {
        match (bytes[i], open) {
            (b'\\', Some(_)) => i += 1,
            (b'\'', None) if is_apostrophe(bytes, line_start, i) => {}
            (q @ (b'"' | b'\'' | b'`'), None) => open = Some((q, i)),
            (q, Some((o, _))) if q == o => open = None,
            _ => {}
        }
        i += 1;
    }
    open
}

/// The position of the unescaped `quote` that closes the string around `from`, or a `;` before it
/// (`"Password=x;User Id=bob"`), or the line's end.
fn closing_quote(bytes: &[u8], from: usize, quote: u8) -> usize {
    let end = line_end(bytes, from);
    let mut i = from;
    while i < end {
        match bytes[i] {
            b'\\' => i += 1,
            b if b == quote || b == b';' => return i,
            _ => {}
        }
        i += 1;
    }
    end
}

/// The text of `<name ...>text</name>`, when the element closes on the same line.
fn xml_element_value(text: &str, start: usize, name_end: usize) -> Option<Range<usize>> {
    let bytes = text.as_bytes();
    let line = line_end(bytes, name_end);
    if !matches!(bytes.get(name_end), Some(b'>' | b' ' | b'\t')) {
        return None;
    }
    let gt = bytes[name_end..line].iter().position(|b| *b == b'>').map(|p| name_end + p)?;
    if bytes[gt - 1] == b'/' {
        return None;
    }
    let close = format!("</{}>", &text[start..name_end]);
    let end = text[gt + 1..line].find(&close).map(|p| gt + 1 + p)?;
    // JSX: `<AuthContext.Provider value={v}>{children}</AuthContext.Provider>`.
    let inner = &text[gt + 1..end];
    if inner.trim_start().starts_with('{') || text[start..gt].contains('{') {
        return None;
    }
    (end > gt + 1).then_some(gt + 1..end)
}

/// Every quoted literal value in the array or object opening at `open`, up to its matching close,
/// across lines. An object's keys (`"a":`) stay.
fn bracket_literals(bytes: &[u8], open: usize, spans: &mut Spans) {
    let mut depth = 0usize;
    // Objects inside: an array of records (`"password": [{"href": ...}]`) holds fields, not secrets.
    let own_objects = usize::from(bytes[open] == b'{');
    let mut objects = 0usize;
    // The key before the next value: a schema key's value (`"type": "string"`) stays.
    let mut key: Option<Range<usize>> = None;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'[' | b'{' => {
                depth += 1;
                objects += usize::from(bytes[i] == b'{');
            }
            b']' | b'}' => {
                depth -= 1;
                objects -= usize::from(bytes[i] == b'}');
                if depth == 0 {
                    return;
                }
            }
            b'"' | b'\'' | b'`' => {
                if let Some(r) = quoted_value(bytes, i) {
                    i = r.end.max(i + 1);
                    let after = skip_inline_space(bytes, i);
                    let is_key = bytes.get(after) == Some(&b':') && bytes.get(after + 1) != Some(&b':');
                    // A value follows `:`, or is an array element after `[` or `,`; `x['key']` is an
                    // index, not a value.
                    let before = bytes[..r.start].iter().rposition(|b| !b.is_ascii_whitespace());
                    let value_position = before.is_some_and(|p| match bytes[p] {
                        b':' | b',' => true,
                        b'[' => p == 0 || !(bytes[p - 1].is_ascii_alphanumeric() || matches!(bytes[p - 1], b')' | b']' | b'_')),
                        _ => false,
                    });
                    if is_key {
                        key = Some(r.clone());
                    } else if r.len() > 2
                        && value_position
                        && objects == own_objects
                        && !key.take().is_some_and(|k| is_schema_key(&String::from_utf8_lossy(&bytes[k])))
                    {
                        spans.push(r);
                    }
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
}

/// Words a `name: value` line can end in that are a type or code, not a value: `password: str` in
/// a Python class, `token: string` in TypeScript.
const TYPE_WORDS: &[&str] = &[
    "str", "string", "bool", "boolean", "int", "integer", "float", "number", "bytes", "any", "unknown", "object", "dict",
    "list", "tuple", "set", "none", "null", "nil", "undefined", "true", "false", "~",
];

/// A type annotation: `str`, `SecretStr`, `Option<String>`, `Optional[str]`, `str | None`,
/// `dict[str, Any]`.
fn looks_like_type(value: &str) -> bool {
    value.split('|').all(|part| {
        let part = part.trim();
        let base_end = part.find(['[', '<']).unwrap_or(part.len());
        let (base, args) = part.split_at(base_end);
        let base_ok = TYPE_WORDS.contains(&base.to_ascii_lowercase().as_str())
            // `SecretStr`, `Option`: capitalized with lower case after. `LEAK` is a value.
            || (base.starts_with(|c: char| c.is_ascii_uppercase())
                && base.bytes().any(|b| b.is_ascii_lowercase())
                && base.bytes().all(|b| b.is_ascii_alphabetic() || matches!(b, b'_' | b'.')));
        base_ok && args.bytes().all(|b| b.is_ascii_alphabetic() || matches!(b, b'[' | b']' | b'<' | b'>' | b',' | b' ' | b'_' | b'.' | b'|'))
    })
}

/// Words that make an unquoted value read as code: `token = token or default`.
const CODE_KEYWORDS: &[&str] = &["if", "else", "or", "and", "not", "in", "is", "for", "await", "new", "return", "as", "then"];

/// An unquoted value that is code or a type, not a secret: `getPassword(),`, `str | None`,
/// `${DB_PASSWORD}`, `a if b else c`.
fn is_code_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    value.ends_with([',', ';', '{', '(', '[', '\\'])
        || value.starts_with(['$', '{', '[', '(', '*', '!', '%', '<', '@', '&'])
        || value.contains(['(', ')', '{', '`'])
        || [" = ", "=>", "->", "::", "&&", "||", " + ", " ? ", "??", "?."].iter().any(|op| value.contains(op))
        || lower.split_whitespace().any(|w| CODE_KEYWORDS.contains(&w))
        || looks_like_type(value)
}

/// Where a YAML `key: value` or `- item` line's value starts, past `key:` and any `&anchor`.
fn yaml_mapping_value(line: &str) -> Option<usize> {
    let (key_end, value) = match line.find(": ") {
        Some(c) => (c, c + 2),
        None if line.ends_with(':') => (line.len() - 1, line.len()),
        None => return None,
    };
    let key = &line[..key_end];
    let quoted = key.starts_with(['"', '\'']);
    (!key.is_empty() && !key.starts_with('#') && (quoted || !key.contains([' ', '\t']))).then_some(value)
}

/// Keys whose values describe or configure a field rather than hold it: a schema's `type`, a
/// chart's `enabled`, a compose file's `file`, a workflow's `runs-on`.
const SCHEMA_KEYS: &[&str] = &[
    "type", "description", "format", "$ref", "enabled", "required", "region", "file", "runs-on", "uses",
    "name", "kind", "title", "example", "examples", "pattern", "minlength", "maxlength", "enum", "nullable",
    "readonly", "writeonly", "deprecated", "create", "mountpath", "path", "optional", "items", "properties",
    "additionalproperties", "minimum", "maximum", "label", "placeholder", "help", "hint", "algorithm", "encoding",
    "size", "rotationpolicy", "usages", "duration", "renewbefore", "apiversion", "metadata", "labels",
    "annotations", "selector", "scheme", "timeout", "api_version",
];

fn is_schema_key(key: &str) -> bool {
    let key = key.trim().trim_matches(['"', '\'']).to_ascii_lowercase();
    // `x-kubernetes-map-type`: an OpenAPI extension.
    SCHEMA_KEYS.contains(&key.as_str()) || key.starts_with("x-")
}

/// A YAML child value that could be a secret: not a plain word, number, null, type, path
/// (`./x`, `/etc/x`), template (`{{ ... }}`, `${X}`), or code.
fn is_secret_candidate(value: &str, list_item: bool) -> bool {
    let value = value.split(" #").next().unwrap_or("").trim();
    let bare = value.trim_matches(['"', '\'']);
    // A file name like `tls.crt` names where a secret is kept.
    let file_name = bare.rsplit_once('.').is_some_and(|(stem, ext)| {
        !stem.is_empty() && (2..=4).contains(&ext.len()) && ext.bytes().all(|b| b.is_ascii_lowercase())
    });
    // Base64 (`/` and `+` inside) and UUIDs are secret shapes, whatever else they look like.
    let base64 = bare.len() >= 16
        && bare.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        && bare.bytes().any(|b| b.is_ascii_uppercase())
        && bare.bytes().any(|b| b.is_ascii_digit() || b == b'=');
    if base64 || is_uuid(bare) {
        return true;
    }
    if file_name {
        return false;
    }
    // A lowercase slug like `osps-baseline` or `maturity-3` names something.
    let slug = bare.contains('-')
        && bare.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && bare.split('-').all(|w| !w.is_empty());
    !bare.is_empty()
        // Translated text (`zero: APIキー`); secrets are ASCII.
        && bare.is_ascii()
        // Prose (`zero: API Keys`) and identifiers with a `/` (`openssf/github-repo`) are not secrets;
        // a secret-named child key (`db_password: two words`) is caught on its own line.
        && !bare.contains('/')
        && (list_item || !bare.contains([' ', '\t']))
        && !slug
        && !matches!(bare, "|" | "|-" | "|+" | ">" | ">-" | ">+")
        && !is_plain_word(bare)
        && !bare.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_' | b':'))
        && !bare.starts_with(['.', '/', '~'])
        && !bare.contains("{{")
        && !looks_like_type(bare)
        && !is_code_value(value)
}

/// How `yaml_block` treats the lines under a key.
#[derive(Clone, Copy, PartialEq)]
enum Block {
    /// A block scalar (`|`, `>`): every line is the value.
    Scalar,
    /// A Kubernetes Secret's `data:`: every value, whatever its key or depth.
    Data,
    /// Each child's value, at any depth, under a secret-named key: only values that could be a
    /// secret, and never a schema key's (`type`, `enabled`, `file`).
    Children,
}

/// The more-indented lines under a YAML key at `indent`, from `at`. Comment and blank lines don't
/// end the block. True when it took any line.
fn yaml_block(text: &str, mut at: usize, indent: usize, mode: Block, spans: &mut Spans) -> bool {
    let bytes = text.as_bytes();
    let mut took = false;
    // A list may sit at the key's own indent: `passwords:\n- a`.
    let mut list_at_indent = false;
    // Lines under a schema key (`required:\n- key`) describe fields, so they are skipped whole.
    let mut schema_pad: Option<usize> = None;
    while at < bytes.len() {
        let stop = line_end(bytes, at);
        let line = &text[at..stop];
        let content = line.trim();
        let pad = line.len() - line.trim_start().len();
        let next = stop + 1;
        if content.is_empty() || (mode != Block::Scalar && content.starts_with('#')) {
            at = next;
            continue;
        }
        let dash = content.starts_with("- ") || content == "-";
        if pad < indent || (pad == indent && !(dash && mode == Block::Children && (!took || list_at_indent))) {
            break;
        }
        list_at_indent |= pad == indent;
        took = true;
        let body = at + pad;
        let end = at + line.trim_end().len();
        at = next;
        if mode != Block::Children {
            let value = if mode == Block::Scalar {
                body
            } else {
                skip_inline_space(bytes, body + yaml_mapping_value(&text[body..end]).unwrap_or(0))
            };
            if value < end && !text[value..end].contains("{{") {
                spans.push(value..end);
            }
            continue;
        }
        let item = if dash { skip_inline_space(bytes, body + 1).min(end) } else { body };
        // Under a schema key's own children only: its siblings (`- name: x` then `value: y`) count.
        let column = item - (stop - line.len());
        match schema_pad {
            Some(p) if column > p || (column == p && dash) => continue,
            _ => schema_pad = None,
        }
        let mapping = yaml_mapping_value(&text[item..end]);
        let value = match mapping {
            Some(offset) => {
                let key = &text[item..item + offset].trim_end().trim_end_matches(':');
                if is_schema_key(key) {
                    // Only a schema key with children (`required:\n- key`) hides lines below it.
                    if item + offset >= end {
                        schema_pad = Some(column);
                    }
                    continue;
                }
                skip_inline_space(bytes, item + offset)
            }
            None => item,
        };
        if value < end && is_secret_candidate(&text[value..end], dash && mapping.is_none()) {
            let cut = text[value..end].find(" #").map_or(end, |c| value + c);
            spans.push(value..cut);
        }
    }
    took
}

/// A name whose blocks hold secrets: its last word is `secret`, `password`, `credentials`,
/// `token` and the like, or a pair like `api_key`. `auth:` or `bearer:` name a section, not a value.
fn names_a_secret_block(name: &str) -> bool {
    if !names_a_secret(name) {
        return false;
    }
    const BLOCK_WORDS: &[&str] = &[
        "secret", "secrets", "password", "passwords", "passwd", "passphrase", "credential", "credentials", "creds",
        "token", "tokens", "apikey", "apikeys",
    ];
    let words = name_words(name);
    let Some(last) = words.last() else { return false };
    BLOCK_WORDS.contains(&last.as_str())
        || words.windows(2).last().is_some_and(|p| SENSITIVE_PAIRS.contains(&(p[0].as_str(), p[1].as_str())))
}

/// A table or object name that holds only secrets: its last word is `secret(s)` or
/// `credential(s)`. `[auth]` or `"password": {` describe a feature or a field.
fn names_a_secret_table(name: &str) -> bool {
    name_words(name).last().is_some_and(|w| matches!(w.as_str(), "secret" | "secrets" | "credential" | "credentials"))
}

/// A YAML value after `name:` at the start of a line: the rest of the line, a flow list or map, or
/// the more-indented lines below (when `whole`: the name is the secret, see `names_a_secret`). Code that looks the same (`token: string`, `password: String,`,
/// `key: str = "x"`) is left to the other rules. True when it took the value.
fn yaml_value(text: &str, line_start: usize, v: usize, name: &str, spans: &mut Spans) -> bool {
    // A block scalar under a key that mentions a secret anywhere (`secret_value: |`,
    // `credentials_json: |`) is a secret whole.
    let bytes = text.as_bytes();
    let line = &text[v..line_end(bytes, v)];
    let block_head = line.split(" #").next().unwrap_or("").trim();
    let mentions = name_words(name)
        .iter()
        .any(|w| ["secret", "secrets", "password", "passwords", "credential", "credentials", "token", "tokens"].contains(&w.as_str()));
    if mentions && matches!(block_head, "|" | "|-" | "|+" | ">" | ">-" | ">+") {
        let indent = bytes[line_start..].iter().take_while(|b| matches!(b, b' ' | b'\t')).count();
        yaml_block(text, (line_end(bytes, v) + 1).min(bytes.len()), indent, Block::Scalar, spans);
        return true;
    }
    // The key's last word decides: `db_password: x`, but not `password_reset: Reset your password`.
    if !names_a_secret(name) {
        return false;
    }
    let bytes = text.as_bytes();
    let end = line_end(bytes, v);
    let indent = bytes[line_start..].iter().take_while(|b| matches!(b, b' ' | b'\t')).count();
    let mut v = v;
    let mut value = text[v..end].trim_end();
    // `password: &anchor value`: the anchor names the value, it isn't one.
    if let Some(anchor) = value.strip_prefix('&') {
        let skip = 1 + anchor.find([' ', '\t']).unwrap_or(anchor.len());
        v = skip_inline_space(bytes, v + skip);
        value = text[v..end].trim_end();
    }
    // Past a trailing comment: `password: |  # from vault`, `withCredentials: false, // default`.
    let head = if value.starts_with('#') { "" } else { value.split(" #").next().unwrap_or("").trim_end() };
    let head = head.split(" //").next().unwrap_or("").trim_end();
    // The lines below: a block scalar (`|`) whole, or the children of a secret-named key.
    let scalar = matches!(head, "|" | "|-" | "|+" | ">" | ">-" | ">+");
    if scalar {
        yaml_block(text, (end + 1).min(bytes.len()), indent, Block::Scalar, spans);
        return true;
    }
    if head.is_empty() {
        return names_a_secret_block(name) && yaml_block(text, (end + 1).min(bytes.len()), indent, Block::Children, spans);
    }
    // A template directive is not a value: `password: {{ .Values.password | quote }}`.
    if head.contains("{{") {
        return true;
    }
    // `password: z` with `.string()` on the next line is a method chain.
    let next_line = text[(end + 1).min(text.len())..].lines().next().unwrap_or("");
    if next_line.trim_start().starts_with('.') {
        return false;
    }
    // `passwords: [a, b]`, `secret: {a: b}`: everything inside.
    if (head.starts_with('[') && head.ends_with(']')) || (head.starts_with('{') && head.ends_with('}')) {
        if head.len() > 2 {
            spans.push(v + 1..v + head.len() - 1);
        }
        return true;
    }
    if value.starts_with(['"', '\'']) || is_code_value(head) || is_plain_word(head) || head.contains("{{") || !head.is_ascii() {
        return false;
    }
    if is_label(name, head) {
        return false;
    }
    spans.push(v..v + head.len());
    true
}

/// A UI label or message, as in an i18n file: several words that end like a sentence (`Forgot
/// password?`), interpolate (`%{count} keys`), or repeat the key (`new_api_key: New API key`).
fn is_label(name: &str, value: &str) -> bool {
    let value = value.trim_matches(['"', '\'']);
    if !value.contains(' ') {
        return false;
    }
    let key_words = name_words(name);
    value.ends_with(['?', '.', '!', ':'])
        || value.contains("%{")
        || value
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|w| w.len() >= 3)
            .any(|w| key_words.iter().any(|k| k.eq_ignore_ascii_case(w)))
}

/// Setting words that are never a secret: `id-token: write`, `withCredentials: true`.
const PLAIN_WORDS: &[&str] = &[
    "read", "write", "none", "true", "false", "yes", "no", "on", "off", "null", "required", "optional", "enabled",
    "disabled", "auto",
];

fn is_plain_word(value: &str) -> bool {
    PLAIN_WORDS.contains(&value.to_ascii_lowercase().as_str())
}

/// Hadoop-style and .NET-style settings, where the name and the value are separate elements or
/// attributes: `<name>db.password</name><value>x</value>`, `<entry key="password">x</entry>`,
/// `<add key="ApiKey" value="x"/>`, `<setting name="ApiKey"><value>x</value>`.
fn xml_pairs(text: &str, spans: &mut Spans) {
    use std::sync::OnceLock;
    static NAME: OnceLock<regex::Regex> = OnceLock::new();
    static ATTR: OnceLock<regex::Regex> = OnceLock::new();
    static VALUE: OnceLock<regex::Regex> = OnceLock::new();
    static VALUE_ATTR: OnceLock<regex::Regex> = OnceLock::new();
    if !text.contains('<') {
        return;
    }
    let name = NAME.get_or_init(|| regex::Regex::new(r"<name>\s*([^<]{1,200}?)\s*</name>").unwrap());
    let attr = ATTR.get_or_init(|| {
        // No `{` or `}` in the tag: JSX (`<FormField name="x" render={() => (`) is not XML.
        regex::Regex::new(r#"<[A-Za-z][\w:.-]*\s[^<>{}]*?\b(?:key|name)\s*=\s*["']([^"'<>]{1,200})["'][^<>{}]*>"#).unwrap()
    });
    let value = VALUE.get_or_init(|| regex::Regex::new(r"^\s*<value>([^<]*)</value>").unwrap());
    let value_attr = VALUE_ATTR.get_or_init(|| regex::Regex::new(r#"\bvalue\s*=\s*["']([^"']*)["']"#).unwrap());
    let next_value = |from: usize, spans: &mut Spans| {
        if let Some(c) = value.captures(&text[from..]).and_then(|c| c.get(1)).filter(|m| !m.as_str().trim().is_empty()) {
            spans.push(from + c.start()..from + c.end());
        }
    };
    for c in name.captures_iter(text) {
        let (whole, n) = (c.get(0).unwrap(), c.get(1).unwrap());
        if is_sensitive_name(n.as_str()) {
            next_value(whole.end(), spans);
        }
    }
    for c in attr.captures_iter(text) {
        let (tag, n) = (c.get(0).unwrap(), c.get(1).unwrap());
        if !is_sensitive_name(n.as_str()) {
            continue;
        }
        if let Some(v) = value_attr.captures(tag.as_str()).and_then(|v| v.get(1)).filter(|v| !v.as_str().is_empty()) {
            spans.push(tag.start() + v.start()..tag.start() + v.end());
            continue;
        }
        if tag.as_str().ends_with("/>") {
            continue;
        }
        // The element's own text, or a `<value>` child.
        let after = tag.end();
        let lt = text[after..].find('<').map_or(text.len(), |p| after + p);
        let own = &text[after..lt];
        // A UI label naming the field: `<TableHead key="access-key-id">Access key ID</TableHead>`.
        if is_label(n.as_str(), own.trim()) {
            continue;
        }
        if !own.trim().is_empty() {
            let lead = own.len() - own.trim_start().len();
            spans.push(after + lead..after + own.trim_end().len());
        } else {
            next_value(after, spans);
        }
    }
}

/// Every value in a TOML or INI table whose name is secret: `[secrets]`, `[database.password]`.
fn toml_secret_tables(text: &str, spans: &mut Spans) {
    let bytes = text.as_bytes();
    let mut secret = false;
    let mut at = 0;
    while at < bytes.len() {
        let stop = line_end(bytes, at);
        let line = text[at..stop].trim();
        if let Some(header) = line.strip_prefix('[') {
            let header = header.split('#').next().unwrap_or("").trim_end();
            if let Some(name) = header.strip_suffix(']') {
                let name = name.trim_start_matches('[').trim_end_matches(']');
                if name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'"' | b' ')) && !name.is_empty() {
                    // `[dependencies.pin-project-lite]` names a package, not a secret.
                    // `[secrets]`, `[app.credentials]`. Other tables (`[auth]`) keep their values;
                    // their secret-named keys are caught line by line.
                    secret = !name.contains("dependencies")
                        && name.split('.').any(|part| names_a_secret_table(part.trim().trim_matches('"')));
                    at = stop + 1;
                    continue;
                }
            }
        }
        // A table holds `key = value` lines with a bare key; anything else (`const x = y`) is code,
        // and ends it.
        let pair = text[at..stop].find('=').filter(|eq| {
            let key = text[at..at + eq].trim().trim_matches('"');
            !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        });
        if secret && !line.is_empty() && !line.starts_with(['#', ';']) && pair.is_none() {
            secret = false;
        }
        if secret
            && !line.starts_with(['#', ';'])
            && let Some(eq) = pair
        {
            let v = skip_inline_space(bytes, at + eq + 1);
            // Where the value ends, so a multi-line array or string doesn't end the table.
            let value_end = match bytes.get(v) {
                Some(b'"' | b'\'') => {
                    let r = quoted_value(bytes, v);
                    let end = r.as_ref().map_or(stop, |r| r.end);
                    spans.extend(r);
                    end
                }
                Some(b'[' | b'{') => {
                    bracket_literals(bytes, v, spans);
                    bracket_end(bytes, v)
                }
                _ => {
                    let end = trimmed_line_end(bytes, v);
                    if end > v {
                        spans.push(v..end);
                    }
                    stop
                }
            };
            at = line_end(bytes, value_end.max(stop)) + 1;
            continue;
        }
        at = stop + 1;
    }
}

/// The position past the bracket that closes the one at `open`, skipping quoted text.
fn bracket_end(bytes: &[u8], open: usize) -> usize {
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'[' | b'{' => depth += 1,
            b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            b'"' | b'\'' => {
                if let Some(r) = quoted_value(bytes, i) {
                    i = r.end.max(i + 1);
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

/// A Kubernetes `kind: Secret`: every value under `data:` and `stringData:`, whatever its key.
fn k8s_secret_data(text: &str, spans: &mut Spans) {
    if !text.contains("Secret") {
        return;
    }
    let bytes = text.as_bytes();
    // One YAML document at a time, split at `---` lines.
    let mut doc_start = 0;
    loop {
        let doc_end = text[doc_start..].find("\n---").map_or(text.len(), |p| doc_start + p + 1);
        let doc = &text[doc_start..doc_end];
        let is_secret = doc.lines().any(|l| {
            let l = l.trim_end();
            l.strip_prefix("kind:").is_some_and(|k| k.trim().trim_matches(['"', '\'']) == "Secret")
        });
        if is_secret {
            let mut at = doc_start;
            while at < doc_end {
                let stop = line_end(bytes, at);
                let line = &text[at..stop];
                let key = line.trim();
                if matches!(key, "data:" | "stringData:") {
                    let indent = line.len() - line.trim_start().len();
                    yaml_block(text, (stop + 1).min(doc_end), indent, Block::Data, spans);
                }
                at = stop + 1;
            }
        }
        if doc_end >= text.len() {
            break;
        }
        doc_start = doc_end;
    }
}

#[cfg(test)]
#[path = "redact_tests.rs"]
mod tests;
