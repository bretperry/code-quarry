//! Runs the real binary on a throwaway repo full of fake secrets. They're assembled at run time so
//! secret scanners don't flag this file.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Repo(PathBuf);

impl Repo {
    fn new() -> Repo {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("code-scry-e2e-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Repo(dir)
    }

    fn write(&self, rel: &str, text: &str) {
        let path = self.0.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        let out = Command::new(env!("CARGO_BIN_EXE_code-scry")).args(args).current_dir(&self.0).output().unwrap();
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        out
    }

    fn search(&self, q: &str) -> String {
        String::from_utf8(self.run(&["search", q, "-k", "20"]).stdout).unwrap()
    }

    fn index_bytes(&self) -> Vec<u8> {
        fs::read(self.0.join(".code-scry/index")).unwrap()
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// One fake of each kind: the secret, and the source line that holds it.
fn fakes() -> Vec<(String, String)> {
    let pem_body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7";
    let pem = format!("-----BEGIN {k}-----\n{pem_body}\n-----END {k}-----", k = ["PRIVATE", " KEY"].concat());
    let github = ["gh", "p_", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7aB3dE6gH9"].concat();
    let aws = ["AK", "IA", "QWERTYUIOPASDFGH"].concat();
    let stripe = ["sk", "_live_", "aB3dE6gH9jK2mN5pQ8sT1vW4"].concat();
    let jwt = ["eyJ", "hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"].concat();
    let entropy = "Zx9Kq2Lm8Pw4Rt7Vb1Nc6Yh3Js5Df0Gu".to_string();
    vec![
        (github.clone(), format!("gh = \"{github}\"")),
        (aws.clone(), format!("aws = \"{aws}\"")),
        (stripe.clone(), format!("stripe = \"{stripe}\"")),
        (jwt.clone(), format!("jwt = \"{jwt}\"")),
        (entropy.clone(), format!("blob = \"{entropy}\"")),
        (pem_body.to_string(), format!("pem = \"\"\"{pem}\"\"\"")),
        ("hunter2pw".to_string(), "dsn = \"postgres://admin:hunter2pw@db.example.com/app\"".to_string()),
        ("correcthorse".to_string(), "password = \"correcthorse\"".to_string()),
        ("batterystaple".to_string(), "api_key = 'batterystaple'".to_string()),
    ]
}

fn python_with_fakes() -> String {
    let lines: Vec<String> = fakes().iter().map(|(_, line)| format!("    {}", line.replace('\n', "\n    "))).collect();
    format!("def load_connection_settings():\n{}\n    return connect()\n", lines.join("\n"))
}

#[test]
fn no_fake_secret_reaches_the_index_or_the_output() {
    let repo = Repo::new();
    repo.write("app/settings.py", &python_with_fakes());
    repo.run(&["index", "."]);

    let bytes = repo.index_bytes();
    let out = repo.search("load connection settings");
    assert!(out.contains("load_connection_settings"), "{out}");
    assert!(out.contains("app/settings.py:1-"), "{out}");
    assert!(out.contains("return connect()"), "the body should be delivered: {out}");
    for (secret, _) in fakes() {
        assert!(!contains(&bytes, &secret), "index holds {secret}");
        assert!(!out.contains(&secret), "output holds {secret}: {out}");
    }
}

#[test]
fn the_index_holds_no_source_text() {
    let repo = Repo::new();
    repo.write("a.py", "def distinctive_function():\n    return 'a_plain_string_literal'\n");
    repo.run(&["index", "."]);
    let bytes = repo.index_bytes();
    assert!(contains(&bytes, "distinctive_function"), "symbol names are kept");
    assert!(!contains(&bytes, "a_plain_string_literal"));
}

#[test]
fn sensitive_files_are_never_indexed() {
    let repo = Repo::new();
    for rel in [".env", ".env.js", "secrets.py", "app/credentials.ts", ".ssh/key.py", "server.key", "deploy.pem"] {
        repo.write(rel, "def sensitive_marker_function():\n    return 1\n");
    }
    repo.write("ok.py", "def harmless():\n    return 1\n");
    repo.run(&["index", "."]);
    assert!(!contains(&repo.index_bytes(), "sensitive_marker_function"));
    assert!(!repo.search("sensitive marker function").contains("sensitive_marker"));
}

#[test]
fn a_symlink_out_of_the_repo_is_not_followed() {
    let outside = Repo::new();
    outside.write("elsewhere.py", "def outside_marker():\n    return 1\n");
    let repo = Repo::new();
    repo.write("ok.py", "def harmless():\n    return 1\n");
    symlink(outside.0.join("elsewhere.py"), repo.0.join("link.py")).unwrap();
    repo.run(&["index", "."]);
    assert!(!contains(&repo.index_bytes(), "outside_marker"));
}

#[test]
fn a_symlinked_parent_folder_is_not_followed() {
    let outside = Repo::new();
    outside.write("sub/elsewhere.py", "def outside_marker():\n    return 1\n");
    let repo = Repo::new();
    repo.write("ok.py", "def harmless():\n    return 1\n");
    Command::new("git").args(["init", "-q"]).current_dir(&repo.0).status().unwrap();
    repo.write("linked/a.py", "def tracked():\n    return 1\n");
    Command::new("git").args(["add", "."]).current_dir(&repo.0).status().unwrap();
    fs::remove_dir_all(repo.0.join("linked")).unwrap();
    symlink(outside.0.join("sub"), repo.0.join("linked")).unwrap();
    fs::rename(outside.0.join("sub/elsewhere.py"), outside.0.join("sub/a.py")).unwrap();
    repo.run(&["index", "."]);
    assert!(!contains(&repo.index_bytes(), "outside_marker"));
}

#[test]
fn utf16_text_is_refused() {
    let repo = Repo::new();
    let secret = ["gh", "p_", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7aB3dE6gH9"].concat();
    let utf16: Vec<u8> = format!("def utf_marker():\n    t = \"{secret}\"\n").bytes().flat_map(|b| [b, 0]).collect();
    fs::write(repo.0.join("a.py"), utf16).unwrap();
    repo.write("ok.py", "def harmless():\n    return 1\n");
    repo.run(&["index", "."]);
    let out = repo.search("utf marker");
    assert!(!out.replace('\0', "").contains(&secret), "{out}");
}

#[test]
fn a_secret_added_after_indexing_is_redacted_at_output() {
    let repo = Repo::new();
    repo.write("a.py", "def fetch_report():\n    return 1\n");
    repo.run(&["index", "."]);
    let secret = ["gh", "p_", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7aB3dE6gH9"].concat();
    repo.write("a.py", &format!("# moved\n\ndef fetch_report():\n    t = \"{secret}\"\n    return 1\n"));
    let out = repo.search("fetch report");
    assert!(!out.contains(&secret), "{out}");
    assert!(out.contains("a.py:3-5"), "the symbol's new lines: {out}");
    assert!(out.contains("[REDACTED]"), "{out}");
}

#[test]
fn a_file_made_sensitive_after_indexing_is_withheld() {
    let repo = Repo::new();
    repo.write("a.py", "def fetch_report():\n    return 'body_marker'\n");
    repo.run(&["index", "."]);
    fs::remove_file(repo.0.join("a.py")).unwrap();
    symlink(Path::new("/etc/hosts"), repo.0.join("a.py")).unwrap();
    let out = repo.search("fetch report");
    assert!(!out.contains("body_marker") && out.contains("[file unreadable"), "{out}");
}

#[test]
fn redaction_does_not_lose_the_functions_after_it() {
    let repo = Repo::new();
    repo.write("a.js", "function first() {\n  log(`token: nope ${x}`);\n  const s = 'it\\'s';\n}\nfunction second_marker() {\n  return 1;\n}\n");
    repo.run(&["index", "."]);
    assert!(contains(&repo.index_bytes(), "second_marker"));
}

#[test]
fn a_reader_that_stops_early_is_not_an_error() {
    let repo = Repo::new();
    let lines = "    x = 1\n".repeat(200);
    for i in 0..40 {
        repo.write(&format!("f{i}.py"), &format!("def fetch_report_{i}():\n{lines}"));
    }
    repo.run(&["index", "."]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_code-scry"))
        .args(["search", "fetch report", "-k", "40"])
        .current_dir(&repo.0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stderr), "");
}

#[test]
fn a_removed_function_says_so() {
    let repo = Repo::new();
    repo.write("a.py", "def fetch_report():\n    return 1\n");
    repo.run(&["index", "."]);
    repo.write("a.py", "def other():\n    return 2\n");
    assert!(repo.search("fetch report").contains("gone from the file"));
}

#[test]
fn search_finds_the_index_from_a_subfolder() {
    let repo = Repo::new();
    repo.write("src/deep/a.py", "def fetch_report():\n    return 1\n");
    repo.run(&["index", "."]);
    let out = Command::new(env!("CARGO_BIN_EXE_code-scry"))
        .args(["search", "fetch report"])
        .current_dir(repo.0.join("src/deep"))
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("src/deep/a.py:1-2"));
}

#[test]
fn nothing_indexed_is_a_clear_error() {
    let repo = Repo::new();
    let out = Command::new(env!("CARGO_BIN_EXE_code-scry")).args(["search", "x"]).current_dir(&repo.0).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("code-scry index"));
}

#[test]
fn a_damaged_index_is_refused() {
    let repo = Repo::new();
    repo.write("a.py", "def fetch_report():\n    return 1\n");
    repo.run(&["index", "."]);
    let path = repo.0.join(".code-scry/index");
    let mut bytes = fs::read(&path).unwrap();
    bytes.truncate(bytes.len() - 1);
    fs::write(&path, bytes).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_code-scry")).args(["search", "x"]).current_dir(&repo.0).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn the_index_is_gitignored_by_itself() {
    let repo = Repo::new();
    repo.write("a.py", "def f():\n    return 1\n");
    repo.run(&["index", "."]);
    assert_eq!(fs::read_to_string(repo.0.join(".code-scry/.gitignore")).unwrap(), "*\n");
}
