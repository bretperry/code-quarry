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
        let dir = std::env::temp_dir().join(format!("quarry-e2e-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Repo(dir)
    }

    fn write(&self, rel: &str, text: &str) {
        let path = self.0.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        let out = Command::new(env!("CARGO_BIN_EXE_quarry")).args(args).current_dir(&self.0).output().unwrap();
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        out
    }

    fn search(&self, q: &str) -> String {
        String::from_utf8(self.run(&["search", q, "-k", "20"]).stdout).unwrap()
    }

    /// Searches without re-indexing first, as if the change went unnoticed.
    fn search_stale(&self, q: &str) -> String {
        String::from_utf8(self.run(&["search", q, "-k", "20", "--no-refresh"]).stdout).unwrap()
    }

    fn quarry(&self, args: &[&str]) -> Output {
        // HOME points into the repo so the user's own agent folders don't change what setup does.
        Command::new(env!("CARGO_BIN_EXE_quarry")).args(args).current_dir(&self.0).env("HOME", &self.0).env("USERPROFILE", &self.0).output().unwrap()
    }

    fn git_init(&self) {
        assert!(Command::new("git").args(["init", "-q"]).current_dir(&self.0).status().unwrap().success());
    }

    fn index_bytes(&self) -> Vec<u8> {
        fs::read(self.0.join(".quarry/index")).unwrap()
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
    // Without the refresh, so this checks redaction of the live file against the old index.
    let out = repo.search_stale("fetch report");
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
    let mut child = Command::new(env!("CARGO_BIN_EXE_quarry"))
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
    assert!(repo.search_stale("fetch report").contains("gone from the file"));
}

#[test]
fn search_finds_the_index_from_a_subfolder() {
    let repo = Repo::new();
    repo.write("src/deep/a.py", "def fetch_report():\n    return 1\n");
    repo.run(&["index", "."]);
    let out = Command::new(env!("CARGO_BIN_EXE_quarry"))
        .args(["search", "fetch report"])
        .current_dir(repo.0.join("src/deep"))
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("src/deep/a.py:1-2"));
}

#[test]
fn nothing_indexed_is_a_clear_error() {
    let repo = Repo::new();
    let out = Command::new(env!("CARGO_BIN_EXE_quarry")).args(["search", "x"]).current_dir(&repo.0).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("quarry index"));
}

#[test]
fn a_damaged_index_is_refused() {
    let repo = Repo::new();
    repo.write("a.py", "def fetch_report():\n    return 1\n");
    repo.run(&["index", "."]);
    let path = repo.0.join(".quarry/index");
    let mut bytes = fs::read(&path).unwrap();
    bytes.truncate(bytes.len() - 1);
    fs::write(&path, bytes).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_quarry")).args(["search", "x"]).current_dir(&repo.0).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn the_index_is_gitignored_by_itself() {
    let repo = Repo::new();
    repo.write("a.py", "def f():\n    return 1\n");
    repo.run(&["index", "."]);
    assert_eq!(fs::read_to_string(repo.0.join(".quarry/.gitignore")).unwrap(), "*\n");
}

#[test]
fn a_comment_above_a_function_makes_it_findable() {
    let repo = Repo::new();
    repo.write("a.js", "// Retries a failed upload with exponential backoff.\nfunction send(x) {\n  return x;\n}\n\nfunction other(y) {\n  return y + 1;\n}\n");
    repo.run(&["index", "."]);
    let out = repo.search("exponential backoff");
    assert!(out.lines().next().unwrap().contains("a.js:2-4 send"), "{out}");
}

#[test]
fn a_secret_in_a_comment_above_a_function_does_not_reach_the_index_or_the_output() {
    let repo = Repo::new();
    let token = ["gh", "p_", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7aB3dE6gH9"].concat();
    repo.write("a.js", &format!("// Uses {token} to push releases.\nfunction publish(x) {{\n  return x;\n}}\n"));
    repo.run(&["index", "."]);
    assert!(!contains(&repo.index_bytes(), &token));
    assert!(!repo.search("push releases").contains(&token));
}

#[test]
fn a_function_ranks_above_unrelated_code_when_its_caller_matches() {
    let repo = Repo::new();
    repo.write("a.js", "function retryUpload(x) {\n  return send(x);\n}\n\nfunction other(y) {\n  return y + 1;\n}\n\nfunction send(x) {\n  return x;\n}\n");
    repo.run(&["index", "."]);
    let out = repo.search("retry upload");
    let at = |name: &str| out.lines().filter(|l| l.starts_with("--- ")).position(|l| l.contains(name)).unwrap();
    assert!(at(" send ") < at(" other "), "{out}");
}

#[test]
fn search_builds_the_index_itself_in_a_git_repo() {
    let repo = Repo::new();
    repo.git_init();
    repo.write("a.py", "def fetch_report():\n    return 1\n");
    // Only git-tracked files are indexed.
    assert!(Command::new("git").args(["add", "a.py"]).current_dir(&repo.0).status().unwrap().success());
    let out = repo.quarry(&["search", "fetch report"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no index yet"));
    assert!(String::from_utf8_lossy(&out.stdout).contains("a.py:1-2"));
}

#[test]
fn search_reindexes_when_a_file_changed() {
    let repo = Repo::new();
    repo.write("a.py", "def fetch_report():\n    return 1\n");
    repo.run(&["index", "."]);
    repo.write("b.py", "def upload_invoice():\n    return 2\n");
    let out = repo.quarry(&["search", "upload invoice"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("re-indexing"));
    assert!(String::from_utf8_lossy(&out.stdout).contains("b.py:1-2"));
    let again = repo.quarry(&["search", "upload invoice"]);
    assert_eq!(String::from_utf8_lossy(&again.stderr), "", "an unchanged repo is not re-indexed");
}

#[test]
fn setup_writes_nothing_without_a_yes() {
    let repo = Repo::new();
    repo.write("CLAUDE.md", "# Mine\n");
    let out = repo.quarry(&["setup"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("Nothing written"));
    assert!(!repo.0.join("AGENTS.md").exists());
    assert_eq!(fs::read_to_string(repo.0.join("CLAUDE.md")).unwrap(), "# Mine\n");
}

#[test]
fn setup_with_yes_adds_the_rule_and_indexes() {
    let repo = Repo::new();
    repo.write("CLAUDE.md", "# Mine\n");
    repo.write("a.py", "def fetch_report():\n    return 1\n");
    assert!(repo.quarry(&["setup", "--yes"]).status.success());
    assert!(fs::read_to_string(repo.0.join("AGENTS.md")).unwrap().contains("quarry search"));
    let claude = fs::read_to_string(repo.0.join("CLAUDE.md")).unwrap();
    assert!(claude.starts_with("# Mine\n\n## Code search") && claude.contains("quarry search"), "{claude}");
    assert!(repo.0.join(".quarry/index").is_file());
    let out = String::from_utf8(repo.quarry(&["setup", "--yes"]).stdout).unwrap();
    assert!(out.contains("already mention quarry"), "{out}");
}

#[test]
fn help_works_for_every_command_and_mistakes_point_to_it() {
    let repo = Repo::new();
    for args in [&["help"][..], &["--help"], &["help", "search"], &["search", "--help"], &["setup", "-h"], &["index", "--help"]] {
        let out = repo.quarry(args);
        assert!(out.status.success() && !out.stdout.is_empty(), "{args:?}");
    }
    let out = repo.quarry(&["search"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("quarry help search"));
    let out = repo.quarry(&["retry", "logic"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("quarry search \"retry logic\""));
    let version = String::from_utf8(repo.quarry(&["--version"]).stdout).unwrap();
    assert_eq!(version, format!("quarry {}\n", env!("CARGO_PKG_VERSION")));
}

// ---- quarry grep, sensitive-list, env-keys ----

struct Run {
    out: String,
    err: String,
    code: i32,
}

/// Runs the binary in `dir`, with HOME inside the repo so the user's own folders change nothing.
fn run_in(dir: &Path, args: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_quarry")).args(args).current_dir(dir).env("HOME", dir).output().unwrap();
    Run {
        out: String::from_utf8(out.stdout).unwrap(),
        err: String::from_utf8(out.stderr).unwrap(),
        code: out.status.code().unwrap(),
    }
}

impl Repo {
    fn grep(&self, args: &[&str]) -> Run {
        let mut all = vec!["grep"];
        all.extend_from_slice(args);
        run_in(&self.0, &all)
    }

    /// A git repo with a few files that all hold the word "needle".
    fn needle_repo() -> Repo {
        let repo = Repo::new();
        repo.git_init();
        repo.write("a.txt", "one\nTwo needle\nthree\nfour\nfive NEEDLE\nsix\n");
        repo.write("src/b.ts", "needle in ts\n");
        repo.write("src/c.test.ts", "needle in test\n");
        repo.write("docs/d.md", "needle md\nneedles\n");
        repo
    }
}

#[test]
fn grep_prints_what_the_mockup_shows() {
    let repo = Repo::new();
    repo.git_init();
    let stripe = fakes()[2].0.clone();
    let mut pay = vec!["import Stripe from \"stripe\";".to_string()];
    pay.extend((2..=10).map(|_| String::new()));
    pay.extend(["const client = new Stripe(".into(), format!("  process.env.STRIPE_KEY ?? \"{stripe}\","), ");".into()]);
    repo.write("src/pay.ts", &(pay.join("\n") + "\n"));
    repo.write("src/config.ts", &format!("export const gh = \"{}\";\n", fakes()[0].0));
    repo.write(".env.local", &format!("STRIPE_KEY={stripe}\n"));
    let r = repo.grep(&["-n", "STRIPE_KEY", "-C1"]);
    assert_eq!(r.out, "src/pay.ts-11-const client = new Stripe(\nsrc/pay.ts:12:  process.env.STRIPE_KEY ?? \"[REDACTED]\",\nsrc/pay.ts-13-);\n");
    assert_eq!(
        r.err,
        "quarry: withheld 1 file (sensitive: .env.local)\nquarry: 2 files had redactions; matches inside them can't show\n"
    );
    assert_eq!(r.code, 0);
}

#[test]
fn grepping_a_secrets_value_finds_nothing_in_any_mode() {
    let repo = Repo::new();
    repo.git_init();
    repo.write("app/settings.py", &python_with_fakes());
    repo.write(".env", &fakes().iter().map(|(s, _)| format!("K{}={s}\n", s.len())).collect::<String>());
    for (secret, _) in fakes() {
        let upper = secret.to_uppercase();
        let escaped = secret.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_string() } else { format!("\\{c}") }).collect::<String>();
        let piece = secret.chars().take(12).collect::<String>();
        for (flags, pattern) in [
            (vec!["-F"], secret.as_str()),
            (vec![], escaped.as_str()),
            (vec!["-F", "-i"], upper.as_str()),
            (vec!["-F", "-w"], secret.as_str()),
            (vec!["-F"], piece.as_str()),
        ] {
            for mode in [&[][..], &["-l"], &["-c"], &["-C", "2"], &["-m", "1"]] {
                let mut args = flags.clone();
                args.extend_from_slice(mode);
                args.extend(["--", pattern]);
                let r = repo.grep(&args);
                assert_eq!((r.code, r.out.as_str()), (1, ""), "{args:?}: {}", r.out);
                assert!(!r.err.contains(&secret), "{args:?}: {}", r.err);
            }
        }
    }
    // The same files do match on their redacted text.
    let r = repo.grep(&["-c", "-F", "[REDACTED]"]);
    assert!(r.code == 0 && r.out.starts_with("app/settings.py:"), "{}", r.out);
}

#[test]
fn what_the_notes_say_does_not_depend_on_the_pattern() {
    let repo = Repo::needle_repo();
    repo.write("src/key.ts", &format!("const k = \"{}\";\n", fakes()[0].0));
    repo.write(".env", "A=1\n");
    let hit = repo.grep(&["needle"]);
    let miss = repo.grep(&[fakes()[0].0.as_str()]);
    assert_eq!((hit.code, miss.code), (0, 1));
    assert_eq!(hit.err, miss.err);
    assert_eq!(hit.err, "quarry: withheld 1 file (sensitive: .env)\nquarry: 1 file had redactions; matches inside it can't show\n");
}

#[test]
fn a_sensitive_file_is_withheld_by_name_and_never_read() {
    let repo = Repo::new();
    repo.git_init();
    repo.write(".env", "PLAIN_VALUE_XYZ=1\n");
    repo.write("keys/a.py", "PLAIN_VALUE_XYZ = 1\n");
    repo.write("deploy/server.pem", "PLAIN_VALUE_XYZ\n");
    repo.write("src/ok.py", "x = 1\n");
    for args in [&["PLAIN_VALUE_XYZ"][..], &["-l", "PLAIN_VALUE_XYZ"], &["-c", "PLAIN_VALUE_XYZ"]] {
        let r = repo.grep(args);
        assert_eq!((r.code, r.out.as_str()), (1, ""), "{args:?}");
        assert_eq!(r.err, "quarry: withheld 3 files (sensitive: .env, deploy/server.pem, keys/a.py)\n");
    }
}

#[test]
fn flags_pick_lines_files_and_counts() {
    let repo = Repo::needle_repo();
    let all = "a.txt:2:Two needle\ndocs/d.md:1:needle md\ndocs/d.md:2:needles\nsrc/b.ts:1:needle in ts\nsrc/c.test.ts:1:needle in test\n";
    assert_eq!(repo.grep(&["needle"]).out, all);
    assert_eq!(repo.grep(&["-n", "needle"]).out, all);
    assert_eq!(repo.grep(&["-i", "needle"]).out, all.replace("a.txt:2:Two needle\n", "a.txt:2:Two needle\na.txt:5:five NEEDLE\n"));
    assert_eq!(repo.grep(&["-w", "needle"]).out, all.replace("docs/d.md:2:needles\n", ""));
    assert_eq!(repo.grep(&["-l", "needle"]).out, "a.txt\ndocs/d.md\nsrc/b.ts\nsrc/c.test.ts\n");
    assert_eq!(repo.grep(&["-c", "needle"]).out, "a.txt:1\ndocs/d.md:2\nsrc/b.ts:1\nsrc/c.test.ts:1\n");
    assert_eq!(repo.grep(&["-c", "-m1", "needle"]).out, "a.txt:1\ndocs/d.md:1\nsrc/b.ts:1\nsrc/c.test.ts:1\n");
    assert_eq!(repo.grep(&["-m1", "needle", "docs"]).out, "docs/d.md:1:needle md\n");
    assert_eq!(repo.grep(&["-F", "-i", "NEEDLES"]).out, "docs/d.md:2:needles\n");
    assert_eq!(repo.grep(&["-C1", "Two"]).out, "a.txt-1-one\na.txt:2:Two needle\na.txt-3-three\n");
    assert_eq!(repo.grep(&["-A1", "Two|six"]).out, "a.txt:2:Two needle\na.txt-3-three\n--\na.txt:6:six\n");
    assert_eq!(repo.grep(&["-B", "1", "five"]).out, "a.txt-4-four\na.txt:5:five NEEDLE\n");
    assert_eq!(repo.grep(&["-A1", "needle md", "docs", "a.txt"]).out, "docs/d.md:1:needle md\ndocs/d.md-2-needles\n");
}

#[test]
fn globs_paths_and_the_search_folder() {
    let repo = Repo::needle_repo();
    assert_eq!(repo.grep(&["-l", "needle", "-g", "*.ts"]).out, "src/b.ts\nsrc/c.test.ts\n");
    assert_eq!(repo.grep(&["-l", "needle", "-g", "*.ts", "-g", "!*.test.ts"]).out, "src/b.ts\n");
    assert_eq!(repo.grep(&["-l", "needle", "-g", "!src"]).out, "a.txt\ndocs/d.md\n");
    assert_eq!(repo.grep(&["-l", "needle", "-g", "docs/**"]).out, "docs/d.md\n");
    assert_eq!(repo.grep(&["-l", "needle", "src"]).out, "src/b.ts\nsrc/c.test.ts\n");
    assert_eq!(repo.grep(&["-l", "needle", "src/b.ts", "docs/"]).out, "docs/d.md\nsrc/b.ts\n");
    // From a subfolder it searches that folder, and paths read from there.
    let sub = run_in(&repo.0.join("src"), &["grep", "-n", "needle"]);
    assert_eq!(sub.out, "b.ts:1:needle in ts\nc.test.ts:1:needle in test\n");
    // --repo names the folder from anywhere.
    let far = run_in(&std::env::temp_dir(), &["grep", "-l", "needle", "src", "--repo", repo.0.to_str().unwrap()]);
    assert_eq!((far.code, far.out.as_str()), (0, "src/b.ts\nsrc/c.test.ts\n"), "{}", far.err);
}

#[test]
fn exit_codes_say_match_none_or_error() {
    let repo = Repo::needle_repo();
    assert_eq!(repo.grep(&["needle"]).code, 0);
    let none = repo.grep(&["absent"]);
    assert_eq!((none.code, none.out.as_str(), none.err.as_str()), (1, "", ""));
    assert_eq!(repo.grep(&["-l", "absent"]).code, 1);
    assert_eq!(repo.grep(&["-m0", "needle"]).code, 1);
}

#[test]
fn bad_input_is_refused_with_exit_2_and_a_reason() {
    let repo = Repo::needle_repo();
    let table: &[(&[&str], &str)] = &[
        (&["--wat", "x"], "unknown option --wat"),
        (&["-z", "x"], "unknown option -z"),
        (&[], "grep needs a pattern"),
        (&["-i"], "grep needs a pattern"),
        (&[""], "the pattern is empty"),
        (&["(", "src"], "bad pattern"),
        (&["(?<=x)y"], "bad pattern"),
        (&["x", "nope"], "no such file or folder: nope"),
        (&["x", ".."], "is outside"),
        (&["-C", "x", "p"], "-C needs a number"),
        (&["-m"], "-m needs a number"),
        (&["-g"], "-g needs a glob"),
        (&["x", "-g", "*.{ts"], "bad glob"),
        (&["x", "--repo", "/no/such/folder"], "no such folder"),
        (&["x", "--repo"], "--repo needs a folder"),
    ];
    for (args, why) in table {
        let r = repo.grep(args);
        assert_eq!(r.code, 2, "{args:?}: {}", r.err);
        assert!(r.out.is_empty() && r.err.contains(why), "{args:?}: {}", r.err);
    }
    let r = repo.grep(&["-P", "x"]);
    assert_eq!((r.code, r.out.as_str(), r.err.as_str()), (2, "", "quarry: -P is not supported (Rust regex syntax only)\n"));
    assert!(repo.grep(&["--bad-flag", "x"]).err.contains("Run `quarry help grep`"));
}

#[test]
fn a_long_line_and_a_long_result_are_cut() {
    let repo = Repo::new();
    repo.git_init();
    repo.write("long.txt", &format!("needle {}\n", "z".repeat(1000)));
    let r = repo.grep(&["needle"]);
    assert_eq!(r.out, format!("long.txt:1:needle {}... [cut]\n", "z".repeat(300 - "needle ".len())));

    let lines: String = (1..=2000).map(|i| format!("needle number {i} {}\n", "y".repeat(80))).collect();
    repo.write("many.txt", &lines);
    let r = repo.grep(&["needle number", "many.txt"]);
    assert_eq!(r.code, 0);
    let (body, marker) = r.out.trim_end().rsplit_once('\n').unwrap();
    assert!(body.chars().count() < 20_000, "{}", body.chars().count());
    let shown = body.lines().count();
    assert_eq!(marker, format!("... [cut: {} more matches. Narrow the pattern or add -g]", 2000 - shown));
    // Counts and file lists are cut the same way.
    for i in 0..400 {
        repo.write(&format!("deep/{}/{i}.txt", "d".repeat(60)), "needle\n");
    }
    let r = repo.grep(&["-l", "needle", "deep"]);
    assert!(r.out.chars().count() < 20_100 && r.out.ends_with(" more files. Narrow the pattern or add -g]\n"), "{}", &r.out[r.out.len().saturating_sub(100)..]);
}

#[test]
fn ignored_files_need_no_ignore_and_git_internals_never_show() {
    let repo = Repo::needle_repo();
    repo.write(".gitignore", "dist/\n.env\n");
    repo.write("dist/out.js", "needle built\n");
    repo.write(".env", "needle=1\n");
    let plain = repo.grep(&["-l", "needle"]);
    assert_eq!((plain.out.as_str(), plain.err.as_str()), ("a.txt\ndocs/d.md\nsrc/b.ts\nsrc/c.test.ts\n", ""));
    let all = repo.grep(&["-l", "needle", "--no-ignore"]);
    assert_eq!(all.out, "a.txt\ndist/out.js\ndocs/d.md\nsrc/b.ts\nsrc/c.test.ts\n");
    assert_eq!(all.err, "quarry: withheld 1 file (sensitive: .env)\n");
    assert!(!all.out.contains(".git/"));
    assert_eq!(repo.grep(&["-l", "needle", "--no-ignore", "dist"]).out, "dist/out.js\n");
}

#[test]
fn outside_git_it_walks_the_folder_and_skips_dot_folders() {
    let repo = Repo::new();
    repo.write("visible/b.txt", "needle\n");
    repo.write(".hidden/a.txt", "needle\n");
    repo.write(".env", "needle\n");
    assert_eq!(repo.grep(&["-l", "needle"]).out, "visible/b.txt\n");
    assert_eq!(repo.grep(&["-l", "needle", ".hidden"]).out, ".hidden/a.txt\n");
    assert_eq!(repo.grep(&["-l", "needle", "--no-ignore"]).out, ".hidden/a.txt\nvisible/b.txt\n");
    assert!(repo.grep(&["needle"]).err.contains("withheld 1 file (sensitive: .env)"));
}

#[test]
fn a_file_that_vanishes_or_cannot_be_read_is_skipped_quietly() {
    let repo = Repo::new();
    repo.git_init();
    repo.write("gone.txt", "needle\n");
    repo.write("kept.txt", "needle\n");
    repo.write("binary.bin", "needle\0\n");
    repo.write("big.txt", &format!("needle\n{}", "x\n".repeat(300_000)));
    repo.write("utf16.txt", "n\0e\0e\0d\0l\0e\0");
    assert!(Command::new("git").args(["add", "."]).current_dir(&repo.0).status().unwrap().success());
    fs::remove_file(repo.0.join("gone.txt")).unwrap();
    let outside = std::env::temp_dir().join(format!("quarry-outside-{}", std::process::id()));
    fs::write(&outside, "needle\n").unwrap();
    symlink(&outside, repo.0.join("link.txt")).unwrap();
    let r = repo.grep(&["-l", "needle"]);
    let _ = fs::remove_file(&outside);
    assert_eq!((r.code, r.out.as_str(), r.err.as_str()), (0, "kept.txt\n", ""));
}

#[test]
fn an_empty_repo_has_no_match_and_a_nested_repo_is_named_as_not_searched() {
    let repo = Repo::new();
    repo.git_init();
    let r = repo.grep(&["x"]);
    assert_eq!((r.code, r.out.as_str(), r.err.as_str()), (1, "", ""));
    repo.write("a.txt", "needle\n");
    assert!(Command::new("git").args(["init", "-q", "libs/inner"]).current_dir(&repo.0).status().unwrap().success());
    repo.write("libs/inner/x.txt", "needle\n");
    let r = repo.grep(&["-l", "needle"]);
    assert_eq!((r.code, r.out.as_str()), (0, "a.txt\n"));
    assert_eq!(r.err, "quarry: 1 submodule not searched (libs/inner)\n");
}

#[test]
fn grep_needs_no_index_and_writes_nothing() {
    let repo = Repo::needle_repo();
    repo.grep(&["needle"]);
    assert!(!repo.0.join(".quarry").exists());
}

#[test]
fn sensitive_list_prints_the_narrow_list_as_json() {
    let repo = Repo::new();
    let r = run_in(&repo.0, &["sensitive-list", "--json"]);
    assert_eq!(r.code, 0);
    assert_eq!(
        r.out,
        "{\"dirs\":[\".ssh\",\".aws\",\".gnupg\",\".kube\"],\
\"names\":[\".env*\",\"id_rsa\",\"id_dsa\",\"id_ecdsa\",\"id_ed25519\",\".netrc\",\".npmrc\",\".pypirc\",\".pgpass\",\".git-credentials\"],\
\"extensions\":[\"pem\",\"key\",\"p12\",\"pfx\",\"jks\",\"keystore\",\"ppk\",\"kdbx\",\"tfvars\",\"tfstate\"],\
\"exempt_suffixes\":[\".example\",\".sample\",\".template\"]}\n"
    );
    for args in [&["sensitive-list"][..], &["sensitive-list", "--yaml"], &["sensitive-list", "--json", "x"]] {
        let r = run_in(&repo.0, args);
        assert!(r.code != 0 && r.out.is_empty() && r.err.contains("quarry help sensitive-list"), "{args:?}");
    }
}

#[test]
fn env_keys_prints_names_and_never_a_value() {
    let repo = Repo::new();
    let secrets: Vec<String> = fakes().into_iter().map(|(s, _)| s).collect();
    let pem = format!("-----BEGIN {k}-----\n{}\n-----END {k}-----", secrets[5], k = ["PRIVATE", " KEY"].concat());
    repo.write(
        ".env",
        &format!(
            "# comment\nDATABASE_URL=postgres://admin:{}@db.example.com/app\nSTRIPE_KEY={}\nexport GH_TOKEN=\"{}\"\nPASSWORD={}\nPRIVATE_KEY=\"{}\"\nAFTER_KEY=1\nQUOTED='a=b'\n\nSTRIPE_KEY=again\n",
            secrets[6], secrets[2], secrets[0], secrets[7], pem
        ),
    );
    let r = run_in(&repo.0, &["env-keys", ".env"]);
    assert_eq!((r.code, r.err.as_str()), (0, ""));
    assert_eq!(r.out, "DATABASE_URL\nSTRIPE_KEY\nGH_TOKEN\nPASSWORD\nPRIVATE_KEY\nAFTER_KEY\nQUOTED\n");
    assert!(!r.out.contains('='));
    for s in &secrets {
        assert!(!r.out.contains(s.as_str()) && !r.err.contains(s.as_str()));
    }
}

#[test]
fn env_keys_refuses_a_key_file_and_a_missing_file() {
    let repo = Repo::new();
    let body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7ab==";
    repo.write("server.pem", &format!("-----BEGIN {k}-----\n{body}\n-----END {k}-----\n", k = ["PRIVATE", " KEY"].concat()));
    let r = run_in(&repo.0, &["env-keys", "server.pem"]);
    assert!(r.code != 0 && r.out.is_empty() && r.err.contains("key file"), "{}", r.out);
    assert!(!r.err.contains(body));
    let r = run_in(&repo.0, &["env-keys", "nope"]);
    assert!(r.code != 0 && r.out.is_empty() && r.err.contains("can't read nope"));
    for args in [&["env-keys"][..], &["env-keys", "a", "b"], &["env-keys", "--json"]] {
        let r = run_in(&repo.0, args);
        assert!(r.code != 0 && r.err.contains("quarry help env-keys"), "{args:?}");
    }
    repo.write("empty.env", "");
    let r = run_in(&repo.0, &["env-keys", "empty.env"]);
    assert_eq!((r.code, r.out.as_str()), (0, ""));
}

#[test]
fn help_covers_the_new_commands() {
    let repo = Repo::new();
    for args in [&["help", "grep"][..], &["grep", "--help"], &["help", "sensitive-list"], &["sensitive-list", "-h"], &["help", "env-keys"], &["env-keys", "--help"]] {
        let r = run_in(&repo.0, args);
        assert!(r.code == 0 && r.out.starts_with("quarry "), "{args:?}");
    }
    let main = run_in(&repo.0, &["help"]).out;
    assert!(main.contains("quarry grep") || main.contains("grep <pattern>"));
}

#[test]
fn setup_names_quarry_grep_in_the_rule() {
    let repo = Repo::new();
    repo.write("a.py", "def f():\n    return 1\n");
    assert!(repo.quarry(&["setup", "--yes"]).status.success());
    assert!(fs::read_to_string(repo.0.join("AGENTS.md")).unwrap().contains("quarry grep"));
}
