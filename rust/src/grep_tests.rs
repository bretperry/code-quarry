//! The matcher on strings, and the seeded loop that tries to read a secret back out of it. Fake
//! secrets are assembled at run time so secret scanners don't flag this file.
use super::*;

fn matcher(flags: &[&str], pattern: &str) -> (Options, Matcher) {
    let mut args: Vec<String> = flags.iter().map(|s| s.to_string()).collect();
    args.push("--".into());
    args.push(pattern.to_string());
    let o = parse(args).unwrap();
    let m = Matcher::new(&o).unwrap();
    (o, m)
}

/// What `quarry grep` would print for one file with this text.
fn grep(text: &str, flags: &[&str], pattern: &str) -> String {
    let (o, m) = matcher(flags, pattern);
    let hits = search_text("f.txt", text, &m);
    if hits.count == 0 { String::new() } else { render(&[("f.txt".into(), hits)], o.mode, o.after > 0 || o.before > 0) }
}

const TEXT: &str = "alpha\nbeta needle\ngamma\ndelta\nepsilon\nzeta needle\neta\ntheta\niota\nkappa\nlambda needle\n";

#[test]
fn a_match_prints_path_line_text() {
    assert_eq!(grep(TEXT, &[], "needle"), "f.txt:2:beta needle\nf.txt:6:zeta needle\nf.txt:11:lambda needle\n");
}

#[test]
fn context_lines_use_a_dash_and_groups_are_split_by_two_dashes() {
    assert_eq!(
        grep(TEXT, &["-C1"], "needle"),
        "f.txt-1-alpha\nf.txt:2:beta needle\nf.txt-3-gamma\n--\nf.txt-5-epsilon\nf.txt:6:zeta needle\nf.txt-7-eta\n--\nf.txt-10-kappa\nf.txt:11:lambda needle\n"
    );
}

#[test]
fn overlapping_context_is_one_group_and_a_nearby_match_is_marked_as_a_match() {
    let out = grep(TEXT, &["-A", "4"], "beta|zeta");
    assert_eq!(
        out,
        "f.txt:2:beta needle\nf.txt-3-gamma\nf.txt-4-delta\nf.txt-5-epsilon\nf.txt:6:zeta needle\nf.txt-7-eta\nf.txt-8-theta\nf.txt-9-iota\nf.txt-10-kappa\n"
    );
}

#[test]
fn before_and_after_can_differ_and_override_c() {
    assert_eq!(grep(TEXT, &["-C", "3", "-A", "0"], "zeta"), "f.txt-3-gamma\nf.txt-4-delta\nf.txt-5-epsilon\nf.txt:6:zeta needle\n");
    assert_eq!(grep(TEXT, &["-B1"], "zeta"), "f.txt-5-epsilon\nf.txt:6:zeta needle\n");
}

#[test]
fn context_past_either_end_of_the_file_is_clamped() {
    assert_eq!(grep("a\nb\n", &["-C", "99999999999"], "a"), "f.txt:1:a\nf.txt-2-b\n");
}

#[test]
fn max_per_file_stops_after_n_matching_lines() {
    assert_eq!(grep(TEXT, &["-m", "2"], "needle"), "f.txt:2:beta needle\nf.txt:6:zeta needle\n");
    assert_eq!(grep(TEXT, &["-m0"], "needle"), "");
    // Trailing context still shows; a later match there is context, not a match.
    assert_eq!(
        grep(TEXT, &["-m1", "-A5"], "needle"),
        "f.txt:2:beta needle\nf.txt-3-gamma\nf.txt-4-delta\nf.txt-5-epsilon\nf.txt-6-zeta needle\nf.txt-7-eta\n"
    );
    assert_eq!(grep(TEXT, &["-c", "-m2"], "needle"), "f.txt:2\n");
}

#[test]
fn files_only_and_counts() {
    assert_eq!(grep(TEXT, &["-l"], "needle"), "f.txt\n");
    assert_eq!(grep(TEXT, &["-c"], "needle"), "f.txt:3\n");
    assert_eq!(grep(TEXT, &["-c", "-l"], "needle"), "f.txt\n");
    assert_eq!(grep(TEXT, &["-l", "-c"], "needle"), "f.txt\n");
    assert_eq!(grep(TEXT, &["-c"], "absent"), "");
}

#[test]
fn fixed_ignore_case_and_word() {
    assert_eq!(grep("a.b\naxb\n", &["-F"], "a.b"), "f.txt:1:a.b\n");
    assert_eq!(grep("a.b\naxb\n", &[], "a.b"), "f.txt:1:a.b\nf.txt:2:axb\n");
    assert_eq!(grep("Retry\nretry\n", &["-i"], "RETRY"), "f.txt:1:Retry\nf.txt:2:retry\n");
    assert_eq!(grep("Retry\nretry\n", &[], "retry"), "f.txt:2:retry\n");
    let words = "retry\nretries\nno_retry\n(retry)\nretry-now\nx retry y\n";
    assert_eq!(grep(words, &["-w"], "retry"), "f.txt:1:retry\nf.txt:4:(retry)\nf.txt:5:retry-now\nf.txt:6:x retry y\n");
    assert_eq!(grep("a.b c\nxa.b c\n", &["-wF"], "a.b"), "f.txt:1:a.b c\n");
}

#[test]
fn a_pattern_cannot_span_lines() {
    assert_eq!(grep("foo\nbar\n", &[], r"foo\s+bar"), "");
    assert_eq!(grep("foo\nbar\n", &[], r"foo$"), "f.txt:1:foo\n");
    assert_eq!(grep("foo\n\nbar\n", &[], "^$"), "f.txt:2:\n");
}

#[test]
fn crlf_lines_match_without_the_carriage_return() {
    assert_eq!(grep("one\r\ntwo\r\n", &[], "one$"), "f.txt:1:one\n");
}

#[test]
fn a_long_line_is_cut_and_says_so() {
    let line = "x".repeat(MAX_LINE_CHARS + 50);
    assert_eq!(grep(&line, &[], "x"), format!("f.txt:1:{}... [cut]\n", "x".repeat(MAX_LINE_CHARS)));
    let exact = "é".repeat(MAX_LINE_CHARS);
    assert_eq!(grep(&exact, &[], "é"), format!("f.txt:1:{exact}\n"));
    let multibyte = "é".repeat(MAX_LINE_CHARS + 1);
    assert_eq!(grep(&multibyte, &[], "é"), format!("f.txt:1:{}... [cut]\n", "é".repeat(MAX_LINE_CHARS)));
}

#[test]
fn output_is_cut_at_the_cap_with_a_count_of_what_is_left() {
    let text: String = (1..=1000).map(|i| format!("line {i} needle {}\n", "y".repeat(80))).collect();
    let out = grep(&text, &[], "needle");
    let (body, marker) = out.trim_end().rsplit_once('\n').unwrap();
    let body_chars = body.chars().count() + 1;
    assert!(body_chars <= MAX_OUTPUT_CHARS);
    let shown = body.lines().count();
    assert_eq!(marker, format!("... [cut: {} more matches. Narrow the pattern or add -g]", 1000 - shown));
    // The next line would not have fit.
    let next = format!("f.txt:{}:line {} needle {}\n", shown + 1, shown + 1, "y".repeat(80));
    assert!(body_chars + next.chars().count() > MAX_OUTPUT_CHARS);
}

#[test]
fn one_match_left_says_match() {
    // Lines 10 to 99 are matches, each printed as 223 characters: 89 fit in the cap and the 90th doesn't.
    let line = format!("x{}", "z".repeat(212));
    let text = format!("{}{}", "no\n".repeat(9), format!("{line}\n").repeat(90));
    let out = grep(&text, &[], "x");
    assert_eq!(out.lines().count(), 90, "89 matches and the marker");
    assert_eq!(out.lines().last().unwrap(), "... [cut: 1 more match. Narrow the pattern or add -g]");
}

#[test]
fn a_cut_file_list_counts_files() {
    let (_, m) = matcher(&[], "x");
    let results: Vec<_> = (0..400).map(|i| (format!("{}/{i}.txt", "d".repeat(60)), search_text("p", "x\n", &m))).collect();
    let out = render(&results, Mode::Files, false);
    let last = out.lines().last().unwrap();
    assert!(last.starts_with("... [cut: ") && last.ends_with(" more files. Narrow the pattern or add -g]"), "{last}");
    let counted = render(&results, Mode::Counts, false);
    assert!(counted.starts_with(&format!("{}/0.txt:1\n", "d".repeat(60))));
}

#[test]
fn nothing_matching_prints_nothing() {
    assert_eq!(grep(TEXT, &[], "absent"), "");
    assert_eq!(grep("", &[], "x"), "");
}

#[test]
fn separators_also_go_between_files() {
    let (_, m) = matcher(&["-A1"], "x");
    let a = search_text("a", "x\ny\n", &m);
    let b = search_text("b", "x\ny\n", &m);
    assert_eq!(render(&[("a".into(), a), ("b".into(), b)], Mode::Lines, true), "a:1:x\na-2-y\n--\nb:1:x\nb-2-y\n");
}

#[test]
fn a_redacted_value_matches_only_as_the_marker() {
    let token = ["gh", "p_", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7aB3dE6gH9"].concat();
    let clean = redact::clean(&format!("let t = \"{token}\";\n")).unwrap();
    assert_eq!(grep(&clean, &[], &token), "");
    assert_eq!(grep(&clean, &["-F"], redact::MARK), "f.txt:1:let t = \"[REDACTED]\";\n");
}

// ---- parsing ----

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn flags_can_be_joined_and_values_attached() {
    let o = parse(args(&["-niC2", "-m5", "-g*.rs", "-g", "!x", "pat", "src", "lib"])).unwrap();
    assert!(o.ignore_case && o.after == 2 && o.before == 2 && o.max_per_file == Some(5));
    assert_eq!(o.globs, ["*.rs", "!x"]);
    assert_eq!(o.pattern, "pat");
    assert_eq!(o.paths, ["src", "lib"]);
    let o = parse(args(&["-nA3", "x"])).unwrap();
    assert_eq!((o.after, o.before), (3, 0));
}

#[test]
fn flags_may_come_after_the_pattern() {
    let o = parse(args(&["-n", "STRIPE_KEY", "-C1"])).unwrap();
    assert_eq!((o.pattern.as_str(), o.after, o.before), ("STRIPE_KEY", 1, 1));
}

#[test]
fn double_dash_lets_a_pattern_start_with_a_dash() {
    let o = parse(args(&["-i", "--", "-x", "src"])).unwrap();
    assert_eq!((o.pattern.as_str(), o.ignore_case), ("-x", true));
    assert_eq!(o.paths, ["src"]);
    assert_eq!(parse(args(&["-"])).unwrap().pattern, "-");
}

#[test]
fn bad_input_is_refused_with_a_reason() {
    let err = |a: &[&str]| parse(args(a)).unwrap_err();
    assert!(err(&["-z", "x"]).starts_with("quarry: unknown option -z\nRun `quarry help grep`"));
    assert!(err(&["--wat", "x"]).contains("unknown option --wat"));
    assert!(err(&[]).contains("grep needs a pattern"));
    assert!(err(&["-n"]).contains("grep needs a pattern"));
    assert!(err(&[""]).contains("the pattern is empty"));
    assert_eq!(err(&["-P", "x"]), "quarry: -P is not supported (Rust regex syntax only)");
    assert_eq!(err(&["-nP", "x"]), "quarry: -P is not supported (Rust regex syntax only)");
    assert_eq!(err(&["--perl-regexp", "x"]), "quarry: -P is not supported (Rust regex syntax only)");
    assert!(err(&["-A", "x", "p"]).contains("-A needs a number"));
    assert!(err(&["-m", "-1", "p"]).contains("-m needs a number"));
    assert!(err(&["p", "-C"]).contains("-C needs a number"));
    assert!(err(&["p", "-g"]).contains("-g needs a glob"));
    assert!(err(&["p", "--repo"]).contains("--repo needs a folder"));
}

#[test]
fn a_bad_regex_is_an_error_and_lookaround_is_not_supported() {
    for bad in ["(", "[a-", "(?<=x)y", r"(a)\1", "a{2,1}"] {
        let o = parse(args(&[bad])).unwrap();
        let err = compile(&o).unwrap_err();
        assert!(err.starts_with("quarry: bad pattern: "), "{bad}: {err}");
    }
    let o = parse(args(&["-F", "(?<=x)y("])).unwrap();
    assert!(compile(&o).is_ok());
}

#[test]
fn a_pattern_that_would_compile_to_a_huge_program_is_refused_not_hung() {
    let o = parse(args(&["((a{100}){100}){100}"])).unwrap();
    assert!(compile(&o).is_err());
}

// ---- globs ----

fn allows(globs: &[&str], path: &str) -> bool {
    Globs::new(&globs.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap().allows(path)
}

#[test]
fn globs_without_a_slash_match_any_part_of_the_path() {
    assert!(allows(&["*.ts"], "src/a/b.ts"));
    assert!(allows(&["*.ts"], "b.ts"));
    assert!(!allows(&["*.ts"], "b.tsx"));
    assert!(!allows(&["*.ts"], "src/b.rs"));
    assert!(allows(&["dist"], "dist/a.js") && allows(&["dist"], "x/dist/a.js") && !allows(&["dist"], "distant/a.js"));
    assert!(allows(&["*.{ts,tsx}"], "a.tsx") && allows(&["*.{ts,tsx}"], "a.ts") && !allows(&["*.{ts,tsx}"], "a.js"));
    assert!(allows(&["file?.rs"], "file1.rs") && !allows(&["file?.rs"], "file12.rs"));
    assert!(allows(&["[ab].rs"], "a.rs") && !allows(&["[ab].rs"], "c.rs") && allows(&["[!ab].rs"], "c.rs"));
}

#[test]
fn globs_with_a_slash_match_from_the_search_folder() {
    assert!(allows(&["src/*.ts"], "src/a.ts"));
    assert!(!allows(&["src/*.ts"], "src/x/a.ts"));
    assert!(allows(&["src/**/*.ts"], "src/x/y/a.ts") && allows(&["src/**/*.ts"], "src/a.ts"));
    assert!(allows(&["src/api"], "src/api/a.ts") && allows(&["src/api/"], "src/api/a.ts"));
    assert!(!allows(&["src/api"], "lib/src/api/a.ts") && !allows(&["src/api"], "src/apix/a.ts"));
    assert!(allows(&["/src"], "src/a.ts") && !allows(&["/src"], "x/src/a.ts"));
    assert!(allows(&["**/test/*.ts"], "a/b/test/x.ts") && allows(&["**/test/*.ts"], "test/x.ts"));
}

#[test]
fn a_bang_excludes_and_excludes_beat_includes() {
    assert!(allows(&[], "anything"));
    assert!(!allows(&["!*.test.ts"], "a.test.ts") && allows(&["!*.test.ts"], "a.ts"));
    assert!(allows(&["*.ts", "!*.test.ts"], "a.ts") && !allows(&["*.ts", "!*.test.ts"], "a.test.ts"));
    assert!(allows(&["*.ts", "*.rs"], "a.rs") && !allows(&["*.ts", "*.rs"], "a.md"));
    assert!(!allows(&["!dist", "*.js"], "dist/a.js"));
}

#[test]
fn a_bad_glob_is_an_error() {
    assert!(Globs::new(&["*.{ts".into()]).is_err());
    assert!(Globs::new(&["[".into()]).is_ok(), "an unclosed [ is a literal one");
    assert!(allows(&["a.b"], "a.b") && !allows(&["a.b"], "axb"), "dots are literal");
    assert!(allows(&["a+b(c)"], "a+b(c)"), "regex characters are literal");
}

// ---- notes ----

#[test]
fn stderr_notes_match_the_mockup() {
    let one = |s: &str| vec![s.to_string()];
    assert_eq!(
        notes(&one(".env.local"), &[], &[], 2),
        ["quarry: withheld 1 file (sensitive: .env.local)", "quarry: 2 files had redactions; matches inside them can't show"]
    );
    assert_eq!(notes(&[], &[], &[], 1), ["quarry: 1 file had redactions; matches inside it can't show"]);
    assert!(notes(&[], &[], &[], 0).is_empty());
    assert_eq!(notes(&[], &one("a.rs"), &[], 0), ["quarry: withheld 1 file (redaction failed: a.rs)"]);
    assert_eq!(notes(&[], &[], &one("vendor/lib"), 0), ["quarry: 1 submodule not searched (vendor/lib)"]);
    let many: Vec<String> = (0..8).map(|i| format!("k{i}.pem")).collect();
    assert_eq!(
        notes(&many, &one("b"), &[], 0),
        ["quarry: withheld 9 files (sensitive: k0.pem, k1.pem, k2.pem, k3.pem, k4.pem, +3 more; redaction failed: b)"]
    );
}

// ---- the property: no secret comes back out ----

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn string(&mut self, alphabet: &str, len: usize) -> String {
        let chars: Vec<char> = alphabet.chars().collect();
        (0..len).map(|_| chars[self.below(chars.len())]).collect()
    }
}

const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const UPPER_DIGITS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE64URL: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
const WORDS: &[&str] = &[
    "let", "fn", "return", "value", "config", "retry", "handler", "build", "request", "queue", "total", "items", "user",
    "state", "load", "write", "parse", "frame", "match", "stream",
];

/// A secret, and a source line that holds it, of a random kind.
fn fake_secret(rng: &mut Rng) -> (String, String) {
    match rng.below(8) {
        0 => {
            let t = format!("{}{}", ["gh", "p_"].concat(), rng.string(ALNUM, 36));
            (t.clone(), format!("let gh = \"{t}\";"))
        }
        1 => {
            let t = format!("{}{}", ["AK", "IA"].concat(), rng.string(UPPER_DIGITS, 16));
            (t.clone(), format!("aws_id = \"{t}\""))
        }
        2 => {
            let t = format!("{}{}", ["sk", "_live_"].concat(), rng.string(ALNUM, 24));
            (t.clone(), format!("stripe: \"{t}\","))
        }
        3 => {
            let t = format!("eyJ{}.eyJ{}.{}", rng.string(BASE64URL, 17), rng.string(BASE64URL, 30), rng.string(BASE64URL, 43));
            (t.clone(), format!("const jwt = '{t}'"))
        }
        4 => {
            let pw = format!("{}{}", rng.string("abcdefghijklmnopqrstuvwxyz", 8), rng.string("0123456789", 2));
            (pw.clone(), format!("dsn = \"postgres://admin:{pw}@db.example.com/app\""))
        }
        5 => {
            let pw = rng.string("abcdefghijklmnopqrstuvwxyz0123456789", 11);
            (pw.clone(), format!("password = \"{pw}\""))
        }
        6 => {
            let pw = rng.string("abcdefghijklmnopqrstuvwxyz0123456789", 12);
            (pw.clone(), format!("api_key = '{pw}'"))
        }
        _ => {
            let body = rng.string(ALNUM, 40);
            let k = ["PRIVATE", " KEY"].concat();
            (body.clone(), format!("-----BEGIN {k}-----\n{body}\n-----END {k}-----"))
        }
    }
}

/// Random code-like lines with a few secrets among them. Returns the text and its secrets.
fn random_file(rng: &mut Rng) -> (String, Vec<String>) {
    let mut lines: Vec<String> = (0..5 + rng.below(40))
        .map(|_| (0..1 + rng.below(8)).map(|_| WORDS[rng.below(WORDS.len())]).collect::<Vec<_>>().join(" "))
        .collect();
    let mut secrets = Vec::new();
    for _ in 0..1 + rng.below(4) {
        let (secret, line) = fake_secret(rng);
        lines.insert(rng.below(lines.len() + 1), line);
        secrets.push(secret);
    }
    (lines.join("\n") + "\n", secrets)
}

/// Every way to ask for one secret: whole, or a piece; plain, escaped, upper or lower case.
fn probes(rng: &mut Rng, secret: &str) -> Vec<(Vec<&'static str>, String)> {
    let chars: Vec<char> = secret.chars().collect();
    let len = 6 + rng.below(chars.len() - 5);
    let from = rng.below(chars.len() - len + 1);
    let piece: String = chars[from..from + len].iter().collect();
    let mut out = Vec::new();
    for text in [secret.to_string(), piece] {
        out.push((vec!["-F"], text.clone()));
        out.push((vec![], regex::escape(&text)));
        out.push((vec!["-F", "-i"], text.to_uppercase()));
        out.push((vec!["-F", "-i"], text.to_lowercase()));
        out.push((vec!["-w", "-F"], text.clone()));
        out.push((vec!["-F", "-C", "3"], text.clone()));
    }
    out
}

/// The same pattern in another mode, without compiling it again (compiling dominates this loop).
fn in_mode(m: &Matcher, mode: Mode) -> Matcher {
    Matcher { re: m.re.clone(), after: m.after, before: m.before, mode, max: m.max }
}

#[test]
fn grepping_a_secrets_value_finds_nothing_in_any_mode() {
    let generic: Vec<(Options, Matcher)> = [".*", r"\w{12,}", "[A-Za-z0-9_]{20,}", ".", "^", r"\S+", "=", "[\"']"]
        .iter()
        .flat_map(|p| [&["-C", "2"][..], &["-A", "1"], &[]].into_iter().map(move |f| matcher(f, p)))
        .collect();
    let mut withheld = 0;
    for seed in 1..=1000u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let (text, secrets) = random_file(&mut rng);
        let Some(clean) = redact::clean(&text) else {
            withheld += 1;
            continue;
        };
        for s in &secrets {
            assert!(!clean.contains(s.as_str()), "seed {seed}: the redactor left {s} in {clean:?}");
        }
        for secret in &secrets {
            // Five of the twelve ways to ask, different each seed.
            let mut all = probes(&mut rng, secret);
            while all.len() > 5 {
                all.swap_remove(rng.below(all.len()));
            }
            for (flags, pattern) in all {
                let (_, lines) = matcher(&flags, &pattern);
                for mode in [Mode::Lines, Mode::Files, Mode::Counts] {
                    let hits = search_text("f.txt", &clean, &in_mode(&lines, mode));
                    assert_eq!(hits.count, 0, "seed {seed}: {flags:?} {pattern:?} {mode:?} matched in {clean:?}");
                    assert!(hits.lines.is_empty());
                }
            }
        }
        // Patterns that match plenty still print only clean text.
        for (o, m) in &generic {
            let out = render(&[("f.txt".into(), search_text("f.txt", &clean, m))], o.mode, o.after > 0 || o.before > 0);
            for s in &secrets {
                assert!(!out.contains(s.as_str()), "seed {seed}: {:?} printed {s}", o.pattern);
            }
        }
    }
    assert!(withheld < 100, "{withheld} of 1000 files were withheld; the loop would prove little");
}

#[test]
fn the_loop_would_notice_a_leak() {
    // The same probe against text that was not redacted must find the secret, or it proves nothing.
    let mut rng = Rng(7);
    let (text, secrets) = random_file(&mut rng);
    let (_, m) = matcher(&["-F"], &secrets[0]);
    assert_eq!(search_text("f.txt", &text, &m).count, 1);
}
