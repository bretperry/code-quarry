//! `quarry grep`: exact-text search over the same redacted text `quarry search` shows.
//!
//! Nothing here sees raw text. Every file goes through `index::read_clean`, the matcher takes the
//! cleaned text, and every mode (`-l`, `-c`, the exit code) derives from matches in that text. No
//! prefilter may look at the raw file: a match on raw text would tell the reader what a secret holds.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

use regex::{Regex, RegexBuilder};

use crate::index::{self, Refused};
use crate::redact;

/// Output past this many characters is cut, with a count of what was left out.
pub const MAX_OUTPUT_CHARS: usize = 20_000;
/// A longer line is cut to this many characters.
pub const MAX_LINE_CHARS: usize = 300;
/// Files are searched on this many threads at most.
const MAX_THREADS: usize = 8;
/// Names listed on one stderr line before "+N more".
const MAX_NAMES_LISTED: usize = 5;

#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum Mode {
    #[default]
    Lines,
    /// `-l`: paths with at least one match.
    Files,
    /// `-c`: `path:count` for paths with at least one match.
    Counts,
}

#[derive(Default, Debug)]
pub struct Options {
    pub pattern: String,
    pub paths: Vec<String>,
    pub fixed: bool,
    pub ignore_case: bool,
    pub word: bool,
    pub after: usize,
    pub before: usize,
    pub mode: Mode,
    pub max_per_file: Option<usize>,
    pub globs: Vec<String>,
    pub no_ignore: bool,
    pub repo: Option<PathBuf>,
}

fn misuse(what: &str) -> String {
    format!("quarry: {what}\nRun `quarry help grep` for how to use it.")
}

const NO_PERL: &str = "quarry: -P is not supported (Rust regex syntax only)";

/// grep flags quarry does not take, with what to do instead. The CLI is fixed, so these are errors
/// that say how to get the same result.
fn unsupported(flag: &str) -> Option<String> {
    let why = match flag {
        "r" | "R" | "recursive" | "dereference-recursive" => "is not needed (search is always recursive); drop it",
        "E" | "extended-regexp" => "is not needed (patterns are already extended regex); drop it",
        "e" | "regexp" => "is not supported; pass the pattern as the first argument (after -- if it starts with -)",
        "o" | "only-matching" => "is not supported; matching lines print whole",
        "v" | "invert-match" => "is not supported; quarry grep prints only matching lines",
        _ => return None,
    };
    let dash = if flag.len() == 1 { "-" } else { "--" };
    Some(format!("quarry: {dash}{flag} {why}"))
}

/// Reads the arguments after `quarry grep`.
pub fn parse(args: Vec<String>) -> Result<Options, String> {
    let mut o = Options::default();
    let mut positional: Vec<String> = Vec::new();
    let (mut context, mut after, mut before) = (None, None, None);
    let mut args = args.into_iter();
    let mut only_positional = false;
    let number = |v: &str, flag: &str| v.parse::<usize>().map_err(|_| misuse(&format!("{flag} needs a number")));
    while let Some(a) = args.next() {
        if only_positional || a == "-" || !a.starts_with('-') {
            positional.push(a);
        } else if a == "--" {
            only_positional = true;
        } else if let Some(long) = a.strip_prefix("--") {
            match long {
                "no-ignore" => o.no_ignore = true,
                "repo" => o.repo = Some(PathBuf::from(args.next().ok_or_else(|| misuse("--repo needs a folder"))?)),
                "perl-regexp" => return Err(NO_PERL.into()),
                _ => return Err(unsupported(long).unwrap_or_else(|| misuse(&format!("unknown option --{long}")))),
            }
        } else {
            let cluster: Vec<char> = a[1..].chars().collect();
            let mut i = 0;
            while i < cluster.len() {
                let c = cluster[i];
                i += 1;
                match c {
                    // Line numbers are always shown, so -n changes nothing.
                    'n' => {}
                    'F' => o.fixed = true,
                    'i' => o.ignore_case = true,
                    'w' => o.word = true,
                    'l' => o.mode = Mode::Files,
                    'c' if o.mode == Mode::Lines => o.mode = Mode::Counts,
                    'c' => {}
                    'P' => return Err(NO_PERL.into()),
                    'A' | 'B' | 'C' | 'm' | 'g' => {
                        let rest: String = cluster[i..].iter().collect();
                        let value = if rest.is_empty() {
                            args.next().ok_or_else(|| misuse(&format!("-{c} needs {}", if c == 'g' { "a glob" } else { "a number" })))?
                        } else {
                            rest
                        };
                        let flag = format!("-{c}");
                        match c {
                            'A' => after = Some(number(&value, &flag)?),
                            'B' => before = Some(number(&value, &flag)?),
                            'C' => context = Some(number(&value, &flag)?),
                            'm' => o.max_per_file = Some(number(&value, &flag)?),
                            _ => o.globs.push(value),
                        }
                        break;
                    }
                    _ => return Err(unsupported(&c.to_string()).unwrap_or_else(|| misuse(&format!("unknown option -{c}")))),
                }
            }
        }
    }
    o.after = after.or(context).unwrap_or(0);
    o.before = before.or(context).unwrap_or(0);
    let mut positional = positional.into_iter();
    o.pattern = positional.next().ok_or_else(|| misuse("grep needs a pattern, like: quarry grep -n \"TODO\""))?;
    if o.pattern.is_empty() {
        return Err(misuse("the pattern is empty"));
    }
    o.paths = positional.collect();
    Ok(o)
}

/// The pattern as a regex. `-w` needs a non-word character (or the line's edge) on both sides.
pub fn compile(o: &Options) -> Result<Regex, String> {
    let body = if o.fixed { regex::escape(&o.pattern) } else { o.pattern.clone() };
    let source = if o.word { format!(r"(?:^|\W)(?:{body})(?:\W|$)") } else { body };
    RegexBuilder::new(&source).case_insensitive(o.ignore_case).build().map_err(|e| {
        // The message quotes the pattern; run it through the redactor like every other output.
        let text = redact::clean(&e.to_string()).unwrap_or_else(|| "invalid pattern".into());
        misuse(&format!("bad pattern: {text}"))
    })
}

/// One printed line of a file's result.
#[derive(Debug)]
pub struct Line {
    pub text: String,
    pub is_match: bool,
    /// Not directly after the previous printed line, so `--` goes between them.
    pub gap_before: bool,
}

#[derive(Default, Debug)]
pub struct FileHits {
    /// Matching lines, after `-m`.
    pub count: usize,
    /// Matches and their context, up to about one output's worth. Empty outside `Mode::Lines`.
    pub lines: Vec<Line>,
}

pub struct Matcher {
    pub re: Regex,
    pub after: usize,
    pub before: usize,
    pub mode: Mode,
    pub max: Option<usize>,
}

impl Matcher {
    pub fn new(o: &Options) -> Result<Matcher, String> {
        Ok(Matcher { re: compile(o)?, after: o.after, before: o.before, mode: o.mode, max: o.max_per_file })
    }
}

fn cut_line(text: &str) -> String {
    match text.char_indices().nth(MAX_LINE_CHARS) {
        Some((end, _)) => format!("{}... [cut]", &text[..end]),
        None => text.to_string(),
    }
}

/// Searches one file's clean text. Pure: no files, no raw text.
#[cfg(test)]
pub fn search_text(path: &str, clean: &str, m: &Matcher) -> FileHits {
    search_text_with(path, clean, m, true)
}

/// `search_text`, keeping the printed lines only when `store` is set. Without it, only counts.
fn search_text_with(path: &str, clean: &str, m: &Matcher, store: bool) -> FileHits {
    let lines: Vec<&str> = clean.lines().collect();
    let limit = m.max.unwrap_or(usize::MAX);
    let mut matched: Vec<usize> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if matched.len() >= limit {
            break;
        }
        if m.re.is_match(line) {
            matched.push(i);
            if m.mode == Mode::Files {
                break;
            }
        }
    }
    let mut hits = FileHits { count: matched.len(), lines: Vec::new() };
    if m.mode != Mode::Lines || matched.is_empty() || !store {
        return hits;
    }
    let mut is_match = vec![false; lines.len()];
    for &i in &matched {
        is_match[i] = true;
    }
    let (mut printed_to, mut last, mut stored) = (0usize, None::<usize>, 0usize);
    for &i in &matched {
        let start = i.saturating_sub(m.before).max(printed_to);
        let end = i.saturating_add(m.after).saturating_add(1).min(lines.len());
        for j in start..end {
            let sep = if is_match[j] { ':' } else { '-' };
            let text = format!("{path}{sep}{}{sep}{}", j + 1, cut_line(lines[j]));
            stored += text.chars().count() + 1;
            hits.lines.push(Line { text, is_match: is_match[j], gap_before: last != Some(j.wrapping_sub(1)) });
            last = Some(j);
            // No later file can use more than one output's worth of this file.
            if stored > MAX_OUTPUT_CHARS {
                return hits;
            }
        }
        printed_to = end.max(printed_to);
    }
    hits
}

/// The characters `lines` add to output that already holds `used`, as `render` counts them.
fn cost(lines: &[Line], context: bool, mut used: usize) -> usize {
    let start = used;
    for line in lines {
        let gap = context && line.gap_before && used > 0;
        used += line.text.chars().count() + 1 + if gap { 3 } else { 0 };
    }
    used - start
}

/// Turns the files' results (paths in order, matching files only) into stdout.
pub fn render(results: &[(String, FileHits)], mode: Mode, context: bool) -> String {
    let (mut out, mut chars, mut shown) = (String::new(), 0usize, 0usize);
    let total: usize = if mode == Mode::Lines { results.iter().map(|(_, h)| h.count).sum() } else { results.len() };
    let mut cut = false;
    'all: for (path, hits) in results {
        let own;
        let lines: &[Line] = match mode {
            Mode::Lines => &hits.lines,
            Mode::Files => {
                own = [Line { text: path.clone(), is_match: true, gap_before: false }];
                &own
            }
            Mode::Counts => {
                own = [Line { text: format!("{path}:{}", hits.count), is_match: true, gap_before: false }];
                &own
            }
        };
        // Lines left out to save memory: output was already full before this file.
        if mode == Mode::Lines && hits.count > 0 && lines.is_empty() {
            cut = true;
            break;
        }
        for line in lines {
            let gap = context && mode == Mode::Lines && line.gap_before && !out.is_empty();
            let cost = line.text.chars().count() + 1 + if gap { 3 } else { 0 };
            if chars + cost > MAX_OUTPUT_CHARS {
                cut = true;
                break 'all;
            }
            if gap {
                out.push_str("--\n");
            }
            out.push_str(&line.text);
            out.push('\n');
            chars += cost;
            shown += usize::from(line.is_match);
        }
    }
    let left = total.saturating_sub(shown);
    // A cut that drops only context lines still says so, with 0 more matches.
    if cut {
        let (one, many) = if mode == Mode::Lines { ("match", "matches") } else { ("file", "files") };
        out.push_str(&format!(
            "... [cut: {left} more {}. Narrow the pattern or add -g]\n",
            if left == 1 { one } else { many }
        ));
    }
    out
}

// ---- -g globs ----

/// A `-g` glob. One without a `/` matches any one part of the path (`*.ts`, `dist`); one with a `/`
/// matches the path from the search folder, or a folder along it.
pub struct Glob {
    re: Regex,
    anchored: bool,
}

/// `*` stays in one folder, `**` crosses folders, `?` is one character, `[a-z]` and `{a,b}` work.
fn glob_to_regex(glob: &str) -> Result<String, String> {
    let chars: Vec<char> = glob.chars().collect();
    let (mut out, mut i, mut depth) = (String::from("^"), 0, 0usize);
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        match c {
            '*' if chars.get(i) == Some(&'*') => {
                i += 1;
                if chars.get(i) == Some(&'/') {
                    i += 1;
                    out.push_str("(?:.*/)?");
                } else {
                    out.push_str(".*");
                }
            }
            '*' => out.push_str("[^/]*"),
            '?' => out.push_str("[^/]"),
            '[' => {
                let Some(close) = chars[i..].iter().position(|c| *c == ']').map(|p| i + p).filter(|p| *p > i) else {
                    out.push_str("\\[");
                    continue;
                };
                out.push('[');
                let mut body = &chars[i..close];
                if matches!(body.first(), Some('!' | '^')) {
                    out.push('^');
                    body = &body[1..];
                }
                for b in body {
                    if matches!(b, '\\' | '[' | ']' | '&' | '~') {
                        out.push('\\');
                    }
                    out.push(*b);
                }
                out.push(']');
                i = close + 1;
            }
            '{' => {
                depth += 1;
                out.push_str("(?:");
            }
            ',' if depth > 0 => out.push('|'),
            '}' if depth > 0 => {
                depth -= 1;
                out.push(')');
            }
            c => out.push_str(&regex::escape(&c.to_string())),
        }
    }
    if depth > 0 {
        return Err("unclosed {".into());
    }
    out.push('$');
    Ok(out)
}

pub fn parse_glob(glob: &str) -> Result<Glob, String> {
    let bad = |why: String| misuse(&format!("bad glob \"{glob}\": {why}"));
    let trimmed = glob.trim_end_matches('/');
    let anchored = trimmed.contains('/');
    let source = glob_to_regex(trimmed.trim_start_matches('/')).map_err(bad)?;
    let re = Regex::new(&source).map_err(|e| bad(e.to_string()))?;
    Ok(Glob { re, anchored })
}

impl Glob {
    pub fn matches(&self, rel: &str) -> bool {
        if !self.anchored {
            return rel.split('/').any(|part| self.re.is_match(part));
        }
        // The whole path, or a folder along it.
        let mut end = 0;
        for part in rel.split('/') {
            end += part.len();
            if self.re.is_match(&rel[..end]) {
                return true;
            }
            end += 1;
        }
        false
    }
}

pub struct Globs {
    include: Vec<Glob>,
    exclude: Vec<Glob>,
}

impl Globs {
    pub fn new(globs: &[String]) -> Result<Globs, String> {
        let (mut include, mut exclude) = (Vec::new(), Vec::new());
        for g in globs {
            match g.strip_prefix('!') {
                Some(rest) => exclude.push(parse_glob(rest)?),
                None => include.push(parse_glob(g)?),
            }
        }
        Ok(Globs { include, exclude })
    }

    pub fn allows(&self, rel: &str) -> bool {
        (self.include.is_empty() || self.include.iter().any(|g| g.matches(rel))) && !self.exclude.iter().any(|g| g.matches(rel))
    }
}

// ---- finding files ----

/// Folders never entered: git's own, and quarry's index.
fn always_skipped(name: &str) -> bool {
    name == ".git" || name == ".quarry"
}

/// A path as git writes it, with `/` between parts.
fn slashed(path: &Path) -> String {
    let text = path.to_string_lossy().into_owned();
    if cfg!(windows) { text.replace('\\', "/") } else { text }
}

/// Every file under `start`, as paths relative to `root`. Symlinks are not followed. Below `start`,
/// `skip_dot_dirs` leaves out folders whose names begin with a dot.
fn walk(start: &Path, root: &Path, skip_dot_dirs: bool, out: &mut Vec<String>) {
    let Ok(meta) = fs::symlink_metadata(start) else { return };
    if meta.is_file() {
        if let Ok(rel) = start.strip_prefix(root) {
            out.push(slashed(rel));
        }
        return;
    }
    let Ok(entries) = fs::read_dir(start) else { return };
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        if kind.is_dir() {
            if !always_skipped(&name) && !(skip_dot_dirs && name.starts_with('.')) {
                walk(&entry.path(), root, skip_dot_dirs, out);
            }
        } else if kind.is_file() {
            out.extend(entry.path().strip_prefix(root).ok().map(slashed));
        }
    }
}

/// Tracked and untracked-but-not-ignored files under `root`, if it is in a git repo.
fn git_files(root: &Path) -> Option<Vec<String>> {
    let out = Command::new("git").arg("-C").arg(root).args(["ls-files", "-co", "--exclude-standard", "-z"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim_end_matches('/').to_string())
            .collect(),
    )
}

/// The files to search, sorted, once each. `targets` are paths relative to `root`; none means all.
pub fn list_files(root: &Path, targets: &[String], no_ignore: bool) -> Vec<String> {
    let mut files = Vec::new();
    match if no_ignore { None } else { git_files(root) } {
        Some(all) => files = all,
        None if targets.is_empty() => walk(root, root, !no_ignore, &mut files),
        None => {
            for t in targets {
                walk(&root.join(t), root, !no_ignore, &mut files);
            }
        }
    }
    // A file named on the command line is searched even when git ignores it.
    files.extend(targets.iter().filter(|t| !t.is_empty() && fs::symlink_metadata(root.join(t)).is_ok_and(|m| m.is_file())).cloned());
    if !targets.is_empty() {
        files.retain(|f| targets.iter().any(|t| t.is_empty() || f == t || f.strip_prefix(t.as_str()).is_some_and(|r| r.starts_with('/'))));
    }
    // `.git` and the index are never searched, even when named: `quarry grep x .git`.
    files.retain(|f| !f.split('/').any(always_skipped));
    files.sort();
    files.dedup();
    files
}

// ---- running ----

enum Outcome {
    Searched { hits: FileHits, redacted: bool },
    Sensitive,
    Failed,
    NotText,
    Submodule,
    Skipped,
}

fn process(root: &Path, rel: &str, m: &Matcher, store: bool) -> Outcome {
    match index::read_clean(root, rel) {
        Ok(source) => {
            Outcome::Searched { hits: search_text_with(&display_path(rel), &source.clean, m, store), redacted: source.is_redacted() }
        }
        Err(Refused::Sensitive) => Outcome::Sensitive,
        Err(Refused::Withheld) => Outcome::Failed,
        Err(Refused::NotText) => Outcome::NotText,
        // A folder in the file list is a submodule or a nested repo; git lists it as one entry.
        Err(Refused::Unreadable) if fs::symlink_metadata(root.join(rel)).is_ok_and(|m| m.is_dir()) => Outcome::Submodule,
        Err(Refused::Unreadable) => Outcome::Skipped,
    }
}

/// Results gathered in file order, so output memory stays near one output's worth.
struct Collector {
    slots: Vec<Option<Outcome>>,
    /// Every slot before this is filled and counted against `used`.
    frontier: usize,
    /// Characters the results before `frontier` add to output.
    used: usize,
}

impl Collector {
    /// Files past this point only need counts: the output before them is already full.
    fn full(&self) -> bool {
        self.used > MAX_OUTPUT_CHARS
    }

    fn put(&mut self, i: usize, mut outcome: Outcome, context: bool) {
        if self.full()
            && let Outcome::Searched { hits, .. } = &mut outcome
        {
            hits.lines = Vec::new();
        }
        self.slots[i] = Some(outcome);
        let was_full = self.full();
        while let Some(Some(outcome)) = self.slots.get_mut(self.frontier) {
            if let Outcome::Searched { hits, .. } = outcome {
                if self.used > MAX_OUTPUT_CHARS {
                    hits.lines = Vec::new();
                } else {
                    self.used += cost(&hits.lines, context, self.used);
                }
            }
            self.frontier += 1;
        }
        if self.full() && !was_full {
            for outcome in self.slots[self.frontier..].iter_mut().flatten() {
                if let Outcome::Searched { hits, .. } = outcome {
                    hits.lines = Vec::new();
                }
            }
        }
    }
}

/// Searches every file on a few threads. Outcomes come back in file order. Once the output in file
/// order is full, later files are only counted.
fn search_all(root: &Path, files: &[String], m: &Matcher, context: bool) -> Result<Vec<Outcome>, String> {
    let threads = thread::available_parallelism().map_or(4, |n| n.get()).clamp(1, MAX_THREADS).min(files.len().max(1));
    let next = AtomicUsize::new(0);
    let full = AtomicBool::new(false);
    let mut slots: Vec<Option<Outcome>> = Vec::new();
    slots.resize_with(files.len(), || None);
    let collector = Mutex::new(Collector { slots, frontier: 0, used: 0 });
    let failed = thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(rel) = files.get(i) else { break };
                        let outcome = process(root, rel, m, !full.load(Ordering::Relaxed));
                        let Ok(mut c) = collector.lock() else { break };
                        c.put(i, outcome, context);
                        if c.full() {
                            full.store(true, Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();
        workers.into_iter().map(|w| w.join()).any(|r| r.is_err())
    });
    let collector = collector.into_inner().map_err(|_| "quarry: internal error".to_string())?;
    if failed || collector.slots.iter().any(Option::is_none) {
        return Err("quarry: internal error".into());
    }
    Ok(collector.slots.into_iter().flatten().collect())
}

/// A path with control characters written out (`\n`, `\t`, `\x1b`), so a file name can't start a
/// new output line or move the cursor.
pub fn display_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn shown_name(path: &str) -> String {
    display_path(&redact::clean(path).unwrap_or_else(|| redact::MARK.into()))
}

fn names(paths: &[String]) -> String {
    let mut listed: Vec<String> = paths.iter().take(MAX_NAMES_LISTED).map(|p| shown_name(p)).collect();
    if paths.len() > MAX_NAMES_LISTED {
        listed.push(format!("+{} more", paths.len() - MAX_NAMES_LISTED));
    }
    listed.join(", ")
}

fn plural(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

/// The stderr notes. None of them depends on the pattern, so they tell the reader nothing about
/// what a secret holds.
fn notes(sensitive: &[String], failed: &[String], not_text: &[String], submodules: &[String], redacted: usize) -> Vec<String> {
    let mut out = Vec::new();
    let withheld = sensitive.len() + failed.len();
    if withheld > 0 {
        let mut why = Vec::new();
        if !sensitive.is_empty() {
            why.push(format!("sensitive: {}", names(sensitive)));
        }
        if !failed.is_empty() {
            why.push(format!("redaction failed: {}", names(failed)));
        }
        out.push(format!("quarry: withheld {} ({})", plural(withheld, "file"), why.join("; ")));
    }
    if !not_text.is_empty() {
        out.push(format!("quarry: skipped {} (over 500 KB or not UTF-8: {})", plural(not_text.len(), "file"), names(not_text)));
    }
    if !submodules.is_empty() {
        out.push(format!("quarry: {} not searched ({})", plural(submodules.len(), "submodule"), names(submodules)));
    }
    if redacted > 0 {
        let them = if redacted == 1 { "it" } else { "them" };
        out.push(format!("quarry: {} had redactions; matches inside {them} can't show", plural(redacted, "file")));
    }
    out
}

/// Resolves a path argument to a path relative to `root`.
fn relative_target(root: &Path, arg: &str) -> Result<String, String> {
    let full = root.join(arg);
    let real = full.canonicalize().map_err(|_| format!("quarry: no such file or folder: {}", shown_name(arg)))?;
    let rel = real.strip_prefix(root).map_err(|_| format!("quarry: {} is outside {}", shown_name(arg), shown_name(&root.to_string_lossy())))?;
    Ok(slashed(rel))
}

/// Runs `quarry grep`. Returns the exit code: 0 for a match, 1 for none.
pub fn run(args: Vec<String>) -> Result<i32, String> {
    let o = parse(args)?;
    let matcher = Matcher::new(&o)?;
    let globs = Globs::new(&o.globs)?;
    let start = match &o.repo {
        Some(p) => p.clone(),
        None => std::env::current_dir().map_err(|e| format!("quarry: {e}"))?,
    };
    let root = start.canonicalize().ok().filter(|p| p.is_dir()).ok_or_else(|| format!("quarry: no such folder: {}", shown_name(&start.to_string_lossy())))?;
    let targets = o.paths.iter().map(|p| relative_target(&root, p)).collect::<Result<Vec<_>, _>>()?;

    let files: Vec<String> = list_files(&root, &targets, o.no_ignore).into_iter().filter(|f| globs.allows(f)).collect();
    let context = o.after > 0 || o.before > 0;
    let outcomes = search_all(&root, &files, &matcher, context)?;

    let (mut sensitive, mut failed, mut not_text, mut submodules) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let (mut redacted, mut results) = (0, Vec::new());
    for (rel, outcome) in files.into_iter().zip(outcomes) {
        match outcome {
            Outcome::Searched { hits, redacted: r } => {
                redacted += usize::from(r);
                if hits.count > 0 {
                    results.push((display_path(&rel), hits));
                }
            }
            Outcome::Sensitive => sensitive.push(rel),
            Outcome::Failed => failed.push(rel),
            Outcome::NotText => not_text.push(rel),
            Outcome::Submodule => submodules.push(rel),
            Outcome::Skipped => {}
        }
    }
    let out = render(&results, o.mode, context);
    if !out.is_empty() {
        crate::emit(&out);
    }
    for note in notes(&sensitive, &failed, &not_text, &submodules, redacted) {
        eprintln!("{note}");
    }
    Ok(if results.is_empty() { 1 } else { 0 })
}

#[cfg(test)]
#[path = "grep_tests.rs"]
mod tests;
