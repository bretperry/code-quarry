use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::chunk::{self, first_chars};
use crate::store::{ChunkEntry, FileEntry, Index, KINDS};
use crate::{embed, redact, store, terms};

const SKIP_DIRS: &[&str] = &[
    ".git", ".code-scry", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", "target", "vendor",
];
pub const MAX_FILE_BYTES: u64 = 500_000;
const MAX_EMBED_CHARS: usize = 2000;
/// How much a chunk's path and symbol count against its body.
const HEAD_VECTOR_WEIGHT: f32 = 3.0;
const HEAD_TERM_WEIGHT: u32 = 8;

fn walk(dir: &Path, repo: &Path, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else { continue };
        let path = entry.path();
        if kind.is_dir() {
            if !SKIP_DIRS.contains(&entry.file_name().to_string_lossy().as_ref()) {
                walk(&path, repo, out);
            }
        } else if kind.is_file() {
            if let Ok(rel) = path.strip_prefix(repo) {
                out.push(rel.to_string_lossy().into_owned());
            }
        }
    }
}

fn list_files(repo: &Path) -> Vec<String> {
    let git = Command::new("git").arg("-C").arg(repo).args(["ls-files", "-z"]).output();
    if let Ok(out) = git {
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout)
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
        }
    }
    let mut out = Vec::new();
    walk(repo, repo, &mut out);
    out
}

pub fn fnv64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8423_2325, |h, b| (h ^ *b as u64).wrapping_mul(0x0000_0100_0000_01b3))
}

/// A file that passed `read_clean`. `raw` is for parsing only and must never be stored or printed.
pub struct Source {
    raw: String,
    pub clean: String,
}

impl Source {
    /// Chunks found by parsing the raw text, since redaction can upset the syntax, with their text
    /// and symbols taken from the clean side. Line numbers match on both sides.
    pub fn chunks(&self, language: &tree_sitter::Language, filename: &str) -> Vec<chunk::Chunk> {
        self.chunks_and_calls(language, filename).0
    }

    /// `chunks`, plus the calls in the file as (line, called name). A call is kept only when its
    /// line is the same before and after redaction, so every name comes from clean text.
    pub fn chunks_and_calls(&self, language: &tree_sitter::Language, filename: &str) -> (Vec<chunk::Chunk>, Vec<(u32, String)>) {
        let lines: Vec<&str> = self.clean.lines().collect();
        let raw_lines: Vec<&str> = self.raw.lines().collect();
        let (chunks, calls) = chunk::chunks_and_calls(self.raw.as_bytes(), language, filename);
        let calls = calls
            .into_iter()
            .filter(|(l, _)| {
                let i = *l as usize - 1;
                i < lines.len() && raw_lines.get(i) == lines.get(i)
            })
            .collect();
        let chunks = chunks
            .into_iter()
            .filter_map(|mut c| {
                c.symbol = redact::clean(&c.symbol)?;
                let start = (c.start_line as usize).saturating_sub(1).min(lines.len());
                let end = (c.end_line as usize).min(lines.len()).max(start);
                c.content = first_chars(&lines[start..end].join("\n"), chunk::MAX_STORED_CHARS);
                Some(c)
            })
            .collect();
        (chunks, calls)
    }
}

/// The file's text, if it may be read at all: not a sensitive path, not a symlink (which could lead
/// out of the repo), not oversized, and valid UTF-8 with no NULs.
pub fn read_clean(repo: &Path, rel: &str) -> Result<Source, Refused> {
    if redact::is_sensitive_path(rel) || redact::clean(rel).as_deref() != Some(rel) {
        return Err(Refused::Sensitive);
    }
    let full = repo.join(rel);
    let meta = fs::symlink_metadata(&full).map_err(|_| Refused::Unreadable)?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return Err(Refused::Unreadable);
    }
    // A symlinked parent folder can lead out of the repo even when the file itself isn't a link.
    let real = full.canonicalize().map_err(|_| Refused::Unreadable)?;
    let real_repo = repo.canonicalize().map_err(|_| Refused::Unreadable)?;
    if !real.starts_with(real_repo) {
        return Err(Refused::Unreadable);
    }
    let bytes = fs::read(&full).map_err(|_| Refused::Unreadable)?;
    let raw = String::from_utf8(bytes).map_err(|_| Refused::Unreadable)?;
    // NULs mean UTF-16 or binary, where the detectors can't see tokens.
    if raw.contains('\0') {
        return Err(Refused::Unreadable);
    }
    let clean = redact::clean(&raw).ok_or(Refused::Withheld)?;
    Ok(Source { raw, clean })
}

#[derive(Debug, PartialEq)]
pub enum Refused {
    Sensitive,
    Unreadable,
    Withheld,
}

const MAX_COMMENT_LINES: usize = 40;
const MAX_COMMENT_CHARS: usize = 600;

/// The comment block directly above a function (`start` is its 1-based line), markers and doc tags
/// removed. Rust attribute lines in between are skipped; a blank line ends the block.
fn leading_comment(lines: &[&str], start: usize) -> String {
    let mut found: Vec<&str> = Vec::new();
    let mut i = start.saturating_sub(1).min(lines.len());
    let mut steps = 0;
    while i > 0 && steps < MAX_COMMENT_LINES {
        let line = lines[i - 1].trim();
        i -= 1;
        steps += 1;
        if line.starts_with("#[") {
            continue;
        }
        let is_comment = line.starts_with("//")
            || line.starts_with("/*")
            || line.starts_with('*')
            || line.ends_with("*/")
            || line.starts_with('#');
        if !is_comment {
            break;
        }
        let text = line.trim_start_matches(['/', '*', '#', '!']).trim().trim_end_matches("*/").trim();
        if !text.is_empty() && !text.starts_with('@') {
            found.push(text);
        }
    }
    found.reverse();
    first_chars(&found.join(" "), MAX_COMMENT_CHARS)
}

/// A called name defined in more places than this is too vague to link.
const MAX_CALL_TARGETS: usize = 3;

struct Pending {
    head: Vec<u32>,
    body: Vec<u32>,
    calls: Vec<String>,
}

/// Turns each chunk's called names into chunk indexes, matching the last part of each symbol.
/// A definition in the caller's own file wins over ones elsewhere.
fn link_calls(chunks: &mut [ChunkEntry], calls: &[Vec<String>]) {
    let mut by_name: HashMap<&str, Vec<u32>> = HashMap::new();
    for (i, c) in chunks.iter().enumerate() {
        by_name.entry(c.symbol.rsplit('.').next().unwrap_or(&c.symbol)).or_default().push(i as u32);
    }
    let links: Vec<Vec<u32>> = calls
        .iter()
        .enumerate()
        .map(|(i, names)| {
            let file = chunks[i].file;
            let mut out: Vec<u32> = Vec::new();
            for name in names {
                let Some(found) = by_name.get(name.as_str()) else { continue };
                let local: Vec<u32> = found.iter().copied().filter(|j| chunks[*j as usize].file == file).collect();
                let targets = if local.is_empty() { found.clone() } else { local };
                if targets.len() <= MAX_CALL_TARGETS {
                    out.extend(targets.into_iter().filter(|j| *j as usize != i));
                }
            }
            out.sort_unstable();
            out.dedup();
            out
        })
        .collect();
    for (c, l) in chunks.iter_mut().zip(links) {
        c.calls = l;
    }
}

pub fn run(repo: PathBuf) -> Result<(), String> {
    let repo = repo.canonicalize().map_err(|e| format!("no such folder: {}: {e}", repo.display()))?;
    let model = embed::Model::load();
    let mut index = Index::default();
    let mut pending = Vec::new();
    let mut doc_freq = vec![0u32; model.vocab_size()];
    let (mut sensitive, mut withheld) = (0, 0);

    for rel in list_files(&repo) {
        let path = Path::new(&rel);
        if redact::is_sensitive_path(&rel) {
            sensitive += 1;
            continue;
        }
        let Some((_, language)) = path.extension().and_then(|e| e.to_str()).and_then(chunk::lang_for) else {
            continue;
        };
        let source = match read_clean(&repo, &rel) {
            Ok(source) => source,
            Err(Refused::Sensitive) => {
                sensitive += 1;
                continue;
            }
            Err(Refused::Withheld) => {
                withheld += 1;
                continue;
            }
            Err(Refused::Unreadable) => continue,
        };

        let filename = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let file = index.files.len() as u32;
        index.files.push(FileEntry { path: rel.clone(), hash: fnv64(source.clean.as_bytes()) });
        let lines: Vec<&str> = source.clean.lines().collect();
        // The index keeps only the links between chunks that calls make, not the called names.
        let (chunks, file_calls) = source.chunks_and_calls(&language, &filename);
        for c in chunks {
            let (first, last) = (c.start_line as u32, c.end_line as u32);
            let mut calls: Vec<String> =
                file_calls.iter().filter(|(l, _)| (first..=last).contains(l)).map(|(_, n)| n.clone()).collect();
            calls.sort_unstable();
            calls.dedup();
            // The comment above a function holds the words people search with. It is read from the
            // redacted text and only feeds the hashed terms and vectors; it is never stored or printed.
            let comment = leading_comment(&lines, c.start_line as usize);
            let text = if comment.is_empty() { c.content.clone() } else { format!("{comment}\n{}", c.content) };
            let head = model.tokens(&format!("{rel} {}", c.symbol));
            let body = model.tokens(&first_chars(&text, MAX_EMBED_CHARS));
            let mut seen: Vec<u32> = head.iter().chain(&body).copied().collect();
            seen.sort_unstable();
            seen.dedup();
            for id in seen {
                doc_freq[id as usize] += 1;
            }
            pending.push(Pending { head, body, calls });

            let mut counts: HashMap<u32, u32> = HashMap::new();
            for t in terms::terms(&text) {
                *counts.entry(t).or_default() += 1;
            }
            for t in terms::terms(&format!("{filename} {}", c.symbol)) {
                *counts.entry(t).or_default() += HEAD_TERM_WEIGHT;
            }
            let length = counts.values().sum();
            let mut terms: Vec<(u32, u8)> = counts.into_iter().map(|(t, n)| (t, n.min(255) as u8)).collect();
            terms.sort_unstable();
            index.chunks.push(ChunkEntry {
                file,
                start_line: c.start_line as u32,
                end_line: c.end_line as u32,
                kind: KINDS.iter().position(|k| *k == c.kind).unwrap_or(0) as u8,
                symbol: c.symbol,
                length,
                terms,
                calls: Vec::new(),
            });
        }
    }

    let calls: Vec<Vec<String>> = pending.iter_mut().map(|p| std::mem::take(&mut p.calls)).collect();
    link_calls(&mut index.chunks, &calls);
    index.weights = embed::idf_weights(&doc_freq, pending.len());
    for p in &pending {
        index.vectors.extend(model.embed(&p.head, HEAD_VECTOR_WEIGHT, &p.body, &index.weights));
    }
    index.save(&repo)?;
    let bytes = fs::metadata(store::index_path(&repo)).map(|m| m.len()).unwrap_or(0);
    crate::emit(&format!(
        "{}: {} files, {} chunks, {} KB. Skipped {sensitive} sensitive, withheld {withheld}.\n",
        repo.display(),
        index.files.len(),
        index.chunks.len(),
        bytes / 1024
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ChunkEntry, Source, leading_comment, link_calls};

    #[test]
    fn a_call_on_a_line_that_redaction_changed_is_dropped() {
        let raw = "fn a() { b(); }\nfn c() { d(\"x\"); }\n";
        let source = Source { raw: raw.into(), clean: "fn a() { b(); }\nfn c() { d([REDACTED]); }\n".into() };
        let (_, language) = crate::chunk::lang_for("rs").unwrap();
        let (chunks, calls) = source.chunks_and_calls(&language, "x.rs");
        assert_eq!(chunks.len(), 2);
        assert_eq!(calls, [(1, "b".to_string())]);
    }

    fn chunk(file: u32, symbol: &str) -> ChunkEntry {
        ChunkEntry { file, start_line: 1, end_line: 1, kind: 0, symbol: symbol.into(), length: 0, terms: vec![], calls: vec![] }
    }

    #[test]
    fn calls_link_to_the_same_file_first_and_skip_vague_names() {
        let mut chunks = vec![chunk(0, "main"), chunk(0, "send"), chunk(1, "send"), chunk(1, "Q.run"), chunk(2, "run"), chunk(3, "run"), chunk(4, "run")];
        let names = |n: &[&str]| n.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let calls = vec![names(&["send", "run", "missing"]), vec![], names(&["send"]), vec![], vec![], vec![], vec![]];
        link_calls(&mut chunks, &calls);
        // `send` resolves to its own file's copy; `run` has four definitions, too many to guess.
        assert_eq!(chunks[0].calls, [1]);
        // A chunk never links to itself.
        assert!(chunks[2].calls.is_empty());
    }

    #[test]
    fn a_block_comment_above_a_function_is_read_without_markers_or_tags() {
        let lines = ["x = 1", "", "/**", " * Retries the upload.", " * @param n count", " */", "function send(n) {"];
        assert_eq!(leading_comment(&lines, 7), "Retries the upload.");
    }

    #[test]
    fn line_comments_are_joined_and_rust_attributes_are_skipped() {
        let lines = ["fn a() {}", "/// Parses the header.", "/// Returns none if absent.", "#[test]", "fn b() {}"];
        assert_eq!(leading_comment(&lines, 5), "Parses the header. Returns none if absent.");
    }

    #[test]
    fn a_blank_line_ends_the_block_and_code_is_not_a_comment() {
        let lines = ["// header", "", "const x = 1;", "function f() {}"];
        assert_eq!(leading_comment(&lines, 4), "");
        assert_eq!(leading_comment(&lines, 3), "");
    }
}
