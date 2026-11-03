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
        let lines: Vec<&str> = self.clean.lines().collect();
        chunk::chunk_source(self.raw.as_bytes(), language, filename)
            .into_iter()
            .filter_map(|mut c| {
                c.symbol = redact::clean(&c.symbol)?;
                let start = (c.start_line as usize).saturating_sub(1).min(lines.len());
                let end = (c.end_line as usize).min(lines.len()).max(start);
                c.content = first_chars(&lines[start..end].join("\n"), chunk::MAX_STORED_CHARS);
                Some(c)
            })
            .collect()
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

struct Pending {
    head: Vec<u32>,
    body: Vec<u32>,
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
        for c in source.chunks(&language, &filename) {
            let head = model.tokens(&format!("{rel} {}", c.symbol));
            let body = model.tokens(&first_chars(&c.content, MAX_EMBED_CHARS));
            let mut seen: Vec<u32> = head.iter().chain(&body).copied().collect();
            seen.sort_unstable();
            seen.dedup();
            for id in seen {
                doc_freq[id as usize] += 1;
            }
            pending.push(Pending { head, body });

            let mut counts: HashMap<u32, u32> = HashMap::new();
            for t in terms::terms(&c.content) {
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
            });
        }
    }

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
