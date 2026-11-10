//! The per-repo index file: file hashes, chunk locations, keyword hashes, and one i8 vector per
//! chunk, and which chunks each one calls. It holds no source text; `search` reads the live file and redacts it again at output.

use std::fs;
use std::path::{Path, PathBuf};

use crate::{embed, redact};

const DIR: &str = ".quarry";
const FILE: &str = "index";
const MAGIC: &[u8; 4] = b"CSRY";
const FORMAT: u32 = 3;
pub const KINDS: &[&str] = &["function", "method", "module"];

pub struct FileEntry {
    pub path: String,
    pub hash: u64,
}

pub struct ChunkEntry {
    pub file: u32,
    pub start_line: u32,
    pub end_line: u32,
    pub kind: u8,
    pub symbol: String,
    /// Total term count, repeats included.
    pub length: u32,
    /// Distinct terms: hash and count.
    pub terms: Vec<(u32, u8)>,
    /// Chunks this one calls, by index.
    pub calls: Vec<u32>,
}

#[derive(Default)]
pub struct Index {
    pub files: Vec<FileEntry>,
    pub chunks: Vec<ChunkEntry>,
    /// `chunks.len() * embed::DIMS` values, in chunk order.
    pub vectors: Vec<i8>,
    /// One per model token.
    pub weights: Vec<u8>,
}

pub fn index_path(root: &Path) -> PathBuf {
    root.join(DIR).join(FILE)
}

/// Nearest folder at or above `start` that has an index.
pub fn find_root(start: &Path) -> Option<PathBuf> {
    start.ancestors().find(|p| index_path(p).is_file()).map(Path::to_path_buf)
}

fn stamp() -> [u32; 3] {
    [FORMAT, redact::VERSION, embed::MODEL_ID]
}

impl Index {
    pub fn vector(&self, chunk: usize) -> &[i8] {
        &self.vectors[chunk * embed::DIMS..(chunk + 1) * embed::DIMS]
    }

    /// Writes the index, plus a `.gitignore` so it never needs an entry in the repo's own. The
    /// rename means a crash leaves the old index, not half of a new one.
    pub fn save(&self, root: &Path) -> Result<(), String> {
        let path = index_path(root);
        let dir = root.join(DIR);
        fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        fs::write(dir.join(".gitignore"), "*\n").map_err(|e| format!("writing .gitignore: {e}"))?;

        let mut out = Vec::with_capacity(self.vectors.len() + self.chunks.len() * 256);
        out.extend_from_slice(MAGIC);
        for n in stamp() {
            put_u32(&mut out, n);
        }
        for n in [self.files.len(), self.chunks.len(), self.weights.len()] {
            put_u32(&mut out, n as u32);
        }
        out.extend_from_slice(&self.weights);
        for f in &self.files {
            put_str(&mut out, &f.path);
            out.extend_from_slice(&f.hash.to_le_bytes());
        }
        for c in &self.chunks {
            for n in [c.file, c.start_line, c.end_line, c.length, c.terms.len() as u32] {
                put_u32(&mut out, n);
            }
            out.push(c.kind);
            put_str(&mut out, &c.symbol);
            for (hash, count) in &c.terms {
                put_u32(&mut out, *hash);
                out.push(*count);
            }
            put_u32(&mut out, c.calls.len() as u32);
            for n in &c.calls {
                put_u32(&mut out, *n);
            }
        }
        out.extend(self.vectors.iter().map(|v| *v as u8));

        let tmp = dir.join(format!("{FILE}.tmp.{}", std::process::id()));
        fs::write(&tmp, &out).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
        fs::rename(&tmp, &path).map_err(|e| format!("replacing {}: {e}", path.display()))
    }

    /// Reads an index. Any mismatch in version, redactor, model, or shape is an error: vectors
    /// made under older rules aren't trusted.
    pub fn load(root: &Path) -> Result<Index, String> {
        let path = index_path(root);
        let bytes = fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        Self::parse(&bytes).ok_or_else(|| "index is from another version or damaged. Run: quarry index .".to_string())
    }

    fn parse(bytes: &[u8]) -> Option<Index> {
        let mut r = Reader { bytes, at: 0 };
        if r.take(4)? != MAGIC || [r.u32()?, r.u32()?, r.u32()?] != stamp() {
            return None;
        }
        let (n_files, n_chunks, n_weights) = (r.u32()? as usize, r.u32()? as usize, r.u32()? as usize);
        let weights = r.take(n_weights)?.to_vec();
        let files = (0..n_files)
            .map(|_| Some(FileEntry { path: r.str()?, hash: u64::from_le_bytes(r.take(8)?.try_into().ok()?) }))
            .collect::<Option<Vec<_>>>()?;
        let chunks = (0..n_chunks)
            .map(|_| {
                let (file, start_line, end_line, length, n_terms) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?);
                ((file as usize) < n_files).then_some(())?;
                let kind = r.take(1)?[0];
                let symbol = r.str()?;
                let terms = (0..n_terms).map(|_| Some((r.u32()?, r.take(1)?[0]))).collect::<Option<Vec<_>>>()?;
                let n_calls = r.u32()? as usize;
                let calls = (0..n_calls).map(|_| r.u32().filter(|n| (*n as usize) < n_chunks)).collect::<Option<Vec<_>>>()?;
                Some(ChunkEntry { file, start_line, end_line, kind, symbol, length, terms, calls })
            })
            .collect::<Option<Vec<_>>>()?;
        let vectors = r.take(n_chunks.checked_mul(embed::DIMS)?)?.iter().map(|b| *b as i8).collect();
        (r.at == bytes.len()).then_some(Index { files, chunks, vectors, weights })
    }
}

fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_u32(out, s.len() as u32);
    out.extend_from_slice(s.as_bytes());
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(out)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn str(&mut self) -> Option<String> {
        let n = self.u32()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).ok()
    }
}
