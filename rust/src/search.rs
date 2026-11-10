use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::index::{self, Refused};
use crate::store::{ChunkEntry, Index, KINDS};
use crate::{chunk, embed, redact, store, terms};

const BM25_K1: f32 = 2.0;
const BM25_B: f32 = 0.9;
/// Keyword matches count more than vector matches. With these BM25 settings, weights from 1.5 to 3
/// beat 1 on 430 queries made from code comments; the 30 hard queries preferred 1 to 1.5.
const KEYWORD_WEIGHT: f32 = 1.5;
/// Reciprocal rank fusion: a low constant lets a top rank from either ranker count.
const FUSION_K: f32 = 20.0;
/// A function scores this share of its best caller's score on top of its own: the code that calls
/// it often says what it is for. Callees' scores hurt, so they aren't used.
const CALLER_WEIGHT: f32 = 0.5;
pub const MAX_OUTPUT_CHARS: usize = 6000;

fn keyword_scores(index: &Index, query: &str) -> Vec<f32> {
    let mut wanted = terms::terms(query);
    wanted.sort_unstable();
    wanted.dedup();
    let n = index.chunks.len() as f32;
    let avg = index.chunks.iter().map(|c| c.length as f32).sum::<f32>() / n.max(1.0);
    let mut doc_freq: HashMap<u32, f32> = HashMap::new();
    for c in &index.chunks {
        for t in &wanted {
            if c.terms.binary_search_by_key(t, |(hash, _)| *hash).is_ok() {
                *doc_freq.entry(*t).or_default() += 1.0;
            }
        }
    }
    index
        .chunks
        .iter()
        .map(|c| {
            wanted
                .iter()
                .filter_map(|t| {
                    let i = c.terms.binary_search_by_key(t, |(hash, _)| *hash).ok()?;
                    let df = doc_freq[t];
                    let idf = (1.0 + (n - df + 0.5) / (df + 0.5)).ln();
                    let tf = c.terms[i].1 as f32;
                    Some(idf * tf * (BM25_K1 + 1.0) / (tf + BM25_K1 * (1.0 - BM25_B + BM25_B * c.length as f32 / avg)))
                })
                .sum()
        })
        .collect()
}

fn vector_scores(index: &Index, query: &str, model: &embed::Model) -> Vec<f32> {
    if index.weights.len() != model.vocab_size() {
        return vec![0.0; index.chunks.len()];
    }
    let q = model.embed(&[], 0.0, &model.tokens(query), &index.weights);
    (0..index.chunks.len())
        .map(|i| index.vector(i).iter().zip(&q).map(|(a, b)| *a as i32 * *b as i32).sum::<i32>() as f32)
        .collect()
}

fn add_fused_ranks(scores: &[f32], total: &mut [f32], weight: f32) {
    let mut order: Vec<usize> = (0..scores.len()).collect();
    order.sort_unstable_by(|a, b| scores[*b].total_cmp(&scores[*a]).then(a.cmp(b)));
    for (rank, i) in order.into_iter().enumerate() {
        total[i] += weight / (FUSION_K + rank as f32);
    }
}

/// Adds `CALLER_WEIGHT` times each chunk's best caller's score.
fn add_caller_scores(index: &Index, scores: &[f32]) -> Vec<f32> {
    let mut best_caller = vec![0f32; scores.len()];
    for (i, c) in index.chunks.iter().enumerate() {
        for j in &c.calls {
            best_caller[*j as usize] = best_caller[*j as usize].max(scores[i]);
        }
    }
    scores.iter().zip(best_caller).map(|(s, b)| s + CALLER_WEIGHT * b).collect()
}

/// Lines `start..=end` (1-based) of cleaned text, capped, saying what the cap cut.
fn body_of(text: &str, start: u32, end: u32, max_lines: Option<usize>) -> String {
    let lines: Vec<&str> =
        text.lines().skip(start.saturating_sub(1) as usize).take((end + 1).saturating_sub(start) as usize).collect();
    let shown = max_lines.map_or(lines.len(), |m| m.min(lines.len()));
    let mut out = String::new();
    let mut count = 0;
    for line in &lines[..shown] {
        if out.len() + line.len() > MAX_OUTPUT_CHARS {
            break;
        }
        out.push_str(line);
        out.push('\n');
        count += 1;
    }
    if count < lines.len() {
        out.push_str(&format!("... [{} more lines, to line {end}]\n", lines.len() - count));
    }
    out
}

/// The chunk's location in the file as it is now: the indexed lines if the file is unchanged, or
/// wherever its symbol moved to. None when the symbol is gone.
fn locate(index: &Index, c: &ChunkEntry, path: &str, source: &index::Source) -> Option<(u32, u32)> {
    if index.files[c.file as usize].hash == index::fnv64(source.clean.as_bytes()) {
        return Some((c.start_line, c.end_line));
    }
    let p = Path::new(path);
    let (_, language) = p.extension().and_then(|e| e.to_str()).and_then(chunk::lang_for)?;
    let filename = p.file_name()?.to_string_lossy();
    source
        .chunks(&language, &filename)
        .into_iter()
        .find(|n| n.symbol == c.symbol)
        .map(|n| (n.start_line as u32, n.end_line as u32))
}

fn print_hit(root: &Path, index: &Index, c: &ChunkEntry, score: f32, max_lines: Option<usize>) {
    let path = &index.files[c.file as usize].path;
    let kind = KINDS.get(c.kind as usize).unwrap_or(&"chunk");
    // The index may be old or edited by hand, so its path and symbol get checked like any text.
    let symbol = redact::clean(&format!("{} ({kind})", c.symbol)).unwrap_or_else(|| "[withheld]".into());
    let safe_path = redact::clean(path).unwrap_or_else(|| "[withheld]".into());
    let header = |lines: &str| format!("--- {score:.3} {safe_path}{lines} {symbol}");
    match index::read_clean(root, path) {
        Ok(source) => match locate(index, c, path, &source) {
            Some((start, end)) => {
                crate::emit(&format!("{}\n{}", header(&format!(":{start}-{end}")), body_of(&source.clean, start, end, max_lines)));
            }
            None => crate::emit(&format!("{}\n[gone from the file since indexing. Run: quarry index .]\n", header(""))),
        },
        Err(Refused::Sensitive) => crate::emit(&format!("{}\n[withheld: sensitive file]\n", header(""))),
        Err(Refused::Withheld) => crate::emit(&format!("{}\n[withheld: could not redact this file]\n", header(""))),
        Err(Refused::Unreadable) => crate::emit(&format!("{}\n[file unreadable. Run: quarry index .]\n", header(""))),
    }
}

/// The git repo holding `start`, if any.
pub fn git_root(start: &Path) -> Option<PathBuf> {
    let out = std::process::Command::new("git").arg("-C").arg(start).args(["rev-parse", "--show-toplevel"]).output().ok()?;
    let top = String::from_utf8(out.stdout).ok()?;
    if out.status.success() && !top.trim().is_empty() { PathBuf::from(top.trim()).canonicalize().ok() } else { None }
}

/// Finds the index for `start`, building it first when there is none in a git repo, or rebuilding
/// it when files changed since. Notes go to stderr so stdout stays only results.
fn fresh_index(start: &Path, refresh: bool) -> Result<(PathBuf, Index), String> {
    let root = match store::find_root(start) {
        Some(root) => root,
        None => {
            // Outside git there's no telling how big the folder is (it could be ~), so ask first.
            let root = git_root(start).ok_or("Nothing indexed here, and it's not a git repo. Run: quarry index <folder>")?;
            eprint!("quarry: no index yet, building one. {}", index::build(&root)?);
            return Ok((root.clone(), Index::load(&root)?));
        }
    };
    let index = Index::load(&root)?;
    if refresh && index::is_stale(&root, &index) {
        eprint!("quarry: files changed since indexing, re-indexing. {}", index::build(&root)?);
        return Ok((root.clone(), Index::load(&root)?));
    }
    Ok((root, index))
}

pub fn run(query: String, repo: Option<PathBuf>, k: usize, max_lines: Option<usize>, refresh: bool) -> Result<(), String> {
    let start = match repo {
        Some(p) => p,
        None => std::env::current_dir().map_err(|e| e.to_string())?,
    };
    let start = start.canonicalize().map_err(|e| format!("no such folder: {}: {e}", start.display()))?;
    let (root, index) = fresh_index(&start, refresh)?;
    let model = embed::Model::load();

    let mut total = vec![0f32; index.chunks.len()];
    add_fused_ranks(&keyword_scores(&index, &query), &mut total, KEYWORD_WEIGHT);
    add_fused_ranks(&vector_scores(&index, &query, &model), &mut total, 1.0);
    let total = add_caller_scores(&index, &total);
    let mut order: Vec<usize> = (0..total.len()).collect();
    order.sort_unstable_by(|a, b| total[*b].total_cmp(&total[*a]).then(a.cmp(b)));
    for i in order.into_iter().take(k) {
        let best = (KEYWORD_WEIGHT + 1.0) / FUSION_K * (1.0 + CALLER_WEIGHT);
        print_hit(&root, &index, &index.chunks[i], total[i] / best, max_lines);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_is_cut_at_the_line_limit_and_says_so() {
        assert_eq!(body_of("a\nb\nc\nd\n", 2, 4, Some(1)), "b\n... [2 more lines, to line 4]\n");
        assert_eq!(body_of("a\nb\nc\n", 1, 3, None), "a\nb\nc\n");
    }

    #[test]
    fn body_is_cut_at_the_size_limit_and_says_so() {
        let line = "x".repeat(MAX_OUTPUT_CHARS);
        let got = body_of(&format!("{line}\n{line}\n"), 1, 2, None);
        assert!(got.ends_with("... [1 more lines, to line 2]\n"), "{}", &got[got.len() - 40..]);
    }

    #[test]
    fn old_or_edited_index_cannot_reach_sensitive_paths() {
        for rel in [".env", "../outside.py", "secrets/x.py"] {
            assert_eq!(index::read_clean(Path::new("."), rel).err(), Some(Refused::Sensitive), "{rel}");
        }
    }
}
