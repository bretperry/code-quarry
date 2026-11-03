//! Keyword terms for BM25: lowercased identifier words with a light stem, stored as hashes so the
//! index holds no words at all.

use crate::embed::split_identifiers;

const STOP: &[&str] = &[
    "a", "an", "the", "of", "to", "in", "on", "for", "and", "or", "is", "it", "this", "that", "with", "from", "by",
    "as", "at", "be", "are", "do", "does", "when", "so", "we", "not", "all", "its",
];
const SUFFIXES: &[&str] = &["ing", "ers", "ed", "es", "er", "s"];
const MIN_STEM: usize = 3;

fn stem(word: &str) -> &str {
    SUFFIXES
        .iter()
        .find_map(|s| word.strip_suffix(s).filter(|rest| rest.len() >= MIN_STEM))
        .unwrap_or(word)
}

pub fn fnv32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5, |h, b| (h ^ *b as u32).wrapping_mul(0x0100_0193))
}

/// One hash per occurrence of each term in `text`.
pub fn terms(text: &str) -> Vec<u32> {
    let lower = split_identifiers(text).to_ascii_lowercase();
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() > 1 && !STOP.contains(w))
        .map(|w| fnv32(stem(w).as_bytes()))
        .collect()
}
