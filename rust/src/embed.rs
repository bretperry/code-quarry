//! Static word vectors compiled into the binary: a chunk's vector is the weighted mean of its
//! tokens' vectors, with no neural network at run time. `tools/build_model.py` makes the files.

use std::collections::HashMap;

pub const DIMS: usize = 64;
/// Bump when the model files change: vectors from different models don't compare.
pub const MODEL_ID: u32 = 1;

const VOCAB: &str = include_str!("../model/vocab.txt");
const VECTORS: &[u8] = include_bytes!("../model/vectors.i8");
const MAX_WORD_CHARS: usize = 100;
const WEIGHT_SCALE: f32 = 25.0;

pub struct Model {
    ids: HashMap<&'static str, u32>,
}

/// Puts a space at each camelCase boundary and turns `_` into a space, so `getUserId` and
/// `get_user_id` both read as words.
pub fn split_identifiers(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len() + text.len() / 8);
    for (i, &c) in chars.iter().enumerate() {
        if c == '_' {
            out.push(' ');
            continue;
        }
        if i > 0 && c.is_ascii_uppercase() {
            let prev = chars[i - 1];
            let next_lower = chars.get(i + 1).is_some_and(char::is_ascii_lowercase);
            if prev.is_ascii_lowercase() || prev.is_ascii_digit() || (prev.is_ascii_uppercase() && next_lower) {
                out.push(' ');
            }
        }
        out.push(c);
    }
    out
}

impl Model {
    pub fn load() -> Model {
        let ids = VOCAB.lines().enumerate().map(|(i, w)| (w, i as u32)).collect();
        Model { ids }
    }

    pub fn vocab_size(&self) -> usize {
        self.ids.len()
    }

    /// BERT-style tokens: lowercase words split greedily into known pieces, punctuation alone.
    /// Words with no pieces are dropped.
    pub fn tokens(&self, text: &str) -> Vec<u32> {
        let split = split_identifiers(text);
        let mut out = Vec::new();
        for word in split.split(|c: char| !c.is_ascii() || c.is_ascii_whitespace() || c.is_ascii_control()) {
            let lower = word.to_ascii_lowercase();
            for piece in lower.split_inclusive(|c: char| c.is_ascii_punctuation()) {
                let (run, punct) = match piece.char_indices().last() {
                    Some((i, c)) if c.is_ascii_punctuation() => piece.split_at(i),
                    _ => (piece, ""),
                };
                self.word_pieces(run, &mut out);
                if let Some(id) = self.ids.get(punct) {
                    out.push(*id);
                }
            }
        }
        out
    }

    fn word_pieces(&self, word: &str, out: &mut Vec<u32>) {
        if word.is_empty() || word.len() > MAX_WORD_CHARS {
            return;
        }
        let mark = out.len();
        let mut buf = String::with_capacity(word.len() + 2);
        let mut start = 0;
        while start < word.len() {
            let mut end = word.len();
            let found = loop {
                if end == start {
                    break None;
                }
                buf.clear();
                if start > 0 {
                    buf.push_str("##");
                }
                buf.push_str(&word[start..end]);
                if let Some(id) = self.ids.get(buf.as_str()) {
                    break Some(*id);
                }
                end -= 1;
            };
            let Some(id) = found else {
                out.truncate(mark);
                return;
            };
            out.push(id);
            start = end;
        }
    }

    /// Unit-length vector stored as i8, with each token scaled by its weight.
    pub fn embed(&self, head: &[u32], head_weight: f32, body: &[u32], weights: &[u8]) -> Vec<i8> {
        let mut sum = [0f32; DIMS];
        for (ids, scale) in [(head, head_weight), (body, 1.0)] {
            for &id in ids {
                let weight = weights[id as usize] as f32 / WEIGHT_SCALE * scale;
                let row = &VECTORS[id as usize * DIMS..(id as usize + 1) * DIMS];
                for (s, v) in sum.iter_mut().zip(row) {
                    *s += (*v as i8) as f32 * weight;
                }
            }
        }
        let norm = sum.iter().map(|v| v * v).sum::<f32>().sqrt().max(1e-9);
        sum.iter().map(|v| (v / norm * 127.0).round() as i8).collect()
    }
}

/// Token weights for this repo, rare tokens highest, from document frequencies.
pub fn idf_weights(doc_freq: &[u32], n_docs: usize) -> Vec<u8> {
    let n = (n_docs + 1) as f32;
    doc_freq
        .iter()
        .map(|df| {
            let idf = (n / (*df as f32 + 1.0)).ln() + 0.1;
            (idf * WEIGHT_SCALE).clamp(1.0, 255.0) as u8
        })
        .collect()
}
