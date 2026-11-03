#!/usr/bin/env python3
"""Builds model/vocab.txt and model/vectors.i8, the static word vectors compiled into the binary.

Same recipe as model2vec: run every BERT token through bge-small-en-v1.5, reduce to DIMS with PCA,
scale by a frequency weight, store as i8. Needs numpy, onnxruntime, and the model files:
    python tools/build_model.py <folder with model_optimized.onnx and tokenizer.json>
"""
import json
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort

DIMS = 64
SIF = 1e-3
BATCH = 256
CLS, SEP = 101, 102


def main():
    src = Path(sys.argv[1])
    out = Path(__file__).resolve().parent.parent / "model"
    vocab = json.loads((src / "tokenizer.json").read_text())["model"]["vocab"]
    n = len(vocab)
    words = [w for w, _ in sorted(vocab.items(), key=lambda kv: kv[1])]

    session = ort.InferenceSession(str(src / "model_optimized.onnx"), providers=["CPUExecutionProvider"])
    vectors = np.zeros((n, 384), np.float64)
    for i in range(0, n, BATCH):
        ids = np.arange(i, min(n, i + BATCH), dtype=np.int64)
        batch = np.stack([np.full(len(ids), CLS, np.int64), ids, np.full(len(ids), SEP, np.int64)], 1)
        feed = {"input_ids": batch, "attention_mask": np.ones_like(batch), "token_type_ids": np.zeros_like(batch)}
        vectors[i : i + len(ids)] = session.run(None, feed)[0].mean(1)

    vectors -= vectors.mean(0)
    eigenvalues, eigenvectors = np.linalg.eigh(vectors.T @ vectors)
    reduced = vectors @ eigenvectors[:, np.argsort(-eigenvalues)[:DIMS]]
    reduced /= np.linalg.norm(reduced, axis=1, keepdims=True) + 1e-9
    # BERT's vocab is close to frequency order, so rank stands in for frequency.
    rank = np.arange(n) + np.e
    probability = (1 / rank) / (1 / rank).sum()
    reduced *= (SIF / (SIF + probability))[:, None]
    quantized = np.round(reduced * 127 / np.abs(reduced).max()).astype(np.int8)

    # The tokenizer treats non-ASCII as a separator, so those entries could never match.
    keep = [i for i, w in enumerate(words) if w.isascii() and not w.startswith("[unused")]
    out.mkdir(exist_ok=True)
    (out / "vocab.txt").write_text("\n".join(words[i] for i in keep) + "\n")
    (out / "vectors.i8").write_bytes(quantized[keep].tobytes())
    print(f"{len(keep)} tokens, {DIMS} dims, {len(keep) * DIMS} bytes")


if __name__ == "__main__":
    main()
