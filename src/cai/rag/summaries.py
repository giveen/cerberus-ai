"""Utilities to generate, persist, and load compact L0/L1 wake-up summaries.

This module provides a deterministic extractive fallback summarizer useful
for local/dev environments (no external model required) and helpers to
persist summaries to disk and load them into a `WakeupIndex` for a
session at startup.
"""
from __future__ import annotations

import os
import re
import json
import datetime as _dt
from typing import Dict, List, Optional

# Small stopword set for deterministic extractive summarization
_STOPWORDS = {
    "the",
    "and",
    "a",
    "an",
    "of",
    "in",
    "to",
    "is",
    "are",
    "for",
    "on",
    "with",
    "as",
    "that",
    "this",
    "it",
    "by",
    "from",
    "at",
    "or",
    "we",
    "you",
    "be",
    "was",
    "were",
}


def _split_sentences(text: str) -> List[str]:
    if not text:
        return []
    # keep it simple and deterministic: split on sentence enders
    parts = re.split(r'(?<=[\.\?!])\s+', text.strip())
    return [p.strip() for p in parts if p.strip()]


def _tokenize(text: str) -> List[str]:
    return [t.lower() for t in re.findall(r"\w+", text or "")]


def _word_frequencies(texts: List[str]) -> Dict[str, int]:
    freqs: Dict[str, int] = {}
    for t in texts:
        for w in _tokenize(t):
            if w in _STOPWORDS:
                continue
            freqs[w] = freqs.get(w, 0) + 1
    return freqs


def generate_l0_summary(collection_texts: List[str], max_tokens: int = 170) -> str:
    """Generate a compact (approximate) extractive L0 summary.

    This is a deterministic, dependency-free fallback summarizer that
    selects high-value sentences based on collection-level word
    frequencies. It is intended for producing a short (about
    `max_tokens`) critical-facts summary per collection.
    """
    if not collection_texts:
        return ""

    full = "\n\n".join(collection_texts)
    sentences = _split_sentences(full)
    if not sentences:
        return ""

    freqs = _word_frequencies(collection_texts)

    scored = []
    for i, s in enumerate(sentences):
        score = 0
        toks = _tokenize(s)
        for w in toks:
            score += freqs.get(w, 0)
        # normalize by length to prefer concise high-density sentences
        if toks:
            score = score / float(len(toks))
        scored.append((i, s, float(score)))

    # choose highest scoring sentences until token budget
    scored_sorted = sorted(scored, key=lambda t: t[2], reverse=True)
    selected_idx = []
    token_count = 0
    for i, s, _ in scored_sorted:
        toks = _tokenize(s)
        if token_count + len(toks) > max_tokens:
            continue
        selected_idx.append(i)
        token_count += len(toks)
        if token_count >= max_tokens:
            break

    # fallback: if nothing selected, take the first sentence(s)
    if not selected_idx:
        out = []
        tc = 0
        for s in sentences:
            toks = _tokenize(s)
            out.append(s)
            tc += len(toks)
            if tc >= max_tokens:
                break
        return " ".join(out)[: max_tokens * 8]

    # preserve original order when returning
    selected_idx = sorted(set(selected_idx))
    out = [sentences[i] for i in selected_idx]
    return " ".join(out)


def generate_l1_summary(collection_texts: List[str], max_tokens: int = 450) -> str:
    """Generate a larger (L1) summary. Uses the same heuristic with a bigger budget."""
    return generate_l0_summary(collection_texts, max_tokens=max_tokens)


def _default_store_path() -> str:
    env = os.getenv("CEREBRO_WAKE_SUMMARIES_FILE")
    if env:
        return env
    # place under project-local .cai directory by default
    return os.path.join(os.getcwd(), ".cai", "wakeup_summaries.json")


def read_persisted_summaries(store_path: Optional[str] = None) -> Dict[str, Dict[str, str]]:
    path = store_path or _default_store_path()
    try:
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def persist_summaries(palace_id: str, l0: str, l1: Optional[str] = None, store_path: Optional[str] = None) -> bool:
    path = store_path or _default_store_path()
    data = read_persisted_summaries(path)
    # Use timezone-aware ISO8601 for updated_at
    data[palace_id] = {"L0": l0, "L1": l1, "updated_at": _dt.datetime.now(_dt.timezone.utc).isoformat()}
    try:
        d = os.path.dirname(path)
        if d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def load_summaries_for_session(
    session_id: str,
    palace_texts: Optional[Dict[str, List[str]]],
    wakeup_index: object,
    store_path: Optional[str] = None,
    regenerate_if_missing: bool = False,
    l0_tokens: int = 170,
    l1_tokens: int = 450,
    l0_priority: float = 10.0,
    l1_priority: float = 5.0,
) -> int:
    """Load L0/L1 summaries into `wakeup_index` for a session.

    Behavior:
      - If `palace_texts` is provided, prefer persisted summaries but
        regenerate when `regenerate_if_missing` is True.
      - If `palace_texts` is None or empty, load any persisted summaries
        found at `store_path` and add them to the wakeup index.

    Returns the number of facts added.
    """
    added = 0
    persisted = read_persisted_summaries(store_path)

    # If caller didn't provide palace_texts, load all persisted entries (best-effort)
    if not palace_texts:
        for palace_id, entry in (persisted or {}).items():
            L0 = entry.get("L0")
            L1 = entry.get("L1")
            try:
                if L0:
                    key0 = f"{palace_id}_L0"
                    wakeup_index.add_fact(
                        session_id=session_id,
                        key=key0,
                        text=L0,
                        metadata={"palace_id": palace_id, "level": "L0"},
                        ttl=None,
                        priority=float(l0_priority),
                    )
                    added += 1
                if L1:
                    key1 = f"{palace_id}_L1"
                    wakeup_index.add_fact(
                        session_id=session_id,
                        key=key1,
                        text=L1,
                        metadata={"palace_id": palace_id, "level": "L1"},
                        ttl=None,
                        priority=float(l1_priority),
                    )
                    added += 1
            except Exception:
                continue
        return added

    # Otherwise, iterate the provided palace_texts and prefer persisted values
    for palace_id, texts in (palace_texts or {}).items():
        L0 = None
        L1 = None
        if palace_id in persisted:
            entry = persisted.get(palace_id, {})
            L0 = entry.get("L0")
            L1 = entry.get("L1")

        if not L0 and regenerate_if_missing and texts:
            L0 = generate_l0_summary(texts, max_tokens=l0_tokens)
            L1 = generate_l1_summary(texts, max_tokens=l1_tokens)
            try:
                persist_summaries(palace_id, L0, L1, store_path=store_path)
            except Exception:
                pass

        # add to wakeup index as high-priority short facts
        try:
            if L0:
                key0 = f"{palace_id}_L0"
                wakeup_index.add_fact(
                    session_id=session_id,
                    key=key0,
                    text=L0,
                    metadata={"palace_id": palace_id, "level": "L0"},
                    ttl=None,
                    priority=float(l0_priority),
                )
                added += 1
            if L1:
                key1 = f"{palace_id}_L1"
                wakeup_index.add_fact(
                    session_id=session_id,
                    key=key1,
                    text=L1,
                    metadata={"palace_id": palace_id, "level": "L1"},
                    ttl=None,
                    priority=float(l1_priority),
                )
                added += 1
        except Exception:
            # best-effort: continue loading other summaries
            continue

    return added


__all__ = [
    "generate_l0_summary",
    "generate_l1_summary",
    "persist_summaries",
    "read_persisted_summaries",
    "load_summaries_for_session",
]
