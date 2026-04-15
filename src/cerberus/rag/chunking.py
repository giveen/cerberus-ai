"""Text chunking and fingerprinting helpers for RAG ingestion.

Provides deterministic chunking (size + overlap) and stable
fingerprinting combining content hash and an embedding fingerprint.
"""
from __future__ import annotations

import hashlib
import struct
import re
from typing import Any, Dict, List, Optional, Tuple


def chunk_text(text: str, chunk_size: int = 1000, overlap: int = 200) -> List[Dict[str, Any]]:
    """Deterministically chunk ``text`` into pieces.

    Returns a list of dicts: {"text": str, "start": int, "end": int, "index": int}
    """
    if text is None:
        return []
    txt = str(text).strip()
    if not txt:
        return []
    try:
        chunk_size = int(chunk_size)
        overlap = int(overlap)
    except Exception:
        chunk_size = 1000
        overlap = 200
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")
    step = max(1, chunk_size - max(0, overlap))

    out: List[Dict[str, Any]] = []
    start = 0
    idx = 0
    L = len(txt)
    while start < L:
        end = start + chunk_size
        chunk = txt[start:end]
        out.append({"text": chunk, "start": start, "end": min(end, L), "index": idx})
        idx += 1
        start += step
    return out


def _embed_fingerprint_from_vec(vec: List[float]) -> Optional[str]:
    """Deterministically compute a hex fingerprint from an embedding vector.

    Packs floats as big-endian doubles and hashes the byte sequence.
    Returns hex digest or None on failure.
    """
    if vec is None:
        return None
    try:
        b = b"".join(struct.pack(
            ">d", float(v)
        ) for v in vec)
        return hashlib.sha256(b).hexdigest()
    except Exception:
        # Fallback: hash the repr string
        try:
            return hashlib.sha256(repr(vec).encode("utf-8")).hexdigest()
        except Exception:
            return None


def fingerprint_chunks(
    chunks: List[Dict[str, Any]],
    embeddings: Optional[List[List[float]]] = None,
) -> List[Dict[str, Any]]:
    """Given chunk dicts and optional embeddings, compute fingerprints.

    Each returned dict augments the chunk with keys:
      - content_hash: sha256 hex of text
      - embed_fingerprint: sha256 hex of embedding bytes (if embeddings provided)
      - fingerprint: combined "content:embed" when both present, else content_hash
      - chunk_id: a stable id derived from content_hash + index
    """
    out: List[Dict[str, Any]] = []
    for i, c in enumerate(chunks):
        txt = c.get("text", "")
        try:
            content_hash = hashlib.sha256(txt.encode("utf-8")).hexdigest()
        except Exception:
            content_hash = None

        embed_fp = None
        if embeddings is not None and i < len(embeddings):
            embed_fp = _embed_fingerprint_from_vec(embeddings[i])

        if content_hash and embed_fp:
            fingerprint = f"{content_hash}:{embed_fp}"
        else:
            fingerprint = content_hash

        chunk_id = f"{content_hash}-{i}" if content_hash else f"chunk-{i}"

        new = dict(c)
        new.update({
            "content_hash": content_hash,
            "embed_fingerprint": embed_fp,
            "fingerprint": fingerprint,
            "chunk_id": chunk_id,
        })
        out.append(new)
    return out


__all__ = ["chunk_text", "fingerprint_chunks"]


# ---------------------------------------------------------------------------
# Logic-Aware Chunking
# ---------------------------------------------------------------------------

_PY_BLOCK_START = re.compile(r"^(def |class )", re.MULTILINE)
_NMAP_HOST = re.compile(r"^Nmap scan report for ", re.MULTILINE)
_LOG_TS = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
_XML_TAG = re.compile(r"^<[a-zA-Z]")


def _detect_block_type(text: str) -> str:
    t = text.lstrip()
    if t.startswith("def ") or t.startswith("class "):
        return "python"
    if "Nmap scan report for" in text[:60]:
        return "nmap"
    if t.startswith("```"):
        return "code_fence"
    if _LOG_TS.match(t):
        return "log"
    if _XML_TAG.match(t):
        return "xml"
    if t.startswith("{") or t.startswith("["):
        return "json"
    return "prose"


def _split_into_blocks(text: str) -> List[str]:
    """Split text on recognised semantic boundaries."""
    lines = text.splitlines(keepends=True)
    if not lines:
        return []
    blocks: List[str] = []
    current: List[str] = []
    in_fence = False

    def _flush() -> None:
        if current:
            blocks.append("".join(current))
            current.clear()

    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("```"):
            if not in_fence:
                _flush()
                in_fence = True
                current.append(line)
            else:
                current.append(line)
                in_fence = False
                _flush()
            continue
        if in_fence:
            current.append(line)
            continue
        if _PY_BLOCK_START.match(line):
            _flush()
            current.append(line)
            continue
        if _NMAP_HOST.match(line):
            _flush()
            current.append(line)
            continue
        # blank line is a soft paragraph boundary
        if not stripped:
            current.append(line)
            _flush()
            continue
        current.append(line)

    _flush()
    return [b for b in blocks if b.strip()]


def _merge_and_split_blocks(
    blocks: List[str],
    max_chunk_size: int = 4000,
    overlap_lines: int = 2,
) -> List[str]:
    """Merge small blocks up to ``max_chunk_size``; split oversized ones."""
    result: List[str] = []
    bucket = ""
    for block in blocks:
        if len(block) > max_chunk_size:
            if bucket.strip():
                result.append(bucket)
                bucket = ""
            sub_lines = block.splitlines(keepends=True)
            chunk_lines: List[str] = []
            char_count = 0
            for line in sub_lines:
                if char_count + len(line) > max_chunk_size and chunk_lines:
                    result.append("".join(chunk_lines))
                    chunk_lines = chunk_lines[-overlap_lines:] if overlap_lines else []
                    char_count = sum(len(ln) for ln in chunk_lines)
                chunk_lines.append(line)
                char_count += len(line)
            if chunk_lines:
                result.append("".join(chunk_lines))
        elif len(bucket) + len(block) <= max_chunk_size:
            bucket += block
        else:
            if bucket.strip():
                result.append(bucket)
            bucket = block
    if bucket.strip():
        result.append(bucket)
    return result


def logic_aware_chunk(
    text: str,
    max_chunk_size: int = 4000,
    overlap_lines: int = 2,
) -> List[Dict[str, Any]]:
    """Chunk text by preserving semantic technical blocks.

    Recognises and keeps together:

    - Python functions/classes (``def``/``class`` at column 0)
    - Nmap host entries (``Nmap scan report for …``)
    - Markdown fenced code blocks (triple-backtick)
    - Timestamped log entries (ISO datetime prefix)
    - XML/JSON root objects

    Falls back to paragraph splitting then to character splitting for
    plain prose.  Returns the same dict schema as :func:`chunk_text`:
    ``{"text": str, "start": int, "end": int, "index": int, "block_type": str}``.
    """
    if not text:
        return []
    raw = str(text)
    blocks = _split_into_blocks(raw)
    merged = _merge_and_split_blocks(blocks, max_chunk_size=max_chunk_size, overlap_lines=overlap_lines)
    out: List[Dict[str, Any]] = []
    cursor = 0
    for i, block in enumerate(merged):
        idx = raw.find(block, cursor)
        if idx == -1:
            idx = cursor
        start = idx
        end = start + len(block)
        out.append({
            "text": block,
            "start": start,
            "end": end,
            "index": i,
            "block_type": _detect_block_type(block),
        })
        cursor = max(cursor, start + 1)
    return out


__all__ = ["chunk_text", "fingerprint_chunks", "logic_aware_chunk"]
