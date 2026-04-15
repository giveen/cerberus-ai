"""Embeddings provider abstraction and concrete implementations.

Provides a deterministic, batched, and optionally cached embeddings
provider interface so different RAG backends (Qdrant, MemPalace, etc.)
can share a single, reproducible embeddings implementation.

The default provider is a lightweight, dependency-free
`LocalDeterministicEmbeddingsProvider` which produces stable vectors
derived from a hash of the input text and a seed. An OpenAI-backed
provider is included as `OpenAIEmbeddingsProvider` and will be used
when `CERBERUS_EMBEDDINGS_PROVIDER` is set to `openai` and the runtime has
an OpenAI key and package available.
"""
from __future__ import annotations

import hashlib
import math
import os
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class EmbeddingsConfig:
    model_name: str = "local-deterministic"
    batch_size: int = 16
    normalize: bool = True
    deterministic_seed: int = 42
    cache_enabled: bool = True
    cache_max_size: int = 10000
    vector_dim: int = 384


class EmbeddingsProvider:
    """Abstract embeddings provider.

    Implementations must provide `embed_texts` that returns a list of
    numeric vectors (list[float]) for the corresponding input texts.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        if isinstance(cfg, EmbeddingsConfig):
            self.config = cfg
        else:
            self.config = EmbeddingsConfig(**cfg)

    def embed_texts(self, texts: List[str]) -> List[List[float]]:
        raise NotImplementedError()

    def embed_text(self, text: str) -> List[float]:
        return self.embed_texts([text])[0]


class LocalDeterministicEmbeddingsProvider(EmbeddingsProvider):
    """Deterministic embeddings computed from a hash of the text.

    Produces reproducible vectors across runs and machines given the
    same `deterministic_seed` and `vector_dim`. This is intentionally
    dependency-free and useful for testing, local dev, and deterministic
    retrieval comparisons.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config=config)
        self._cache: "OrderedDict[str, List[float]]" = OrderedDict()

    def _make_vector(self, text: str) -> List[float]:
        dim = int(self.config.vector_dim)
        seed = int(self.config.deterministic_seed)
        out: List[float] = []
        counter = 0
        text_bytes = text.encode("utf-8")
        seed_bytes = str(seed).encode("utf-8")
        # Expand hash material until we have enough floats
        while len(out) < dim:
            hasher = hashlib.sha256()
            hasher.update(seed_bytes)
            hasher.update(b"|")
            hasher.update(counter.to_bytes(4, "big", signed=False))
            hasher.update(b"|")
            hasher.update(text_bytes)
            digest = hasher.digest()
            # Use 4-byte chunks to produce floats in [-1,1]
            for i in range(0, len(digest), 4):
                if len(out) >= dim:
                    break
                chunk = digest[i : i + 4]
                ival = int.from_bytes(chunk, "big", signed=False)
                f = (ival / 0xFFFFFFFF) * 2.0 - 1.0
                out.append(f)
            counter += 1

        if self.config.normalize:
            # L2 normalize
            norm = math.sqrt(sum(x * x for x in out)) or 1.0
            out = [x / norm for x in out]
        return out

    def embed_texts(self, texts: List[str]) -> List[List[float]]:
        batch_size = max(1, int(self.config.batch_size))
        results: List[List[float]] = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            for t in batch:
                if self.config.cache_enabled:
                    vec = self._cache.get(t)
                    if vec is not None:
                        # move to end for LRU
                        self._cache.move_to_end(t)
                        results.append(vec)
                        continue
                vec = self._make_vector(t)
                if self.config.cache_enabled:
                    self._cache[t] = vec
                    # enforce max size
                    if len(self._cache) > int(self.config.cache_max_size):
                        self._cache.popitem(last=False)
                results.append(vec)
        return results


class OpenAIEmbeddingsProvider(EmbeddingsProvider):
    """OpenAI-backed embeddings provider.

    Tries to use the `openai` package if available and `OPENAI_API_KEY`
    is set in the environment. Batching is handled according to
    `EmbeddingsConfig.batch_size`.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config=config)
        # lazy import of openai to avoid hard dependency at module import
        try:
            import openai  # type: ignore

            self._openai = openai
        except Exception as exc:  # pragma: no cover - environment dependent
            raise RuntimeError("openai package is required for OpenAIEmbeddingsProvider") from exc

        if not (os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_KEY")):
            # allow service account style keys or other env names in practice
            # but make the error clear
            raise RuntimeError("OPENAI_API_KEY environment variable is not set")

    def embed_texts(self, texts: List[str]) -> List[List[float]]:
        # Use model name from config
        model = self.config.model_name
        batch_size = max(1, int(self.config.batch_size))
        out: List[List[float]] = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            # The OpenAI python client has changed shapes; use the v1 embeddings API
            res = self._openai.Embedding.create(input=batch, model=model)
            # response.data is a list with embedding vectors
            for item in res.get("data", []):
                out.append(item.get("embedding"))
        return out


_PROVIDERS: Dict[str, Any] = {
    "local": LocalDeterministicEmbeddingsProvider,
    "local-deterministic": LocalDeterministicEmbeddingsProvider,
    "deterministic": LocalDeterministicEmbeddingsProvider,
    "openai": OpenAIEmbeddingsProvider,
    "cuda": None,  # registered below after class definition
    "sentence-transformers": None,
}


class CUDAEmbeddingsProvider(EmbeddingsProvider):
    """Sentence-transformers provider with explicit RTX 5090 / CUDA device mapping.

    Processes texts in large batches suitable for cold-start indexing of
    10,000+ chunks in parallel on the GPU. Falls back to CPU then to the
    ``LocalDeterministicEmbeddingsProvider`` when sentence-transformers
    or CUDA is unavailable.

    Set ``CERBERUS_CUDA_MODEL`` env var to choose the ST model
    (default: ``BAAI/bge-m3``).
    """

    _DEFAULT_CUDA_BATCH: int = 256

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config=config)
        self._model: Optional[Any] = None
        self._device: str = "cpu"
        self._load_model()

    def _load_model(self) -> None:
        """Lazy-load the sentence-transformer model onto CUDA when available."""
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
            import torch  # type: ignore

            device = "cuda:0" if torch.cuda.is_available() else "cpu"
            model_name = self.config.model_name
            if model_name in ("local-deterministic", "local", "cuda", "sentence-transformers"):
                model_name = os.getenv("CERBERUS_CUDA_MODEL", "BAAI/bge-m3")
            self._model = SentenceTransformer(model_name, device=device)
            self._device = device
        except Exception:
            self._model = None
            self._device = "cpu"

    def embed_texts(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []
        if self._model is None:
            _cfg = {
                "vector_dim": self.config.vector_dim,
                "batch_size": self.config.batch_size,
                "normalize": self.config.normalize,
                "deterministic_seed": self.config.deterministic_seed,
            }
            return LocalDeterministicEmbeddingsProvider(config=_cfg).embed_texts(texts)
        batch_size = max(self._DEFAULT_CUDA_BATCH, int(self.config.batch_size))
        results: List[List[float]] = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            encoded = self._model.encode(
                batch,
                batch_size=batch_size,
                show_progress_bar=False,
                normalize_embeddings=bool(self.config.normalize),
                convert_to_numpy=True,
            )
            results.extend(row.tolist() for row in encoded)
        return results

    @property
    def device(self) -> str:
        """Returns the active torch device string (e.g. ``'cuda:0'`` or ``'cpu'``)."""
        return self._device


# Register CUDA provider now that the class is defined
_PROVIDERS["cuda"] = CUDAEmbeddingsProvider
_PROVIDERS["sentence-transformers"] = CUDAEmbeddingsProvider

def get_embeddings_provider(name: Optional[str] = None, config: Optional[Dict[str, Any]] = None) -> EmbeddingsProvider:
    """Factory that returns an `EmbeddingsProvider` instance.

    If `name` is not provided, the environment variable
    `CERBERUS_EMBEDDINGS_PROVIDER` is consulted. When unset, prefer OpenAI if
    an API key is present; otherwise fall back to the local deterministic
    provider.
    """
    chosen = (name or os.getenv("CERBERUS_EMBEDDINGS_PROVIDER") or "").lower()
    if not chosen:
        if os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_KEY"):
            chosen = "openai"
        else:
            chosen = "local-deterministic"

    if chosen not in _PROVIDERS:
        raise ValueError(f"Unknown embeddings provider: {chosen}")

    cls = _PROVIDERS[chosen]
    return cls(config=config)


__all__ = [
    "CUDAEmbeddingsProvider",
    "EmbeddingsConfig",
    "EmbeddingsProvider",
    "LocalDeterministicEmbeddingsProvider",
    "OpenAIEmbeddingsProvider",
    "get_embeddings_provider",
]
