"""
Cerberus Multi-Agent Pipeline — MITRE ATT&CK RAG Engine
=========================================================
Performs TF-IDF keyword/semantic retrieval over the locally bundled
MITRE ATT&CK Enterprise technique knowledge base (data/mitre_attack.json).

Returns the top-K most relevant techniques for a given alert context
including Technique ID, name, tactics, description, and detection notes.
"""

import json
import os
import re

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

_DEFAULT_DATA = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "mitre_attack.json"
)


class RAGEngine:
    """
    Lightweight MITRE ATT&CK Retrieval-Augmented Generation engine.
    Builds a TF-IDF index on startup and supports fast similarity search.
    """

    def __init__(self, mitre_path: str | None = None):
        path = mitre_path or os.getenv("MITRE_DATA_PATH", _DEFAULT_DATA)
        self._techniques: list[dict] = []
        self._corpus: list[str] = []
        self._vectorizer: TfidfVectorizer | None = None
        self._matrix = None
        self._ready = False
        self._load(path)

    def _load(self, path: str) -> None:
        """Load and index MITRE techniques from JSON."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._techniques = data.get("techniques", [])

            # Build composite corpus: name + tactics + description + detection
            self._corpus = [
                " ".join([
                    t.get("id", ""),
                    t.get("name", ""),
                    " ".join(t.get("tactics", [])),
                    t.get("description", ""),
                    t.get("detection", ""),
                ]).lower()
                for t in self._techniques
            ]

            if self._corpus:
                self._vectorizer = TfidfVectorizer(
                    max_features=8000,
                    ngram_range=(1, 2),
                    sublinear_tf=True,
                    stop_words="english",
                )
                self._matrix = self._vectorizer.fit_transform(self._corpus)
                self._ready = True
        except Exception as exc:
            print(f"[RAGEngine] Failed to load MITRE data: {exc}")

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def technique_count(self) -> int:
        return len(self._techniques)

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        """
        Returns the top-K MITRE ATT&CK techniques most relevant to the query.
        Each result contains: id, name, tactics, description, detection.
        """
        if not self._ready or not query.strip():
            return []

        top_k = int(os.getenv("RAG_TOP_K", str(top_k)))

        try:
            query_vec = self._vectorizer.transform([query.lower()])  # type: ignore[union-attr]
            scores = cosine_similarity(query_vec, self._matrix).flatten()
            top_indices = np.argsort(scores)[::-1][:top_k]

            results = []
            for idx in top_indices:
                if scores[idx] < 0.01:
                    continue  # Skip near-zero relevance matches
                tech = self._techniques[idx]
                results.append({
                    "id":          tech.get("id", ""),
                    "name":        tech.get("name", ""),
                    "tactics":     tech.get("tactics", []),
                    "description": tech.get("description", "")[:600],
                    "detection":   tech.get("detection", "")[:400],
                    "platforms":   tech.get("platforms", []),
                    "score":       round(float(scores[idx]), 4),
                })
            return results
        except Exception as exc:
            print(f"[RAGEngine] Search error: {exc}")
            return []

    def format_for_prompt(self, results: list[dict]) -> str:
        """Formats RAG results into a concise, LLM-readable context block."""
        if not results:
            return "No relevant MITRE ATT&CK techniques found."

        lines = []
        for r in results:
            tactics = ", ".join(r.get("tactics", [])) or "Unknown"
            lines.append(
                f"[{r['id']}] {r['name']} | Tactics: {tactics}\n"
                f"  Description: {r['description'][:300]}...\n"
                f"  Detection:   {r['detection'][:200]}"
            )
        return "\n\n".join(lines)


# Singleton instance shared across all agents
_rag_engine: RAGEngine | None = None


def get_rag_engine() -> RAGEngine:
    global _rag_engine
    if _rag_engine is None:
        _rag_engine = RAGEngine()
    return _rag_engine
