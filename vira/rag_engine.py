"""
RAG Engine: Semantic & Keyword Hybrid Knowledge Base Retriever.
Indexes MITRE ATT&CK Enterprise Matrix & NIST Incident Playbooks.
"""
import os
import json
from typing import List, Optional, Tuple
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .models import RAGSearchResult, PlaybookMatch


class SecOpsRAGEngine:
    """Retrieval-Augmented Generation engine for Cybersecurity threat intelligence."""

    def __init__(self, data_dir: Optional[str] = None):
        if data_dir is None:
            data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
        self.data_dir = data_dir
        self.mitre_kb_file = os.path.join(data_dir, "mitre_attack_kb.json")
        self.playbooks_file = os.path.join(data_dir, "incident_playbooks.json")

        self.mitre_entries = []
        self.playbook_entries = []

        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
        self.kb_corpus = []
        self.kb_matrix = None

        self._load_knowledge_base()

    def _load_knowledge_base(self):
        """Loads and indexes the MITRE ATT&CK entries and incident playbooks."""
        if not os.path.exists(self.mitre_kb_file):
            raise FileNotFoundError(f"MITRE KB file not found at {self.mitre_kb_file}")

        with open(self.mitre_kb_file, "r", encoding="utf-8") as f:
            self.mitre_entries = json.load(f)

        if os.path.exists(self.playbooks_file):
            with open(self.playbooks_file, "r", encoding="utf-8") as f:
                self.playbook_entries = json.load(f)

        # Build corpus for TF-IDF vectorization
        self.kb_corpus = []
        for entry in self.mitre_entries:
            combined_text = (
                f"{entry['technique_id']} {entry['name']} {entry['tactic']} "
                f"{entry['description']} {' '.join(entry.get('keywords', []))} "
                f"{entry.get('detection', '')} {entry.get('mitigation', '')}"
            )
            self.kb_corpus.append(combined_text)

        self.kb_matrix = self.vectorizer.fit_transform(self.kb_corpus)

    def search_mitre(self, query: str, top_k: int = 3) -> List[RAGSearchResult]:
        """Hybrid search combining TF-IDF cosine similarity with keyword boosting."""
        if not query.strip():
            return []

        query_vec = self.vectorizer.transform([query])
        sim_scores = cosine_similarity(query_vec, self.kb_matrix)[0]

        query_lower = query.lower()
        scored_results: List[Tuple[float, dict, List[str]]] = []

        for idx, entry in enumerate(self.mitre_entries):
            score = float(sim_scores[idx])
            matched_keywords = []

            # Exact Technique ID boost
            if entry["technique_id"].lower() in query_lower:
                score += 0.40
                matched_keywords.append(entry["technique_id"])

            # Technique name boost
            if entry["name"].lower() in query_lower:
                score += 0.25
                matched_keywords.append(entry["name"])

            # Keyword matches
            for kw in entry.get("keywords", []):
                if kw.lower() in query_lower:
                    score += 0.15
                    matched_keywords.append(kw)

            # Cap score at 1.0
            final_score = min(round(score, 4), 1.0)
            scored_results.append((final_score, entry, matched_keywords))

        # Sort by score descending
        scored_results.sort(key=lambda x: x[0], reverse=True)

        results: List[RAGSearchResult] = []
        for score, entry, matched_kws in scored_results[:top_k]:
            results.append(
                RAGSearchResult(
                    technique_id=entry["technique_id"],
                    technique_name=entry["name"],
                    tactic=entry["tactic"],
                    relevance_score=score,
                    description=entry["description"],
                    detection_guidance=entry.get("detection", ""),
                    mitigation_guidance=entry.get("mitigation", ""),
                    matched_keywords=list(set(matched_kws))
                )
            )

        return results

    def get_playbook_for_technique(self, technique_id: str) -> Optional[PlaybookMatch]:
        """Retrieves NIST incident playbook mapped to the given MITRE technique ID."""
        tech_prefix = technique_id.split(".")[0]
        for pb in self.playbook_entries:
            trigger = pb.get("trigger_technique", "")
            if trigger == technique_id or trigger.startswith(tech_prefix):
                return PlaybookMatch(
                    playbook_id=pb["playbook_id"],
                    name=pb["name"],
                    severity_baseline=pb.get("severity_baseline", "HIGH"),
                    containment_steps=pb.get("containment_steps", []),
                    verification_query=pb.get("verification_query", ""),
                    automated_action_type=pb.get("automated_action_type", "GENERIC_INVESTIGATION")
                )
        return None
