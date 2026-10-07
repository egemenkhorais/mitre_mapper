import math
import re
from collections import Counter

from mitre_db import build_attack_db


class MitreRetriever:
    """Local lexical MITRE ATT&CK retriever. Used by mitre_multi_retriever.py."""

    GENERIC_TERMS = {
        "possible", "potential", "suspected", "detected", "activity",
        "behavior", "behaviour", "internal", "external", "network",
        "host", "system", "traffic", "connection", "connections",
        "event", "events", "alert", "alerts", "attack", "malicious",
        "suspicious", "multiple", "high", "volume",
    }

    SYNONYMS = {
        "scan": {"scan", "scanning", "discovery", "enumeration", "probe", "probing"},
        "scanning": {"scan", "scanning", "discovery", "enumeration", "probe", "probing"},
        "discovery": {"discovery", "enumeration"},
        "lateral": {"lateral", "remote", "movement", "pivot", "pivoting"},
        "movement": {"lateral", "remote", "movement", "pivot", "pivoting"},
        "smb": {"smb", "share", "shares", "windows", "admin", "445"},
        "share": {"share", "shares", "smb", "admin"},
        "shares": {"share", "shares", "smb", "admin"},
        "credential": {"credential", "credentials", "password", "authentication"},
        "service": {"service", "services", "port", "ports"},
        "services": {"service", "services", "port", "ports"},
        "remote": {"remote", "lateral"},
        "host": {"host", "hosts", "system", "systems"},
    }

    FIELD_WEIGHTS = {
        "name": 5.0,
        "description": 1.0,
        "tactics": 2.5,
        "platforms": 1.0,
        "data_sources": 1.0,
    }

    def __init__(self):
        self.attack_db = build_attack_db()
        self.techniques = list(self.attack_db.values())
        self.documents = []
        self.document_frequency = Counter()

        for technique in self.techniques:
            document = self._prepare_document(technique)
            self.documents.append(document)
            for term in document["all_tokens"]:
                self.document_frequency[term] += 1

        self.document_count = max(len(self.documents), 1)

    @staticmethod
    def _normalize_text(value):
        if value is None:
            return ""
        if isinstance(value, (list, tuple, set)):
            value = " ".join(str(item) for item in value)
        value = str(value).lower().replace("_", " ").replace("-", " ")
        return re.sub(r"[^a-z0-9.]+", " ", value).strip()

    def _tokenize(self, value):
        return re.findall(r"[a-z0-9]+(?:\.[0-9]+)?", self._normalize_text(value))

    def _prepare_document(self, technique):
        name_text = self._normalize_text(technique.get("name", ""))

        name_tokens = set(self._tokenize(name_text))
        description_tokens = set(self._tokenize(technique.get("description", "")))
        tactics_tokens = set(self._tokenize(technique.get("tactics", [])))
        platform_tokens = set(self._tokenize(technique.get("platforms", [])))
        data_source_tokens = set(self._tokenize(
            technique.get("data_sources", technique.get("dataSources", []))
        ))

        return {
            "technique": technique,
            "name_text": name_text,
            "name_tokens": name_tokens,
            "description_tokens": description_tokens,
            "tactics_tokens": tactics_tokens,
            "platform_tokens": platform_tokens,
            "data_sources_tokens": data_source_tokens,
            "all_tokens": (
                name_tokens | description_tokens | tactics_tokens
                | platform_tokens | data_source_tokens
            ),
        }

    def _idf(self, term):
        frequency = self.document_frequency.get(term, 0)
        return math.log((self.document_count + 1) / (frequency + 1)) + 1.0

    def _expand_query_terms(self, query_terms):
        expanded = set(query_terms)
        for term in query_terms:
            expanded.update(self.SYNONYMS.get(term, set()))
        return expanded

    def _score_term(self, term, document):
        score = 0.0
        matched_fields = []
        multiplier = 0.15 if term in self.GENERIC_TERMS else 1.0
        term_idf = self._idf(term)

        field_mapping = {
            "name": document["name_tokens"],
            "description": document["description_tokens"],
            "tactics": document["tactics_tokens"],
            "platforms": document["platform_tokens"],
            "data_sources": document["data_sources_tokens"],
        }

        for field_name, field_tokens in field_mapping.items():
            if term in field_tokens:
                score += self.FIELD_WEIGHTS[field_name] * term_idf * multiplier
                matched_fields.append(field_name)

        return score, matched_fields

    def retrieve(self, query, top_k=10):
        if not query or top_k <= 0:
            return []

        normalized_query = self._normalize_text(query)
        original_terms = set(self._tokenize(normalized_query))
        if not original_terms:
            return []

        expanded_terms = self._expand_query_terms(original_terms)
        meaningful_terms = original_terms - self.GENERIC_TERMS
        results = []

        for document in self.documents:
            technique = document["technique"]
            total_score = 0.0
            matched_terms = set()
            matched_fields = set()

            for term in expanded_terms:
                term_score, term_fields = self._score_term(term, document)
                if term_score <= 0:
                    continue
                total_score += term_score
                matched_terms.add(term)
                matched_fields.update(term_fields)

            if normalized_query in document["name_text"]:
                total_score += 15.0

            name_matches = meaningful_terms & document["name_tokens"]
            if len(name_matches) >= 2:
                total_score += len(name_matches) * 4.0

            coverage = len(original_terms & document["all_tokens"]) / len(original_terms)

            if not (matched_terms - self.GENERIC_TERMS):
                total_score *= 0.05

            total_score *= 0.50 + coverage

            if total_score <= 0:
                continue

            results.append({
                "id": technique.get("id", ""),
                "name": technique.get("name", ""),
                "description": technique.get("description", ""),
                "tactics": technique.get("tactics", []),
                "platforms": technique.get("platforms", []),
                "match_score": round(total_score, 6),
                "query_coverage": round(coverage, 6),
                "matched_terms": sorted(matched_terms),
                "matched_fields": sorted(matched_fields),
            })

        results.sort(
            key=lambda item: (item["match_score"], item["query_coverage"]),
            reverse=True,
        )
        return results[:top_k]
