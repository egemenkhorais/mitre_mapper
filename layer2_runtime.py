from __future__ import annotations

import argparse
import html
import json
import logging
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import unquote_plus

import joblib
import numpy as np

LOGGER = logging.getLogger("layer2")

DEFAULT_MODEL_PATH = os.getenv(
    "LAYER2_MODEL_PATH",
    "models/layer2_payload_classifier.joblib",
)
DEFAULT_THRESHOLD = float(os.getenv("LAYER2_THRESHOLD", "0.80"))
DEFAULT_MAX_PAYLOAD_LENGTH = int(
    os.getenv("LAYER2_MAX_PAYLOAD_LENGTH", "16384")
)

# Only these headers are accepted. Secrets such as Cookie and Authorization
# are intentionally excluded.
DEFAULT_ALLOWED_HEADERS = {
    "content-type",
    "user-agent",
    "referer",
    "x-requested-with",
}


@dataclass(frozen=True)
class Layer2Result:
    status: str
    label: str | None
    raw_label: str | None
    confidence: float | None
    threshold: float
    payload_length: int
    reason: str | None = None
    score: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_SQLI_REGEX = re.compile(
    r"('|\")\s*(--|#|/\*)"
    r"|(\b(union\s+(all\s+)?select|select\s+.+\s+from|insert\s+into|drop\s+table|update\s+.+\s+set|information_schema|sleep\s*\(|benchmark\s*\(|waitfor\s+delay)\b)"
    r"|(\b(or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)"
    r"|(\badmin['\"]\s*(--|#))"
    r"|('\s*(or|and)\s*')",
    re.IGNORECASE,
)

_XSS_REGEX = re.compile(
    r"(<\s*script\b|javascript\s*:|on(error|load|mouseover|focus|click)\s*=|<\s*(img|svg|iframe|body)\b[^>]*\bon\w+\s*=|\balert\s*\()",
    re.IGNORECASE,
)

_TRAVERSAL_REGEX = re.compile(
    r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini|win\.ini|/proc/self/)",
    re.IGNORECASE,
)

_CMD_INJECTION_REGEX = re.compile(
    r"(;|\|\||&&|\|)\s*(cat|ls|whoami|id|uname|curl|wget|nc|bash|sh|powershell)\b|\$\([^)]+\)",
    re.IGNORECASE,
)


def _heuristic_payload_check(text: str) -> tuple[str | None, float, str | None]:
    """
    ML modeli TF-IDF vektörleştiricisi olmadan kaydedildiyse veya düşük güven
    verdiyse, bariz SQLi / XSS / Path Traversal / Command Injection imzalarını
    kaçırmamak için deterministik güvenlik ağı.
    """
    if not text:
        return None, 0.0, None

    if _SQLI_REGEX.search(text):
        return "sql_injection", 0.96, "Matched SQL Injection payload signature"
    if _XSS_REGEX.search(text):
        return "xss", 0.95, "Matched Cross-Site Scripting (XSS) signature"
    if _TRAVERSAL_REGEX.search(text):
        return "path_traversal", 0.95, "Matched Path Traversal signature"
    if _CMD_INJECTION_REGEX.search(text):
        return "command_injection", 0.94, "Matched Command Injection signature"

    return None, 0.0, None


class Layer2PayloadClassifier:
    """Runtime wrapper for the trained Layer 2 payload classifier."""

    def __init__(
        self,
        model_path: str | Path = DEFAULT_MODEL_PATH,
        confidence_threshold: float = DEFAULT_THRESHOLD,
        max_payload_length: int = DEFAULT_MAX_PAYLOAD_LENGTH,
        decode_payload: bool = True,
    ) -> None:
        self.model_path = Path(model_path)
        self.confidence_threshold = float(confidence_threshold)
        self.max_payload_length = int(max_payload_length)
        self.decode_payload = bool(decode_payload)
        self.vectorizer = None
        self.label_encoder = None

        if not 0.0 <= self.confidence_threshold <= 1.0:
            raise ValueError("confidence_threshold must be between 0 and 1")
        if self.max_payload_length <= 0:
            raise ValueError("max_payload_length must be greater than zero")
        if not self.model_path.is_file():
            raise FileNotFoundError(
                f"Layer 2 model not found: {self.model_path.resolve()}"
            )

        artifact = joblib.load(model_path)

        # If the artifact is a dictionary, unpack the components
        if isinstance(artifact, dict):
            self.model = (
                artifact.get("pipeline")
                or artifact.get("model")
                or artifact.get("classifier")
                or artifact.get("clf")
            )
            self.vectorizer = (
                artifact.get("vectorizer")
                or artifact.get("tfidf")
                or artifact.get("feature_extractor")
            )
            self.label_encoder = (
                artifact.get("label_encoder")
                or artifact.get("encoder")
            )
        else:
            self.model = artifact

        if not hasattr(self.model, "predict"):
            raise TypeError("Model artifact does not provide predict()")

        self.classes = self._get_classes()
        LOGGER.info(
            "Layer 2 loaded: model=%s threshold=%.2f classes=%s",
            self.model_path,
            self.confidence_threshold,
            self.classes,
        )

    def _get_classes(self) -> list[str]:
        if self.label_encoder is not None and hasattr(self.label_encoder, "classes_"):
            return [str(v) for v in self.label_encoder.classes_]
        if hasattr(self.model, "classes_"):
            values = self.model.classes_
        elif (
            hasattr(self.model, "named_steps")
            and "clf" in self.model.named_steps
            and hasattr(self.model.named_steps["clf"], "classes_")
        ):
            values = self.model.named_steps["clf"].classes_
        else:
            raise TypeError("Could not read classes from model artifact")
        return [str(value) for value in values]

    def _normalize(self, payload: str | bytes) -> str:
        if isinstance(payload, bytes):
            text = payload.decode("utf-8", errors="replace")
        else:
            text = str(payload)

        text = text.replace("\x00", " ")
        text = html.unescape(text)
        if self.decode_payload:
            text = unquote_plus(text)
        text = " ".join(text.split())
        return text[: self.max_payload_length]

    @staticmethod
    def _safe_headers(
        headers: Mapping[str, Any] | None,
        allowed_headers: set[str] | None = None,
    ) -> dict[str, str]:
        if not headers:
            return {}
        allowed = allowed_headers or DEFAULT_ALLOWED_HEADERS
        return {
            str(key).lower(): str(value)
            for key, value in headers.items()
            if str(key).lower() in allowed
        }

    def classify(self, payload: str | bytes | None) -> Layer2Result:
        if payload is None:
            return Layer2Result(
                status="payload_unavailable",
                label=None,
                raw_label=None,
                confidence=None,
                threshold=self.confidence_threshold,
                payload_length=0,
                reason="Payload is None",
                score=0,
            )

        normalized = self._normalize(payload)
        if not normalized:
            return Layer2Result(
                status="payload_unavailable",
                label=None,
                raw_label=None,
                confidence=None,
                threshold=self.confidence_threshold,
                payload_length=0,
                reason="Payload is empty after normalization",
                score=0,
            )

        heur_label, heur_conf, heur_reason = _heuristic_payload_check(normalized)

        raw_label = None
        confidence = None

        try:
            X_input = (
                self.vectorizer.transform([normalized])
                if self.vectorizer is not None
                else [normalized]
            )
            pred = self.model.predict(X_input)[0]
            if self.label_encoder is not None:
                try:
                    raw_label = str(self.label_encoder.inverse_transform([pred])[0])
                except Exception:
                    raw_label = str(pred)
            else:
                raw_label = str(pred)

            probabilities = np.asarray(
                self.model.predict_proba(X_input)[0], dtype=float
            )
            confidence = float(np.max(probabilities))
        except Exception as exc:
            LOGGER.debug("Layer 2 ML predict fallback to heuristic: %s", exc)

        # Eğer deterministik imza (SQLi/XSS/Traversal/CmdInj) yakalandıysa:
        if heur_label is not None:
            final_conf = max(float(confidence or 0.0), heur_conf)
            return Layer2Result(
                status="classified",
                label=heur_label,
                raw_label=raw_label or heur_label,
                confidence=final_conf,
                threshold=self.confidence_threshold,
                payload_length=len(normalized),
                reason=heur_reason,
                score=int(round(final_conf * 40)),
            )

        # ML modeli vectorizer eksikliği vb. nedeniyle çalışmadıysa ve imza da temizse:
        if raw_label is None or confidence is None:
            return Layer2Result(
                status="classified",
                label="benign",
                raw_label="benign",
                confidence=0.90,
                threshold=self.confidence_threshold,
                payload_length=len(normalized),
                reason="No exploit signature found in HTTP request",
                score=0,
            )

        is_non_attack = raw_label.strip().lower() in {
            "benign",
            "normal",
            "none",
            "0",
        }
        attack_score = 0 if is_non_attack else int(round(confidence * 40))

        if confidence < self.confidence_threshold:
            return Layer2Result(
                status="abstain",
                label="benign" if is_non_attack else "unknown_web_attack",
                raw_label=raw_label,
                confidence=confidence,
                threshold=self.confidence_threshold,
                payload_length=len(normalized),
                reason="Prediction confidence is below threshold",
                score=0,
            )

        return Layer2Result(
            status="classified",
            label=raw_label,
            raw_label=raw_label,
            confidence=confidence,
            threshold=self.confidence_threshold,
            payload_length=len(normalized),
            score=attack_score,
        )

    def classify_http_request(
        self,
        *,
        method: str | None = None,
        path: str | None = None,
        query: str | None = None,
        body: str | bytes | None = None,
        headers: Mapping[str, Any] | None = None,
    ) -> Layer2Result:
        parts: list[str] = []
        if method:
            parts.append(f"METHOD={method}")
        if path:
            parts.append(f"PATH={path}")
        if query:
            parts.append(f"QUERY={query}")

        for key, value in sorted(self._safe_headers(headers).items()):
            parts.append(f"HEADER_{key.upper()}={value}")

        if body:
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")
            parts.append(f"BODY={body}")

        return self.classify("\n".join(parts))


def should_run_layer2(layer1_label: str | None) -> bool:
    if not layer1_label:
        return False
    normalized = str(layer1_label).strip().lower().replace("-", "_")
    return normalized in {"web attack", "web_attack", "webattack"}


def enrich_layer1_event(
    event: dict[str, Any],
    classifier: Layer2PayloadClassifier,
    *,
    method: str | None = None,
    path: str | None = None,
    query: str | None = None,
    body: str | bytes | None = None,
    headers: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Add Layer 2 output to an existing Layer 1 event dictionary."""
    layer1 = event.get("layer1", {})
    layer1_label = layer1.get("label") or event.get("layer1_label")

    if not should_run_layer2(layer1_label):
        event["routing_decision"] = "layer1_complete"
        return event

    result = classifier.classify_http_request(
        method=method,
        path=path,
        query=query,
        body=body,
        headers=headers,
    )
    event["layer2"] = result.to_dict()

    if result.status == "payload_unavailable":
        event["routing_decision"] = "payload_required"
    elif result.status == "abstain":
        event["routing_decision"] = "send_to_local_llm"
    else:
        event["routing_decision"] = "mitre_enrichment"

    return event


def _cli() -> None:
    parser = argparse.ArgumentParser(description="Layer 2 payload classifier")
    parser.add_argument("--model", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument("--payload")
    parser.add_argument("--request-json")
    args = parser.parse_args()

    classifier = Layer2PayloadClassifier(
        model_path=args.model,
        confidence_threshold=args.threshold,
    )

    if args.request_json:
        request = json.loads(Path(args.request_json).read_text(encoding="utf-8"))
        result = classifier.classify_http_request(
            method=request.get("method"),
            path=request.get("path"),
            query=request.get("query"),
            body=request.get("body"),
            headers=request.get("headers"),
        )
    elif args.payload is not None:
        result = classifier.classify(args.payload)
    else:
        parser.error("Specify --payload or --request-json")

    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _cli()
