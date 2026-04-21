"""
LSTM sequence anomaly detector.
Learns normal event-sequence patterns from training logs.
Anomalous sequences score high due to high prediction error.
Falls back to n-gram transition scoring if PyTorch unavailable.
"""
import json
import logging
import math
import pickle
from collections import defaultdict
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)
SAVED_DIR = Path(__file__).parent / "saved" / "lstm"

# Canonical event types for feature encoding
EVENT_TYPES = [
    "login_success", "login_failure", "process_create", "process_terminate",
    "network_connect", "network_listen", "file_create", "file_modify",
    "file_delete", "registry_set", "registry_delete", "dns_query",
    "service_install", "service_start", "privilege_escalation", "other",
]
EVENT_DIM = len(EVENT_TYPES)
SEQ_LEN = 16  # events per window


class LSTMPredictor:
    """
    PyTorch LSTM trained to predict the next event in a normal sequence.
    High prediction error → anomalous sequence → high threat score.
    """

    def __init__(self):
        self._model = None
        self._trained = False
        self._ngram: dict = defaultdict(lambda: defaultdict(int))
        self._ngram_trained = False
        self._device = "cpu"
        self._load()

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, text: str) -> dict:
        events = self._parse_events(text)
        if len(events) < 2:
            return self._result(0, 0.0, "insufficient-events", {"event_count": len(events)})

        if self._trained and self._model is not None:
            return self._lstm_score(events)
        if self._ngram_trained:
            return self._ngram_score(events)
        return self._rule_score(events)

    def fit(self, log_texts: list[str]):
        """Train on a list of benign log strings."""
        all_events = []
        for t in log_texts:
            all_events.extend(self._parse_events(t))

        # Always train n-gram fallback
        self._fit_ngram(all_events)

        # Attempt PyTorch LSTM
        try:
            self._fit_lstm(all_events)
        except Exception as exc:
            logger.warning("[LSTM] PyTorch training failed: %s", exc)

    def is_trained(self) -> bool:
        return self._trained or self._ngram_trained

    # ── LSTM training / inference ─────────────────────────────────────────────

    def _fit_lstm(self, events: list[str]):
        import torch
        import torch.nn as nn

        sequences, targets = self._make_sequences(events)
        if len(sequences) < 32:
            return

        X = torch.tensor(sequences, dtype=torch.float32)
        Y = torch.tensor(targets, dtype=torch.float32)

        model = _LSTMNet(EVENT_DIM, hidden=64, layers=2)
        optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
        criterion = nn.MSELoss()

        model.train()
        for epoch in range(30):
            optimizer.zero_grad()
            out = model(X)
            loss = criterion(out, Y)
            loss.backward()
            optimizer.step()
            if epoch % 10 == 0:
                logger.debug("[LSTM] Epoch %d loss=%.4f", epoch, loss.item())

        self._model = model
        self._trained = True
        SAVED_DIR.mkdir(parents=True, exist_ok=True)
        import torch
        torch.save(model.state_dict(), SAVED_DIR / "model.pt")
        logger.info("[LSTM] PyTorch model trained and saved")

    def _lstm_score(self, events: list[str]) -> dict:
        import torch
        sequences, _ = self._make_sequences(events)
        if not sequences:
            return self._result(0, 0.0, "no-sequences", {})

        X = torch.tensor(sequences, dtype=torch.float32)
        self._model.eval()
        with torch.no_grad():
            preds = self._model(X).numpy()

        # Build ground truth targets from actual events
        _, targets = self._make_sequences(events)
        Y = np.array(targets)
        errors = np.mean((preds - Y) ** 2, axis=1)
        mean_err = float(np.mean(errors))
        max_err = float(np.max(errors))

        # Error ranges: 0 = perfect prediction, ~1 = totally wrong
        score = int(min(max_err * 120, 100))
        confidence = min(mean_err * 2, 1.0)
        return self._result(score, confidence, "lstm-pytorch", {"mean_pred_error": round(mean_err, 4)})

    # ── N-gram fallback ───────────────────────────────────────────────────────

    def _fit_ngram(self, events: list[str]):
        for i in range(len(events) - 1):
            self._ngram[events[i]][events[i + 1]] += 1
        self._ngram_trained = True
        SAVED_DIR.mkdir(parents=True, exist_ok=True)
        with open(SAVED_DIR / "ngram.pkl", "wb") as f:
            pickle.dump(dict(self._ngram), f)

    def _ngram_score(self, events: list[str]) -> dict:
        surprises = []
        for i in range(len(events) - 1):
            curr, nxt = events[i], events[i + 1]
            if curr in self._ngram:
                counts = self._ngram[curr]
                total = sum(counts.values())
                prob = counts.get(nxt, 0) / max(total, 1)
            else:
                prob = 0.0
            surprises.append(1.0 - prob)

        if not surprises:
            return self._result(0, 0.0, "ngram-empty", {})

        surprise = float(np.mean(surprises))
        score = int(min(surprise * 100, 100))
        return self._result(score, 0.7, "ngram-transition", {"mean_surprise": round(surprise, 4)})

    def _rule_score(self, events: list[str]) -> dict:
        dangerous_seqs = [
            ("login_failure", "login_success"),
            ("process_create", "network_connect"),
            ("file_create", "privilege_escalation"),
            ("service_install", "registry_set"),
            ("dns_query", "network_connect"),
        ]
        hits = 0
        for i in range(len(events) - 1):
            pair = (events[i], events[i + 1])
            if pair in dangerous_seqs:
                hits += 1
        score = min(hits * 25, 100)
        return self._result(score, 0.4, "rule-sequence", {"dangerous_pairs": hits})

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _load(self):
        ngram_path = SAVED_DIR / "ngram.pkl"
        model_path = SAVED_DIR / "model.pt"
        if ngram_path.exists():
            try:
                with open(ngram_path, "rb") as f:
                    self._ngram = defaultdict(lambda: defaultdict(int), pickle.load(f))
                self._ngram_trained = True
                logger.info("[LSTM] N-gram model loaded")
            except Exception as exc:
                logger.warning("[LSTM] N-gram load failed: %s", exc)
        if model_path.exists():
            try:
                import torch
                m = _LSTMNet(EVENT_DIM, hidden=64, layers=2)
                m.load_state_dict(torch.load(model_path, map_location="cpu"))
                m.eval()
                self._model = m
                self._trained = True
                logger.info("[LSTM] PyTorch model loaded")
            except Exception as exc:
                logger.warning("[LSTM] PyTorch model load failed: %s", exc)

    def _make_sequences(self, events: list[str]):
        X, Y = [], []
        encoded = [self._encode_event(e) for e in events]
        for i in range(len(encoded) - SEQ_LEN):
            X.append(encoded[i: i + SEQ_LEN])
            Y.append(encoded[i + SEQ_LEN])
        return X, Y

    @staticmethod
    def _encode_event(event_type: str) -> list:
        vec = [0.0] * EVENT_DIM
        idx = EVENT_TYPES.index(event_type) if event_type in EVENT_TYPES else EVENT_DIM - 1
        vec[idx] = 1.0
        return vec

    @staticmethod
    def _parse_events(text: str) -> list[str]:
        """Map raw log text lines to canonical event type strings."""
        keyword_map = {
            "accepted": "login_success", "logged in": "login_success",
            "failed": "login_failure", "invalid": "login_failure", "error auth": "login_failure",
            "process": "process_create", "execve": "process_create", "spawn": "process_create",
            "connect": "network_connect", "tcp": "network_connect", "udp": "network_connect",
            "listen": "network_listen", "bind": "network_listen",
            "created": "file_create", "write": "file_modify", "delete": "file_delete",
            "registry": "registry_set", "regedit": "registry_set",
            "dns": "dns_query", "query": "dns_query",
            "service": "service_install", "install": "service_install",
            "privilege": "privilege_escalation", "sudo": "privilege_escalation", "elevat": "privilege_escalation",
        }
        events = []
        for line in text.splitlines():
            lower = line.lower()
            matched = "other"
            for kw, etype in keyword_map.items():
                if kw in lower:
                    matched = etype
                    break
            events.append(matched)
        return events

    @staticmethod
    def _result(score: int, confidence: float, method: str, details: dict) -> dict:
        return {
            "threat_score": score,
            "confidence": round(confidence, 4),
            "detection_method": f"lstm:{method}",
            "details": details,
        }


class _LSTMNet:
    """PyTorch LSTM network — defined inside module to avoid import errors when torch absent."""

    def __new__(cls, *args, **kwargs):
        import torch.nn as nn
        import torch

        class Net(nn.Module):
            def __init__(self, input_dim, hidden, layers):
                super().__init__()
                self.lstm = nn.LSTM(input_dim, hidden, layers, batch_first=True, dropout=0.2)
                self.fc = nn.Linear(hidden, input_dim)

            def forward(self, x):
                out, _ = self.lstm(x)
                return self.fc(out[:, -1, :])

        return Net(*args, **kwargs)
