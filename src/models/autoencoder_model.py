"""
Autoencoder anomaly detector.
Reconstructs normal log feature vectors; high error = anomalous.
Falls back to PCA reconstruction if PyTorch is unavailable.
"""
import logging
import pickle
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)
SAVED_DIR = Path(__file__).parent / "saved" / "autoencoder"
FEATURE_DIM = 20  # must match IsolationForestModel._extract_features output length


class AutoencoderModel:
    """
    MLP autoencoder: input(20) → 16 → 8 → 4 → 8 → 16 → 20.
    Reconstruction error on unseen anomalous inputs is significantly higher.
    """

    def __init__(self):
        self._model = None
        self._scaler = None
        self._trained = False
        self._pca = None
        self._threshold = 1.0
        self._load()

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, text: str) -> dict:
        from src.models.isolation_forest_model import IsolationForestModel
        features = IsolationForestModel._extract_features(text)
        vec = np.array(features["vector"], dtype=np.float64).reshape(1, -1)

        if self._trained and self._model is not None:
            return self._ae_score(vec, features)
        if self._pca is not None:
            return self._pca_score(vec, features)
        return self._heuristic_score(features)

    def fit(self, texts: list[str]):
        from src.models.isolation_forest_model import IsolationForestModel
        from sklearn.preprocessing import StandardScaler

        vectors = np.array([IsolationForestModel._extract_features(t)["vector"] for t in texts])
        self._scaler = StandardScaler().fit(vectors)
        scaled = self._scaler.transform(vectors)

        # Try PyTorch first
        try:
            self._fit_torch(scaled)
        except Exception as exc:
            logger.warning("[AE] PyTorch unavailable (%s) — falling back to PCA", exc)
            self._fit_pca(scaled)

    def is_trained(self) -> bool:
        return self._trained or (self._pca is not None)

    # ── PyTorch autoencoder ───────────────────────────────────────────────────

    def _fit_torch(self, data: np.ndarray):
        import torch
        import torch.nn as nn

        X = torch.tensor(data, dtype=torch.float32)
        model = _AENet(FEATURE_DIM)
        opt = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-5)
        criterion = nn.MSELoss()

        model.train()
        for epoch in range(50):
            opt.zero_grad()
            recon = model(X)
            loss = criterion(recon, X)
            loss.backward()
            opt.step()
            if epoch % 10 == 0:
                logger.debug("[AE] Epoch %d loss=%.5f", epoch, loss.item())

        model.eval()
        with torch.no_grad():
            errors = nn.MSELoss(reduction="none")(model(X), X).mean(dim=1).numpy()

        self._threshold = float(np.percentile(errors, 95))
        self._model = model
        self._trained = True
        SAVED_DIR.mkdir(parents=True, exist_ok=True)
        torch.save({"state": model.state_dict(), "threshold": self._threshold}, SAVED_DIR / "ae.pt")
        with open(SAVED_DIR / "scaler.pkl", "wb") as f:
            pickle.dump(self._scaler, f)
        logger.info("[AE] Autoencoder trained. 95th-pct threshold=%.4f", self._threshold)

    def _ae_score(self, vec: np.ndarray, features: dict) -> dict:
        import torch
        import torch.nn as nn

        scaled = torch.tensor(self._scaler.transform(vec), dtype=torch.float32)
        self._model.eval()
        with torch.no_grad():
            recon = self._model(scaled)
            error = float(nn.MSELoss()(recon, scaled).item())

        ratio = error / max(self._threshold, 1e-9)
        score = int(min(ratio * 60, 100))
        confidence = min(ratio / 2.0, 1.0)
        return self._result(score, confidence, "pytorch-autoencoder",
                            {"recon_error": round(error, 6), "threshold": round(self._threshold, 6)})

    # ── PCA fallback ──────────────────────────────────────────────────────────

    def _fit_pca(self, data: np.ndarray):
        from sklearn.decomposition import PCA
        n_comp = min(8, data.shape[1], data.shape[0] - 1)
        pca = PCA(n_components=n_comp)
        pca.fit(data)
        reconstructed = pca.inverse_transform(pca.transform(data))
        errors = np.mean((data - reconstructed) ** 2, axis=1)
        self._threshold = float(np.percentile(errors, 95))
        self._pca = pca
        SAVED_DIR.mkdir(parents=True, exist_ok=True)
        with open(SAVED_DIR / "pca.pkl", "wb") as f:
            pickle.dump({"pca": pca, "threshold": self._threshold, "scaler": self._scaler}, f)
        logger.info("[AE] PCA fallback trained. threshold=%.4f", self._threshold)

    def _pca_score(self, vec: np.ndarray, features: dict) -> dict:
        scaled = self._scaler.transform(vec)
        recon = self._pca.inverse_transform(self._pca.transform(scaled))
        error = float(np.mean((scaled - recon) ** 2))
        ratio = error / max(self._threshold, 1e-9)
        score = int(min(ratio * 60, 100))
        return self._result(score, 0.6, "pca-reconstruction",
                            {"recon_error": round(error, 6), "threshold": round(self._threshold, 6)})

    def _heuristic_score(self, features: dict) -> dict:
        kw = features.get("keyword_hits", 0)
        ent = features.get("entropy", 0.0)
        score = min(kw * 10 + int(max(ent - 3.5, 0) * 15), 100)
        return self._result(score, 0.35, "heuristic-fallback", {})

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self):
        ae_path = SAVED_DIR / "ae.pt"
        pca_path = SAVED_DIR / "pca.pkl"
        scaler_path = SAVED_DIR / "scaler.pkl"

        if ae_path.exists() and scaler_path.exists():
            try:
                import torch
                ckpt = torch.load(ae_path, map_location="cpu")
                m = _AENet(FEATURE_DIM)
                m.load_state_dict(ckpt["state"])
                m.eval()
                self._model = m
                self._threshold = ckpt["threshold"]
                with open(scaler_path, "rb") as f:
                    self._scaler = pickle.load(f)
                self._trained = True
                logger.info("[AE] Autoencoder loaded from %s", SAVED_DIR)
                return
            except Exception as exc:
                logger.warning("[AE] AE load failed: %s", exc)

        if pca_path.exists():
            try:
                with open(pca_path, "rb") as f:
                    state = pickle.load(f)
                self._pca = state["pca"]
                self._threshold = state["threshold"]
                self._scaler = state["scaler"]
                logger.info("[AE] PCA model loaded")
            except Exception as exc:
                logger.warning("[AE] PCA load failed: %s", exc)

    @staticmethod
    def _result(score: int, confidence: float, method: str, details: dict) -> dict:
        return {
            "threat_score": score,
            "confidence": round(confidence, 4),
            "detection_method": f"autoencoder:{method}",
            "details": details,
        }


class _AENet:
    """PyTorch MLP autoencoder — lazy import to survive missing torch."""

    def __new__(cls, input_dim: int):
        import torch.nn as nn

        class Net(nn.Module):
            def __init__(self, d):
                super().__init__()
                self.encoder = nn.Sequential(
                    nn.Linear(d, 16), nn.ReLU(),
                    nn.Linear(16, 8), nn.ReLU(),
                    nn.Linear(8, 4),
                )
                self.decoder = nn.Sequential(
                    nn.Linear(4, 8), nn.ReLU(),
                    nn.Linear(8, 16), nn.ReLU(),
                    nn.Linear(16, d),
                )

            def forward(self, x):
                return self.decoder(self.encoder(x))

        return Net(input_dim)
