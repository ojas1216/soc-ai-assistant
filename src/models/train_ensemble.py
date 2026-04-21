"""
Ensemble training script.
Feed a directory of normal (benign) log files to train all 5 models.

Usage:
    python -m src.models.train_ensemble --data ./baseline_logs/
    python -m src.models.train_ensemble --data ./baseline_logs/ --epochs 50
"""
import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Add project root to path when run as script
sys.path.insert(0, str(Path(__file__).parents[2]))


def load_texts(data_dir: str, max_files: int = 5000) -> list[str]:
    """Recursively load all .log .txt .json files from data_dir."""
    texts = []
    p = Path(data_dir)
    if not p.exists():
        raise FileNotFoundError(f"Data directory not found: {data_dir}")

    for fpath in sorted(p.rglob("*")):
        if not fpath.is_file():
            continue
        if fpath.suffix.lower() not in (".log", ".txt", ".json", ".csv"):
            continue
        try:
            raw = fpath.read_text(encoding="utf-8", errors="replace")
            # Split into chunks of ~512 chars to get more training samples
            for i in range(0, len(raw), 512):
                chunk = raw[i: i + 512].strip()
                if chunk:
                    texts.append(chunk)
        except Exception as exc:
            logger.warning("Skipping %s: %s", fpath, exc)

        if len(texts) >= max_files:
            break

    logger.info("Loaded %d training samples from %s", len(texts), data_dir)
    return texts


def train(data_dir: str, epochs: int = 30):
    t0 = time.time()
    texts = load_texts(data_dir)

    if len(texts) < 50:
        logger.error("Need at least 50 samples for meaningful training. Got %d.", len(texts))
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("Training 5-algorithm ensemble on %d samples", len(texts))
    logger.info("=" * 60)

    # 1. Isolation Forest
    logger.info("\n[1/5] Training Isolation Forest ...")
    from src.models.isolation_forest_model import IsolationForestModel
    iforest = IsolationForestModel()
    iforest.fit(texts)
    logger.info("      Isolation Forest: OK")

    # 2. One-Class SVM
    logger.info("\n[2/5] Training One-Class SVM ...")
    from src.models.one_class_svm import OneClassSVMModel
    ocsvm = OneClassSVMModel()
    ocsvm.fit(texts)
    logger.info("      One-Class SVM: OK")

    # 3. Autoencoder
    logger.info("\n[3/5] Training Autoencoder ...")
    from src.models.autoencoder_model import AutoencoderModel
    ae = AutoencoderModel()
    ae.fit(texts)
    logger.info("      Autoencoder: OK")

    # 4. LSTM
    logger.info("\n[4/5] Training LSTM sequence predictor ...")
    from src.models.lstm_predictor import LSTMPredictor
    lstm = LSTMPredictor()
    lstm.fit(texts)
    logger.info("      LSTM: OK")

    # 5. BERT (downloads model if needed)
    logger.info("\n[5/5] Initialising BERT analyser (downloads model on first run) ...")
    from src.models.bert_analyzer import BERTAnalyzer
    bert = BERTAnalyzer()
    status = "transformer-mode" if bert._use_transformers else "keyword-fallback"
    logger.info("      BERT: %s", status)

    elapsed = time.time() - t0
    logger.info("\n" + "=" * 60)
    logger.info("Training complete in %.1f s", elapsed)
    logger.info("Models saved to src/models/saved/")
    logger.info("=" * 60)

    # Write training manifest
    manifest = {
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sample_count": len(texts),
        "models": {
            "isolation_forest": iforest.is_trained(),
            "ocsvm": ocsvm.is_trained(),
            "autoencoder": ae.is_trained(),
            "lstm": lstm.is_trained(),
            "bert": bert._use_transformers,
        },
    }
    manifest_path = Path(__file__).parent / "saved" / "training_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2))
    logger.info("Manifest written to %s", manifest_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train SOC AI Assistant ensemble models")
    parser.add_argument("--data", required=True, help="Directory of benign log files")
    parser.add_argument("--epochs", type=int, default=30, help="Training epochs for neural models")
    args = parser.parse_args()
    train(args.data, args.epochs)
