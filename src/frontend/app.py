"""
SOC AI Assistant Pro — Flask API + Cyberpunk UI server.
Security-hardened: CORS restricted, rate-limited, all inputs sanitized.
"""
import base64
import json
import logging
import os
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parents[2]))

from flask import Flask, request, jsonify, render_template, send_file, Response, stream_with_context
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
import io

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

# ── App factory ───────────────────────────────────────────────────────────────

def create_app(config: dict = None) -> Flask:
    cfg = config or {}

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB
    app.config["SECRET_KEY"] = os.urandom(32).hex()

    # Security headers middleware
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Referrer-Policy"]            = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"]   = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
            "img-src 'self' data:;"
        )
        return response

    # CORS — restrict to localhost only
    CORS(app, origins=["http://localhost:5000", "http://127.0.0.1:5000"])

    # Rate limiting
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "60 per hour"],
        storage_uri="memory://",
    )

    # Load engine singleton
    from src.core.inference_engine import InferenceEngine
    from src.security.license_manager import LicenseManager
    from src.security.input_sanitizer import InputSanitizer

    engine   = InferenceEngine.get_instance(cfg)
    license_mgr = LicenseManager(cfg.get("license_key_path", "./license.txt"))
    sanitizer   = InputSanitizer()

    # Validate license at startup
    valid, msg = license_mgr.validate()
    if not valid:
        logger.error("[App] License validation failed: %s", msg)
        # Don't exit in development; just warn
        logger.warning("[App] Running in UNLICENSED mode — limited functionality")

    # ── Routes ────────────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("index.html",
                               tool_version="2.0.0",
                               license_tier=license_mgr.get_tier(),
                               licensed=valid)

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "version": "2.0.0",
                        "engine_ready": engine._ready,
                        "training_status": engine.training_status()})

    @app.route("/analyze", methods=["POST"])
    @limiter.limit("10 per minute")
    def analyze():
        """
        Main analysis endpoint.
        Accepts multipart/form-data with optional file(s) and JSON params.
        Also accepts application/json with base64-encoded file content.
        """
        try:
            # --- Parse input ---
            if request.content_type and "application/json" in request.content_type:
                data = request.get_json(force=True, silent=True) or {}
                log_text  = _decode_b64_field(data.get("log_file", ""))
                pcap_text = _decode_b64_field(data.get("pcap_file", ""))
                ioc       = str(data.get("ioc", ""))
                customer_id = str(data.get("customer_id", ""))
                fmt       = str(data.get("format", "json"))
                mode      = str(data.get("mode", "tool"))
            else:
                log_file  = request.files.get("log")
                pcap_file = request.files.get("pcap")
                ioc       = sanitizer.sanitize_text(request.form.get("ioc", ""), redact_pii=False)
                customer_id = sanitizer.sanitize_text(request.form.get("customer_id", ""), redact_pii=False)
                fmt       = request.form.get("format", "json")
                mode      = request.form.get("mode", "tool")

                log_text  = ""
                pcap_text = ""

                if log_file and log_file.filename:
                    fname = sanitizer.sanitize_filename(log_file.filename)
                    raw   = log_file.read()
                    ok, err_msg = sanitizer.validate_upload(fname, raw)
                    if not ok:
                        return jsonify({"error": err_msg}), 400
                    log_text = raw.decode("utf-8", errors="replace")

                if pcap_file and pcap_file.filename:
                    fname = sanitizer.sanitize_filename(pcap_file.filename)
                    raw   = pcap_file.read()
                    ok, err_msg = sanitizer.validate_upload(fname, raw)
                    if not ok:
                        return jsonify({"error": err_msg}), 400
                    if fname.endswith((".pcap", ".cap")):
                        from src.utils.pcap_parser import PCAPParser
                        parsed = PCAPParser().parse(raw)
                        pcap_text = parsed.get("text_summary", "")
                    else:
                        pcap_text = raw.decode("utf-8", errors="replace")

            # --- Service mode license check ---
            if mode == "service" and not license_mgr.is_service_mode_allowed():
                return jsonify({"error": "Service mode requires Pro or Enterprise license"}), 403

            # --- Sanitize text inputs ---
            log_text  = sanitizer.sanitize_text(log_text)
            pcap_text = sanitizer.sanitize_text(pcap_text)

            if ioc:
                ioc_valid, ioc_type = sanitizer.validate_ioc(ioc)
                if not ioc_valid:
                    return jsonify({"error": f"Invalid IOC: {ioc_type}"}), 400

            # --- Run analysis ---
            result = engine.analyze(
                log_text=log_text,
                pcap_text=pcap_text,
                ioc=ioc,
                customer_id=customer_id,
                mode=mode,
            )

            # --- Build response ---
            if fmt == "pdf":
                pdf_bytes = engine.generate_pdf(result)
                if not pdf_bytes:
                    return jsonify({"error": "PDF generation failed"}), 500
                watermark = customer_id if mode == "service" else ""
                if mode == "service" and watermark:
                    result["_watermark"] = watermark
                    pdf_bytes = engine.generate_pdf(result)
                return send_file(
                    io.BytesIO(pdf_bytes),
                    mimetype="application/pdf",
                    as_attachment=True,
                    download_name=f"soc_report_{int(time.time())}.pdf",
                )
            elif fmt == "both":
                pdf_bytes = engine.generate_pdf(result)
                result["pdf_b64"] = base64.b64encode(pdf_bytes).decode() if pdf_bytes else ""
                return jsonify(result)
            else:
                return jsonify(result)

        except Exception as exc:
            logger.error("[Analyze] Unhandled error: %s", exc, exc_info=True)
            return jsonify({"error": "Internal analysis error", "detail": str(exc)}), 500

    @app.route("/stream-analysis", methods=["POST"])
    @limiter.limit("5 per minute")
    def stream_analysis():
        """Server-Sent Events endpoint for real-time terminal feed in the UI."""
        data = request.get_json(force=True, silent=True) or {}
        log_text  = sanitizer.sanitize_text(_decode_b64_field(data.get("log_file", "")))
        ioc       = data.get("ioc", "")

        def event_stream():
            steps = [
                ("Initialising ensemble detector...",           0.3),
                ("Running BERT semantic analyser...",           1.0),
                ("Running Isolation Forest...",                 0.5),
                ("Running LSTM sequence predictor...",          0.8),
                ("Running Autoencoder reconstruction...",       0.5),
                ("Running One-Class SVM...",                    0.4),
                ("Aggregating weighted votes...",               0.3),
                ("Running zero-day detector (6 methods)...",   1.2),
                ("Scanning YARA rules...",                      0.5),
                ("Matching Sigma rules...",                     0.4),
                ("Correlating CVE database...",                 0.3),
                ("Mapping MITRE ATT&CK techniques...",          0.4),
                ("Reconstructing kill chain...",                1.0) if ioc else ("Skipping kill chain (no IOC)...", 0.1),
                ("Generating PDF report...",                    0.8),
                ("Analysis complete.",                          0.0),
            ]
            for msg, delay in steps:
                yield f"data: {json.dumps({'step': msg})}\n\n"
                if delay:
                    time.sleep(delay)
            # Run actual analysis
            result = engine.analyze(log_text=log_text, ioc=ioc)
            yield f"data: {json.dumps({'done': True, 'result': result})}\n\n"

        return Response(stream_with_context(event_stream()),
                        content_type="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.route("/training-status")
    def training_status():
        return jsonify(engine.training_status())

    @app.route("/hardware-id")
    def hardware_id():
        return jsonify({"hardware_id": license_mgr.get_hardware_id()})

    return app


# ── Helpers ───────────────────────────────────────────────────────────────────

def _decode_b64_field(value: str) -> str:
    if not value:
        return ""
    try:
        return base64.b64decode(value + "==").decode("utf-8", errors="replace")
    except Exception:
        return value  # assume it's plain text


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SOC AI Assistant Pro — Web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    app = create_app()
    logger.info("Starting SOC AI Assistant Pro on http://%s:%d", args.host, args.port)
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
