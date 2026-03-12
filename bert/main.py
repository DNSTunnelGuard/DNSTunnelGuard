from flask import Flask, request, jsonify
from model import predict_float, determine_device
from transformers import AutoModelForSequenceClassification
import logging
import argparse
import sys

# ── Logging setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("main_log.txt")
    ]
)
log = logging.getLogger(__name__)

# ── Flask app ──────────────────────────────────────────────────────────────────
app = Flask(__name__)

# Globals set during main() after args are parsed
model       = None
device      = None
temperature = None

@app.route('/weight', methods=['GET'])
def get_weight_percentage():
    query = request.args.get('query', type=str)
    if not query:
        return jsonify({"error": "Missing or invalid 'query' parameter"}), 400

    try:
        weight_percentage = predict_float(query, model, temperature, device)
        log.info(f"Query: {query!r:60s}  Score: {weight_percentage:.4f}  Temp: {temperature}")
        return jsonify({"weight_percentage": weight_percentage, "temperature": temperature})

    except Exception as e:
        log.error(f"Prediction error for query {query!r}: {e}")
        return jsonify({"error": "Prediction failed.", "details": str(e)}), 500


if __name__ == '__main__':
    if len(sys.argv) < 4 or len(sys.argv) > 5:
        print("Usage: python3 main.py <model_path> <temperature> <port> [debug]")
        print("  model_path  : Path to the pretrained model directory (e.g. models/default)")
        print("  temperature : Model prediction temperature, must be a positive number (e.g. 1.0)")
        print("  port        : Port to listen on (e.g. 3000)")
        print("  debug       : Optional, pass 'debug' to enable Flask debug mode")
        sys.exit(1)

    model_path = sys.argv[1]

    try:
        temperature = float(sys.argv[2])
        if temperature <= 0:
            raise ValueError
    except ValueError:
        print("Error: temperature must be a positive number.")
        sys.exit(1)

    try:
        port = int(sys.argv[3])
    except ValueError:
        print("Error: port must be an integer.")
        sys.exit(1)

    debug = len(sys.argv) == 5 and sys.argv[4].lower() == "debug"

    # ── Model loading (once on startup) ───────────────────────────────────────
    log.info(f"Loading model from: {model_path}")
    log.info(f"Temperature:        {temperature}")
    device = determine_device()
    model  = AutoModelForSequenceClassification.from_pretrained(model_path)
    model.to(device)
    model.eval()
    log.info(f"Model loaded on device: {device}")

    app.run(host="0.0.0.0", port=port, debug=debug)
