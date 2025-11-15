from flask import Flask, render_template, request, jsonify
import pickle
import numpy as np
from feature_extractor import extract_features_from_url, required_feature_names
import os

app = Flask(__name__)

MODEL_PATH = os.path.join("model", "phishing_rf_model.pkl")

# Load model
try:
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
except Exception as e:
    model = None
    print("Error loading model:", e)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    url = request.form.get("url", "").strip()
    if not url:
        return render_template("index.html", error="Please enter a URL")

    # Extract features
    features, meta = extract_features_from_url(url)

    if model is None:
        return render_template("index.html", error="Model not loaded on server. Check model file.")

    # Convert to shape (1, n)
    X = np.array(features).reshape(1, -1)

    try:
        pred = model.predict(X)[0]
        label = "Phishing" if int(pred) == 1 else "Legitimate"
        return render_template("index.html", url=url, prediction=label, meta=meta)
    except Exception as e:
        return render_template("index.html", error=f"Prediction error: {e}", meta=meta)


@app.route("/api/predict", methods=["POST"])
def api_predict():
    """
    Expects JSON: { "url": "http://..." }
    Returns JSON: { "prediction": "Phishing"/"Legitimate", "features": {...} }
    """
    data = request.get_json(force=True)
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please provide a url field in JSON"}), 400

    features, meta = extract_features_from_url(url)
    if model is None:
        return jsonify({"error": "Model not loaded on server."}), 500

    X = np.array(features).reshape(1, -1)
    try:
        pred = model.predict(X)[0]
        label = "Phishing" if int(pred) == 1 else "Legitimate"
        return jsonify({"prediction": label, "features": meta})
    except Exception as e:
        return jsonify({"error": f"Prediction failed: {e}"}), 500


if __name__ == "__main__":
    app.run(debug=True)
