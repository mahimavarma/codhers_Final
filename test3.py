import argparse
import fitz  # PyMuPDF
import pdfplumber
import os
import pandas as pd
import joblib
import re
from math import log2

# Utility: detect JavaScript presence
def detect_javascript(text):
    js_keywords = ['app.alert', 'this.submitForm', 'this.getField', '/JavaScript']
    return any(kw in text for kw in js_keywords)

# Feature extraction from PDF
def extract_features(file_path):
    try:
        doc = fitz.open(file_path)
        file_size = os.path.getsize(file_path)
        num_pages = len(doc)

        # Safe check for /OpenAction
        try:
            catalog = doc.pdf_catalog()
            has_openaction = int("/OpenAction" in catalog if isinstance(catalog, dict) else False)
        except Exception:
            has_openaction = 0

        has_launch_action = 0
        has_embedded_file = 0
        has_uri = 0
        has_js = 0
        num_objects = 0
        num_streams = 0
        encoded_stream_ratio = 0.0
        entropy = 0.0

        all_text = ""
        for page in doc:
            text = page.get_text()
            all_text += text
            links = page.get_links()
            if links:
                for link in links:
                    if "uri" in link:
                        has_uri = 1
            # Check for Launch action in annotations (AcroForms, JavaScript, etc.)
            if '/Launch' in page.get_text("text"):
                has_launch_action = 1

        has_js = int(detect_javascript(all_text))

        # Check for embedded files
        if doc.embfile_count() > 0:
            has_embedded_file = 1

        # Calculate entropy from file bytes
        with open(file_path, 'rb') as f:
            data = f.read()
            prob = [float(data.count(byte)) / len(data) for byte in set(data)]
            entropy = -sum([p * log2(p) for p in prob if p > 0])

        # Use pdfplumber for num_streams and num_objects (rough estimates)
        with pdfplumber.open(file_path) as pdf:
            text = "".join([p.extract_text() or "" for p in pdf.pages])
            num_streams = text.count("stream")
            num_objects = text.count("obj")

        encoded_stream_ratio = num_streams / num_objects if num_objects > 0 else 0.0

        # Final feature dictionary
        features = {
            'has_js': has_js,
            'has_openaction': has_openaction,
            'has_embedded_file': has_embedded_file,
            'has_uri': has_uri,
            'has_launch_action': has_launch_action,
            'entropy': round(entropy, 4),
            'num_objects': num_objects,
            'num_streams': num_streams,
            'num_pages': num_pages,
            'encoded_stream_ratio': round(encoded_stream_ratio, 4),
            'file_size': file_size
        }

        return pd.DataFrame([features])

    except Exception as e:
        print("❌ Error reading PDF:", e)
        return None

# Main CLI logic
def main():
    parser = argparse.ArgumentParser(description="PDF Malware Detection CLI")
    parser.add_argument("file_path", help="Path to the PDF file")
    args = parser.parse_args()

    # Load model
    try:
        model = joblib.load("models/rf_model.pkl")
    except Exception as e:
        print("❌ Couldn't load 'rf_model.pkl'. Error:", e)
        return

    # Extract features
    features_df = extract_features(args.file_path)
    if features_df is None:
        return

    # Predict
    try:
        prediction = model.predict(features_df)[0]
        label = "🚨 Malicious" if prediction == 1 else "✅ Benign"
        print("\nPrediction:", label)
        print("Extracted Features:")
        print(features_df.to_string(index=False))
    except Exception as e:
        print("❌ Prediction failed:", e)

if __name__ == "__main__":
    main()
