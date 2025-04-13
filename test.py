import pandas as pd
import pickle
import sys
import os

# === Paths ===
MODEL_PATH = os.path.join("models", "pe_models.pkl")
CSV_PATH = "Header.csv"

# === Malware check (basic) ===
def is_malicious(file_path):
    suspicious_keywords = ["<script>", "eval(", "exec(", "base64,", "<?php", "rm -rf", "import os", "subprocess"]
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
            for keyword in suspicious_keywords:
                if keyword in content:
                    print(f"[✖] Suspicious keyword detected: '{keyword}'")
                    return True
    except Exception as e:
        print(f"[✖] Error reading file: {e}")
        return True
    return False

# === Load Model ===
def load_model(path):
    try:
        with open(path, 'rb') as f:
            model_dict = pickle.load(f)
        print("[✔] Model dictionary loaded successfully.")
        print(f"[ℹ] Available models: {list(model_dict.keys())}")
        return model_dict
    except Exception as e:
        print(f"[✖] Failed to load model: {e}")
        sys.exit(1)

# === Run Predictions ===
def run_prediction(model, csv_path):
    try:
        data = pd.read_csv(csv_path)
        print(f"[✔] CSV loaded. Shape: {data.shape}")

        # Drop non-numeric columns
        numeric_data = data.select_dtypes(include=['number'])

        # Align features with model
        if hasattr(model, 'feature_names_in_'):
            numeric_data = numeric_data[model.feature_names_in_]
        else:
            numeric_data = numeric_data.iloc[:, :model.n_features_in_]

        print(f"[ℹ] Final data shape used for prediction: {numeric_data.shape}")
        predictions = model.predict(numeric_data)

        print("[✔] Predictions (Top 10):")
        print(predictions[:10])
    except Exception as e:
        print(f"[✖] Prediction failed: {e}")



# === Main Execution ===
if __name__ == "__main__":
    if is_malicious(CSV_PATH):
        print("[⚠] Malicious content detected in CSV. Exiting.")
        sys.exit(1)

    model_dict = load_model(MODEL_PATH)

    # You can change 'rf_model' to 'gb_model' if you want to use the gradient boosting model
    if 'rf_model' in model_dict:
        selected_model = model_dict['rf_model']
        run_prediction(selected_model, CSV_PATH)
    else:
        print("[✖] 'rf_model' not found in the model dictionary.")
