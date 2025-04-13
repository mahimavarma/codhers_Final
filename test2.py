import pandas as pd
import pickle
import sys
import os
import pefile
import math

# === Paths ===
MODEL_PATH = os.path.join("models", "pe_models.pkl")

# === Malware check for file content ===
def is_malicious(file_path):
    suspicious_keywords = ["<script>", "eval(", "exec(", "base64,", "<?php", "rm -rf", "import os", "subprocess"]
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
            for keyword in suspicious_keywords:
                if keyword in content:
                    print(f"[✖] Suspicious keyword detected: '{keyword}'")
                    return True
    except:
        pass  # Ignore read errors for binary files
    return False

# === Feature extraction logic ===
def is_pe_file(file_path):
    try:
        pefile.PE(file_path)
        return True
    except:
        return False

def get_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log(p_x, 2)
    return entropy

def extract_pe_features(file_path):
    pe = pefile.PE(file_path)
    return {
        "MajorImageVersion": pe.OPTIONAL_HEADER.MajorImageVersion,
        "SizeOfCode": pe.OPTIONAL_HEADER.SizeOfCode,
        "SizeOfInitializedData": pe.OPTIONAL_HEADER.SizeOfInitializedData,
        "CheckSum": pe.OPTIONAL_HEADER.CheckSum,
        "AddressOfEntryPoint": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "MinorLinkerVersion": pe.OPTIONAL_HEADER.MinorLinkerVersion,
        "SizeOfImage": pe.OPTIONAL_HEADER.SizeOfImage,
        "TimeDateStamp": pe.FILE_HEADER.TimeDateStamp,
        "e_lfanew": pe.DOS_HEADER.e_lfanew,
        "FileAlignment": pe.OPTIONAL_HEADER.FileAlignment
    }

def extract_generic_features(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
        file_size = os.path.getsize(file_path)
        entropy = get_entropy(data)
    return {
        "MajorImageVersion": 0,
        "SizeOfCode": 0,
        "SizeOfInitializedData": 0,
        "CheckSum": 0,
        "AddressOfEntryPoint": 0,
        "MinorLinkerVersion": 0,
        "SizeOfImage": 0,
        "TimeDateStamp": 0,
        "e_lfanew": 0,
        "FileAlignment": 0,
        "Entropy": entropy,
        "FileSize": file_size
    }

def extract_features(file_path):
    if is_pe_file(file_path):
        print("[✔] PE file detected. Extracting PE features...")
        return extract_pe_features(file_path)
    else:
        print("[✔] Non-PE file. Extracting generic features...")
        return extract_generic_features(file_path)

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

# === Run Prediction ===
def run_prediction(model, feature_dict):
    try:
        df = pd.DataFrame([feature_dict])  # One row, many features

        # Align with model
        if hasattr(model, 'feature_names_in_'):
            df = df[model.feature_names_in_]
        else:
            df = df.iloc[:, :model.n_features_in_]

        print(f"[ℹ] Input features shape: {df.shape}")
        prediction = model.predict(df)
        print(f"[✔] Prediction: {'Malicious' if prediction[0] == 1 else 'Benign'}")
    except Exception as e:
        print(f"[✖] Prediction failed: {e}")

# === Main ===
if __name__ == "__main__":
    target_file = input("Enter path to the file to scan: ")

    if not os.path.isfile(target_file):
        print("[✖] File does not exist.")
        sys.exit(1)

    if is_malicious(target_file):
        print("[⚠] Malicious content detected in file. Exiting early.")
        sys.exit(1)

    features = extract_features(target_file)
    model_dict = load_model(MODEL_PATH)

    if 'rf_model' in model_dict:
        selected_model = model_dict['rf_model']
        run_prediction(selected_model, features)
    else:
        print("[✖] 'rf_model' not found in the model dictionary.")
