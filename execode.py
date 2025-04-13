import pandas as pd
import pefile
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# === Step 1: Load and prepare the dataset ===
df = pd.read_csv("PE_Header.csv")  # Replace with your CSV path if needed

# Drop SHA256 (not a feature)
X = df.drop(columns=['SHA256', 'Type'])
y = df['Type']  # 0 = benign, 1 = malicious

# === Step 2: Train/test split ===
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# === Step 3: Train the Random Forest model ===
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# === Step 4: Evaluate the model ===
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"✅ Model Accuracy: {accuracy * 100:.2f}%")

# === Step 5: Extract features from a real .exe file ===
def extract_pe_features(filepath):
    pe = pefile.PE(filepath)

    features = {
        'e_magic': pe.DOS_HEADER.e_magic,
        'e_cblp': pe.DOS_HEADER.e_cblp,
        'e_cp': pe.DOS_HEADER.e_cp,
        'e_crlc': pe.DOS_HEADER.e_crlc,
        'e_cparhdr': pe.DOS_HEADER.e_cparhdr,
        'e_minalloc': pe.DOS_HEADER.e_minalloc,
        'e_maxalloc': pe.DOS_HEADER.e_maxalloc,
        'e_ss': pe.DOS_HEADER.e_ss,
        'e_sp': pe.DOS_HEADER.e_sp,
        'e_csum': pe.DOS_HEADER.e_csum,
        'e_ip': pe.DOS_HEADER.e_ip,
        'e_cs': pe.DOS_HEADER.e_cs,
        'e_lfarlc': pe.DOS_HEADER.e_lfarlc,
        'e_ovno': pe.DOS_HEADER.e_ovno,
        'e_oemid': pe.DOS_HEADER.e_oemid,
        'e_oeminfo': pe.DOS_HEADER.e_oeminfo,
        'e_lfanew': pe.DOS_HEADER.e_lfanew,
        'Machine': pe.FILE_HEADER.Machine,
        'NumberOfSections': pe.FILE_HEADER.NumberOfSections,
        'TimeDateStamp': pe.FILE_HEADER.TimeDateStamp,
        'PointerToSymbolTable': pe.FILE_HEADER.PointerToSymbolTable,
        'NumberOfSymbols': pe.FILE_HEADER.NumberOfSymbols,
        'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
        'Characteristics': pe.FILE_HEADER.Characteristics,
        'Magic': pe.OPTIONAL_HEADER.Magic,
        'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
        'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
        'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
        'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
        'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
        'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
        'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
        'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
        'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
        'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
        'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
        'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
        'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
        'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
        'Reserved1': pe.OPTIONAL_HEADER.Reserved1,
        'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
        'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
        'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
        'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
        'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
        'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
        'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
        'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
        'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
        'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
    }

    return pd.DataFrame([features])[X.columns]  # Ensure correct column order

# === Step 6: Predict the uploaded .exe file ===
exe_path = "dummy.exe"  # Replace with your uploaded .exe file path
new_data = extract_pe_features(exe_path)

# Predict
prediction = model.predict(new_data)

# Output result
print(f"🧪 Prediction for {exe_path}:")
print("⚠ Malicious" if prediction[0] == 1 else "✅ Benign")