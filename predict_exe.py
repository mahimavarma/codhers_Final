import pefile
import pandas as pd
import joblib
import sys

# === Step 1: Load your trained model ===
model = joblib.load("models/exe_model.pkl")  # Replace with your actual .pkl filename

# === Step 2: Define the feature extraction function ===
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

    return pd.DataFrame([features])

# === Step 3: CLI input and prediction ===
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python predict_exe.py <path_to_exe_file>")
        sys.exit(1)

    exe_path = sys.argv[1]

    try:
        new_data = extract_pe_features(exe_path)
        prediction = model.predict(new_data)
        print("\n🧪 Prediction Result:")
        print("⚠️ Malware Detected!" if prediction[0] == 1 else "✅ Benign File")
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
