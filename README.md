# 🛡️ Malware Detector

A machine learning-based malware detection system designed to identify malicious files across various formats using static analysis. The system supports multiple file types including PE (.exe), PDF, Excel, Word, PowerPoint, CSV, and more. It leverages **XGBoost** and **Random Forest** classifiers trained on real malware datasets.

---

## 📂 Supported File Types

- **PE (.exe):** Windows executables.
- **PDF:** Documents with embedded exploits or JavaScript.
- **Excel (.xls, .xlsx):** Spreadsheets (macro detection optional).
- **PowerPoint (.pptx):** Presentations with embedded scripts.
- **Word (.doc, .docx):** Documents potentially containing macros.
- **CSV:** Analyzed for malicious patterns or embedded scripts.
- **TDL:** Handled generically if not format-specific.

---

## ⚙️ Features

- **Static Analysis:** No need to execute files.
- **Multi-format Support:** Flexible design for different file types.
- **Dual Classifier Support:** Choose between XGBoost or Random Forest.
- **Detailed JSON Reports:** Get full breakdowns of predictions and feature contributions.
- **Extensible:** Easily add support for new file types or classifiers.

---

## 🧠 Classifiers

- **XGBoost:** Gradient boosting for accuracy and handling imbalanced data.
- **Random Forest:** Ensemble method providing robust feature importance.

---

## 🧪 Feature Extraction

| File Type     | Features Extracted |
|---------------|--------------------|
| PE (.exe)     | Header info, entropy, DLL characteristics |
| PDF           | JavaScript presence, embedded files, metadata |
| Excel/Word/PPT| Entropy, byte frequency, basic metadata |
| CSV/TDL       | Entropy, byte frequency, structure patterns |

---

## 🧰 Prerequisites

- **Python:** 3.8+
- **OS:** Linux (recommended), Windows, or macOS
- **Sandbox:** Run inside a VM for safety (e.g., Ubuntu)
- **Required Python Packages:**
  - `numpy`, `pandas`, `scikit-learn`, `xgboost`, `python-magic`, `joblib`, `PyPDF2`
  - Optional: `oletools` (for macro detection)

---

## 📦 Installation

```bash
git clone <your-repo-url>
cd pe-malware-detector
python pe_malware_detector.py install
