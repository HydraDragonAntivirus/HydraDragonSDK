import argparse
import os
import hashlib
from typing import Dict, Any, List, Tuple

import pefile
import capstone
import numpy as np
import pandas as pd
import joblib

# ---------------------- Utilities (copied from antivirus_sdk_cli.py) ----------------------

def md5_file(path: str) -> str:
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    a = np.frombuffer(data, dtype=np.uint8)
    probs = np.bincount(a, minlength=256) / a.size
    probs = probs[probs > 0]
    return -np.sum(probs * np.log2(probs))

# ---------------------- Disassembler & Feature Extractor (copied from antivirus_sdk_cli.py) ----------------------

class Disassembler:
    def __init__(self, arch: str = 'auto'):
        self.arch = arch

    def _capstone_for_pe(self, pe) -> capstone.Cs:
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            raise ValueError('Unsupported architecture for PE')

    def disassemble_all_sections(self, pe: pefile.PE) -> Dict[str, Any]:
        analysis = {
            'overall_analysis': {
                'total_instructions': 0,
                'add_count': 0,
                'mov_count': 0,
                'is_likely_packed': None
            },
            'sections': {},
            'error': None
        }
        try:
            md = self._capstone_for_pe(pe)
            total_add_count = 0
            total_mov_count = 0
            grand_total_instructions = 0

            for section in pe.sections:
                section_name = section.Name.decode(errors='ignore').strip('\x00')
                code = section.get_data()
                base_address = (pe.OPTIONAL_HEADER.ImageBase or 0) + section.VirtualAddress
                instruction_counts: Dict[str, int] = {}
                total_instructions_in_section = 0
                sec_entropy = entropy(code)
                sec_size = len(code)
                if not code:
                    analysis['sections'][section_name] = {
                        'instruction_counts': {},
                        'total_instructions': 0,
                        'add_count': 0,
                        'mov_count': 0,
                        'is_likely_packed': False,
                        'entropy': sec_entropy,
                        'size': sec_size
                    }
                    continue
                for i in md.disasm(code, base_address):
                    mnemonic = i.mnemonic
                    instruction_counts[mnemonic] = instruction_counts.get(mnemonic, 0) + 1
                    total_instructions_in_section += 1
                add_count = instruction_counts.get('add', 0)
                mov_count = instruction_counts.get('mov', 0)
                total_add_count += add_count
                total_mov_count += mov_count
                grand_total_instructions += total_instructions_in_section
                analysis['sections'][section_name] = {
                    'instruction_counts': instruction_counts,
                    'total_instructions': total_instructions_in_section,
                    'add_count': add_count,
                    'mov_count': mov_count,
                    'is_likely_packed': (add_count > mov_count) if total_instructions_in_section > 0 else False,
                    'entropy': sec_entropy,
                    'size': sec_size
                }

            analysis['overall_analysis']['total_instructions'] = grand_total_instructions
            analysis['overall_analysis']['add_count'] = total_add_count
            analysis['overall_analysis']['mov_count'] = total_mov_count
            analysis['overall_analysis']['is_likely_packed'] = (total_add_count > total_mov_count) if grand_total_instructions > 0 else False

        except Exception as e:
            analysis['error'] = str(e)
        return analysis


class FeatureExtractor:
    def __init__(self):
        pass

    def extract(self, path: str) -> Tuple[Dict[str, Any], Dict[str, float]]:
        """Return raw analysis dict and a flat feature vector (dict).
        Features are intentionally simple and explainable for research purposes.
        """
        try:
            pe = pefile.PE(path, fast_load=True)
        except pefile.PEFormatError:
            raise ValueError(f"File {path} is not a valid PE file.")

        dis = Disassembler()
        analysis = dis.disassemble_all_sections(pe)

        # Basic PE features
        features: Dict[str, float] = {}
        features['file_size'] = os.path.getsize(path)
        # entropy of .text and overall
        try:
            text_section = [s for s in pe.sections if s.Name.decode(errors='ignore').strip('\x00') == '.text']
            if text_section:
                features['text_entropy'] = entropy(text_section[0].get_data())
                features['text_size'] = len(text_section[0].get_data())
            else:
                features['text_entropy'] = 0.0
                features['text_size'] = 0
        except Exception:
            features['text_entropy'] = 0.0
            features['text_size'] = 0

        features['num_sections'] = len(pe.sections)
        # imports count
        try:
            imports = sum([len(i.imports) for i in pe.DIRECTORY_ENTRY_IMPORT]) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
        except Exception:
            imports = 0
        features['imports_count'] = imports

        # instruction-based features from disassembly
        agg = analysis['overall_analysis']
        features['total_instructions'] = agg.get('total_instructions', 0)
        features['add_count'] = agg.get('add_count', 0)
        features['mov_count'] = agg.get('mov_count', 0)
        features['add_mov_ratio'] = (features['add_count'] / features['mov_count']) if features['mov_count'] > 0 else features['add_count']

        # section-level entropies
        entropies = [sec.get('entropy', 0.0) for sec in analysis['sections'].values()]
        features['max_section_entropy'] = max(entropies) if entropies else 0.0
        features['mean_section_entropy'] = float(np.mean(entropies)) if entropies else 0.0

        # code density: total_instr / text_size
        features['code_density_text'] = (features['total_instructions'] / features['text_size']) if features['text_size'] > 0 else 0.0

        # simple signature: n-grams of mnemonics from .text (here we produce counts of top mnemonics)
        mnemonic_counts: Dict[str, int] = {}
        for sec in analysis['sections'].values():
            for m, c in sec['instruction_counts'].items():
                mnemonic_counts[m] = mnemonic_counts.get(m, 0) + c
        # keep top 20 mnemonics as features
        top_mnemonics = sorted(mnemonic_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        for name, count in top_mnemonics:
            # prefix to avoid collisions
            features[f'mnem_{name}'] = count

        return analysis, features


# ---------------------- ML Model wrapper (copied from antivirus_sdk_cli.py) ----------------------

from sklearn.ensemble import RandomForestClassifier

class PackedDetectorModel:
    def __init__(self, model: RandomForestClassifier = None):
        self.model = model or RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42)

    def predict(self, X: pd.DataFrame) -> Dict[str, Any]:
        # Ensure the input DataFrame has the same columns as the trained model
        # Fill missing columns with 0 and align column order
        if hasattr(self.model, 'feature_names_in_'):
            expected_features = self.model.feature_names_in_
            X = X.reindex(columns=expected_features, fill_value=0)
        else:
            print("Warning: Model does not have 'feature_names_in_' attribute. Proceeding with existing features.")

        X = X.fillna(0) # Fill any remaining NaNs
        probs = self.model.predict_proba(X)[:, 1] if hasattr(self.model, 'predict_proba') else None
        preds = self.model.predict(X)
        return {'preds': preds.tolist(), 'probs': probs.tolist() if probs is not None else None}

    @classmethod
    def load(cls, path: str):
        m = joblib.load(path)
        return cls(m)

# ---------------------- Scanner Logic ----------------------

def scan_folder(folder_path: str, model_path: str):
    if not os.path.isdir(folder_path):
        print(f"Error: Folder '{folder_path}' not found.")
        return

    if not os.path.exists(model_path):
        print(f"Error: Model '{model_path}' not found.")
        return

    print(f"Loading detection model from '{model_path}'...")
    try:
        model = PackedDetectorModel.load(model_path)
        print("Model loaded successfully.")
    except Exception as e:
        print(f"Error loading model: {e}")
        return

    feature_extractor = FeatureExtractor()
    results = []

    print(f"\nScanning folder: '{folder_path}' for PE files...")
    total_pe_scanned = 0
    malicious_count = 0
    benign_count = 0
    not_pe_count = 0
    error_count = 0

    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            print(f"  Checking: {file_path}")
            try:
                # Attempt to extract features, which will raise ValueError if not a PE file
                _, features = feature_extractor.extract(file_path)
                df = pd.DataFrame([features]).fillna(0)
                prediction_result = model.predict(df)

                prediction = "Malicious/Packed" if prediction_result['preds'][0] == 1 else "Benign/Unpacked"
                probability = prediction_result['probs'][0] if prediction_result['probs'] else 'N/A'

                results.append({
                    'file': file_path,
                    'prediction': prediction,
                    'probability': probability,
                    'status': 'Scanned'
                })
                print(f"    -> {prediction} (Probability: {probability:.4f})")
                total_pe_scanned += 1
                if prediction_result['preds'][0] == 1:
                    malicious_count += 1
                else:
                    benign_count += 1

            except pefile.PEFormatError:
                results.append({
                    'file': file_path,
                    'prediction': 'N/A',
                    'probability': 'N/A',
                    'status': 'Not a PE file'
                })
                print(f"    -> Not a PE file, skipping.")
                not_pe_count += 1
            except Exception as e:
                results.append({
                    'file': file_path,
                    'prediction': 'Error',
                    'probability': 'N/A',
                    'status': f'Error: {e}'
                })
                print(f"    -> Error during scanning: {e}")
                error_count += 1

    print("\n--- Scan Results ---")
    if not results:
        print("No PE files found or scanned.")
    else:
        for res in results:
            print(f"File: {res['file']}")
            print(f"  Status: {res['status']}")
            if res['status'] == 'Scanned':
                print(f"  Prediction: {res['prediction']}")
                print(f"  Probability: {res['probability']:.4f}")
            print("-" * 30)
    
    print("\n--- Summary ---")
    print(f"Total files in folder: {total_pe_scanned + not_pe_count + error_count}")
    print(f"Total PE files scanned: {total_pe_scanned}")
    print(f"  Malicious/Packed: {malicious_count}")
    print(f"  Benign/Unpacked: {benign_count}")
    print(f"Files not PE format: {not_pe_count}")
    print(f"Files with errors during scan: {error_count}")

    if total_pe_scanned > 0:
        detection_rate = (malicious_count / total_pe_scanned) * 100
        print(f"Detection Rate (Malicious/Packed PE files): {detection_rate:.2f}%")
    else:
        print("No PE files were successfully scanned to calculate a detection rate.")


def main():
    parser = argparse.ArgumentParser(description="Scan a folder for malicious/packed PE files using a joblib model.")
    parser.add_argument("--folder", required=True, help="Path to the folder to scan.")
    parser.add_argument("--model", default="packed_detector.joblib", help="Path to the joblib detection model.")
    args = parser.parse_args()

    scan_folder(args.folder, args.model)

if __name__ == "__main__":
    main()
