#!/usr/bin/env python3
"""
Antivirus SDK (CLI) - Capstone-based disassembly + signature DB + ML model

Single-file SDK providing:
 - PE disassembly using Capstone
 - Feature extraction (instruction counts, entropy, section stats, imports)
 - Signature DB (sqlite) to avoid duplicates by file hash
 - Training/prediction wrapper around scikit-learn RandomForest
 - CLI for dataset ingestion, training, prediction, and exporting signatures

Usage examples (after installing deps):
  pip install capstone pefile scikit-learn joblib numpy pandas tqdm

  # Add labeled samples to DB (label: 1=malicious-packed, 0=benign-or-nonpacked)
  python antivirus_sdk_cli.py add-sample --path samples/sample1.exe --label 1

  # Train a model from DB
  python antivirus_sdk_cli.py train --model-out packed_detector.joblib

  # Predict single PE
  python antivirus_sdk_cli.py predict --path sample.exe --model packed_detector.joblib

  # Export signatures (simple: top N frequently-occurring instruction sequences)
  python antivirus_sdk_cli.py export-signatures --out signatures.json

Notes:
 - This is a research SDK: model quality depends on labeled dataset and features.
 - Use responsibly. Do NOT use models for automated takedown decisions without human review.
"""

import argparse
import json
import os
import sqlite3
import hashlib
import time
from typing import Dict, Any, List, Tuple

import pefile
import capstone
import numpy as np
import pandas as pd

# ML
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import joblib

# ---------------------- Utilities ----------------------

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

# ---------------------- Disassembler & Feature Extractor ----------------------

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
        pe = pefile.PE(path, fast_load=True)
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

# ---------------------- Signature DB ----------------------

class SignatureDB:
    def __init__(self, db_path: str = 'signatures.db'):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS samples (
                md5 TEXT PRIMARY KEY,
                path TEXT,
                label INTEGER,
                features_json TEXT,
                analysis_json TEXT,
                added_at REAL
            )
        ''')
        conn.commit()
        conn.close()

    def add_sample(self, path: str, label: int, features: Dict[str, float], analysis: Dict[str, Any]) -> bool:
        sha = md5_file(path)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT md5 FROM samples WHERE md5 = ?', (sha,))
        if c.fetchone():
            conn.close()
            return False
        c.execute('INSERT INTO samples (md5, path, label, features_json, analysis_json, added_at) VALUES (?, ?, ?, ?, ?, ?)',
                  (sha, path, label, json.dumps(features), json.dumps(analysis), time.time()))
        conn.commit()
        conn.close()
        return True

    def list_samples(self) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT md5, path, label, features_json, analysis_json, added_at FROM samples')
        rows = c.fetchall()
        conn.close()
        res = []
        for r in rows:
            res.append({
                'md5': r[0],
                'path': r[1],
                'label': r[2],
                'features': json.loads(r[3]),
                'analysis': json.loads(r[4]),
                'added_at': r[5]
            })
        return res

    def export_signatures(self, out_path: str, top_n: int = 200):
        # Simple heuristic export: aggregate top mnemonics per label
        samples = self.list_samples()
        by_label = {}
        for s in samples:
            label = s['label']
            by_label.setdefault(label, []).append(s)
        export = {}
        for label, items in by_label.items():
            agg = {}
            for it in items:
                feats = it['features']
                for k, v in feats.items():
                    if k.startswith('mnem_'):
                        agg[k] = agg.get(k, 0) + v
            top = sorted(agg.items(), key=lambda x: x[1], reverse=True)[:top_n]
            export[label] = top
        with open(out_path, 'w') as f:
            json.dump(export, f, indent=2)
        return out_path

    def to_dataframe(self) -> pd.DataFrame:
        samples = self.list_samples()
        rows = []
        for s in samples:
            row = s['features'].copy()
            row['label'] = s['label']
            row['md5'] = s['md5']
            row['path'] = s['path']
            rows.append(row)
        if not rows:
            return pd.DataFrame()
        df = pd.DataFrame(rows)
        return df

# ---------------------- ML Model wrapper ----------------------

class PackedDetectorModel:
    def __init__(self, model: RandomForestClassifier = None):
        self.model = model or RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42)

    def train(self, X: pd.DataFrame, y: pd.Series, model_out: str = None, test_size: float = 0.2):
        if X.empty:
            raise ValueError('Empty training set')
        # align columns (fill missing)
        X = X.fillna(0)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=y)
        self.model.fit(X_train, y_train)
        preds = self.model.predict(X_test)
        probs = self.model.predict_proba(X_test)[:, 1] if hasattr(self.model, 'predict_proba') else None
        report = classification_report(y_test, preds, output_dict=False)
        roc = None
        if probs is not None:
            try:
                roc = roc_auc_score(y_test, probs)
            except Exception:
                roc = None
        if model_out:
            joblib.dump(self.model, model_out)
        return {'report': report, 'roc_auc': roc}

    def predict(self, X: pd.DataFrame) -> Dict[str, Any]:
        X = X.fillna(0)
        probs = self.model.predict_proba(X)[:, 1] if hasattr(self.model, 'predict_proba') else None
        preds = self.model.predict(X)
        return {'preds': preds.tolist(), 'probs': probs.tolist() if probs is not None else None}

    def save(self, path: str):
        joblib.dump(self.model, path)

    @classmethod
    def load(cls, path: str):
        m = joblib.load(path)
        return cls(m)

# ---------------------- CLI ----------------------

def cmd_add_sample(args):
    db = SignatureDB(args.db)
    fe = FeatureExtractor()
    analysis, features = fe.extract(args.path)
    added = db.add_sample(args.path, args.label, features, analysis)
    if added:
        print(f"Sample added: {args.path} (label={args.label})")
    else:
        print("Sample already exists (duplicate MD5). Skipped.")


def cmd_train(args):
    db = SignatureDB(args.db)
    df = db.to_dataframe()
    if df.empty:
        print('No samples in DB. Add some with add-sample.')
        return
    y = df['label']
    X = df.drop(columns=[c for c in ['label', 'md5', 'path'] if c in df.columns])
    model = PackedDetectorModel()
    res = model.train(X, y, model_out=args.model_out)
    print('Training complete')
    print(res['report'])
    if res['roc_auc']:
        print('ROC AUC:', res['roc_auc'])


def cmd_predict(args):
    model = PackedDetectorModel.load(args.model)
    fe = FeatureExtractor()
    _, features = fe.extract(args.path)
    df = pd.DataFrame([features]).fillna(0)
    res = model.predict(df)
    print('Prediction:', res['preds'][0])
    if res['probs']:
        print('Probability:', res['probs'][0])


def cmd_export(args):
    db = SignatureDB(args.db)
    out = db.export_signatures(args.out, top_n=args.top_n)
    print('Exported signatures to', out)


def cmd_list(args):
    db = SignatureDB(args.db)
    df = db.to_dataframe()
    if df.empty:
        print('No samples')
    else:
        print(df[['path', 'md5', 'label']].to_string(index=False))


def build_cli():
    p = argparse.ArgumentParser(description='Antivirus SDK CLI')
    sp = p.add_subparsers()

    p_add = sp.add_parser('add-sample', help='Add a labeled PE sample to DB')
    p_add.add_argument('--db', default='signatures.db')
    p_add.add_argument('--path', required=True)
    p_add.add_argument('--label', type=int, choices=[0,1], required=True, help='1=malicious-packed, 0=benign/nonpacked')
    p_add.set_defaults(func=cmd_add_sample)

    p_train = sp.add_parser('train', help='Train packed-vs-nonpacked model from DB')
    p_train.add_argument('--db', default='signatures.db')
    p_train.add_argument('--model-out', default='packed_detector.joblib')
    p_train.set_defaults(func=cmd_train)

    p_pred = sp.add_parser('predict', help='Predict a PE sample with a trained model')
    p_pred.add_argument('--model', required=True)
    p_pred.add_argument('--path', required=True)
    p_pred.set_defaults(func=cmd_predict)

    p_export = sp.add_parser('export-signatures', help='Export simple signature aggregations')
    p_export.add_argument('--db', default='signatures.db')
    p_export.add_argument('--out', required=True)
    p_export.add_argument('--top-n', type=int, default=200)
    p_export.set_defaults(func=cmd_export)

    p_list = sp.add_parser('list', help='List samples in DB')
    p_list.add_argument('--db', default='signatures.db')
    p_list.set_defaults(func=cmd_list)

    return p


def main():
    p = build_cli()
    args = p.parse_args()
    if not hasattr(args, 'func'):
        p.print_help()
        return
    args.func(args)

if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""
Antivirus SDK (CLI) - Capstone-based disassembly + signature DB + ML model

Single-file SDK providing:
 - PE disassembly using Capstone
 - Feature extraction (instruction counts, entropy, section stats, imports)
 - Signature DB (sqlite) to avoid duplicates by file hash
 - Training/prediction wrapper around scikit-learn RandomForest
 - CLI for dataset ingestion, training, prediction, and exporting signatures

Usage examples (after installing deps):
  pip install capstone pefile scikit-learn joblib numpy pandas tqdm

  # Add labeled samples to DB (label: 1=malicious-packed, 0=benign-or-nonpacked)
  python antivirus_sdk_cli.py add-sample --path samples/sample1.exe --label 1

  # Train a model from DB
  python antivirus_sdk_cli.py train --model-out packed_detector.joblib

  # Predict single PE
  python antivirus_sdk_cli.py predict --path sample.exe --model packed_detector.joblib

  # Export signatures (simple: top N frequently-occurring instruction sequences)
  python antivirus_sdk_cli.py export-signatures --out signatures.json

Notes:
 - This is a research SDK: model quality depends on labeled dataset and features.
 - Use responsibly. Do NOT use models for automated takedown decisions without human review.
"""

import argparse
import json
import os
import sqlite3
import hashlib
import time
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Tuple

import pefile
import capstone
import numpy as np
import pandas as pd
from tqdm import tqdm

# ML
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score
import joblib

# ---------------------- Utilities ----------------------

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

# ---------------------- Disassembler & Feature Extractor ----------------------

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
        pe = pefile.PE(path, fast_load=True)
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

# ---------------------- Signature DB ----------------------

class SignatureDB:
    def __init__(self, db_path: str = 'signatures.db'):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS samples (
                md5 TEXT PRIMARY KEY,
                path TEXT,
                label INTEGER,
                features_json TEXT,
                analysis_json TEXT,
                added_at REAL
            )
        ''')
        conn.commit()
        conn.close()

    def add_sample(self, path: str, label: int, features: Dict[str, float], analysis: Dict[str, Any]) -> bool:
        sha = md5_file(path)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT md5 FROM samples WHERE md5 = ?', (sha,))
        if c.fetchone():
            conn.close()
            return False
        c.execute('INSERT INTO samples (md5, path, label, features_json, analysis_json, added_at) VALUES (?, ?, ?, ?, ?, ?)',
                  (sha, path, label, json.dumps(features), json.dumps(analysis), time.time()))
        conn.commit()
        conn.close()
        return True

    def list_samples(self) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT md5, path, label, features_json, analysis_json, added_at FROM samples')
        rows = c.fetchall()
        conn.close()
        res = []
        for r in rows:
            res.append({
                'md5': r[0],
                'path': r[1],
                'label': r[2],
                'features': json.loads(r[3]),
                'analysis': json.loads(r[4]),
                'added_at': r[5]
            })
        return res

    def export_signatures(self, out_path: str, top_n: int = 200):
        # Simple heuristic export: aggregate top mnemonics per label
        samples = self.list_samples()
        by_label = {}
        for s in samples:
            label = s['label']
            by_label.setdefault(label, []).append(s)
        export = {}
        for label, items in by_label.items():
            agg = {}
            for it in items:
                feats = it['features']
                for k, v in feats.items():
                    if k.startswith('mnem_'):
                        agg[k] = agg.get(k, 0) + v
            top = sorted(agg.items(), key=lambda x: x[1], reverse=True)[:top_n]
            export[label] = top
        with open(out_path, 'w') as f:
            json.dump(export, f, indent=2)
        return out_path

    def to_dataframe(self) -> pd.DataFrame:
        samples = self.list_samples()
        rows = []
        for s in samples:
            row = s['features'].copy()
            row['label'] = s['label']
            row['md5'] = s['md5']
            row['path'] = s['path']
            rows.append(row)
        if not rows:
            return pd.DataFrame()
        df = pd.DataFrame(rows)
        return df

# ---------------------- ML Model wrapper ----------------------

class PackedDetectorModel:
    def __init__(self, model: RandomForestClassifier = None):
        self.model = model or RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42)

    def train(self, X: pd.DataFrame, y: pd.Series, model_out: str = None, test_size: float = 0.2):
        if X.empty:
            raise ValueError('Empty training set')
        # align columns (fill missing)
        X = X.fillna(0)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=y)
        self.model.fit(X_train, y_train)
        preds = self.model.predict(X_test)
        probs = self.model.predict_proba(X_test)[:, 1] if hasattr(self.model, 'predict_proba') else None
        report = classification_report(y_test, preds, output_dict=False)
        roc = None
        if probs is not None:
            try:
                roc = roc_auc_score(y_test, probs)
            except Exception:
                roc = None
        if model_out:
            joblib.dump(self.model, model_out)
        return {'report': report, 'roc_auc': roc}

    def predict(self, X: pd.DataFrame) -> Dict[str, Any]:
        X = X.fillna(0)
        probs = self.model.predict_proba(X)[:, 1] if hasattr(self.model, 'predict_proba') else None
        preds = self.model.predict(X)
        return {'preds': preds.tolist(), 'probs': probs.tolist() if probs is not None else None}

    def save(self, path: str):
        joblib.dump(self.model, path)

    @classmethod
    def load(cls, path: str):
        m = joblib.load(path)
        return cls(m)

# ---------------------- CLI ----------------------

def cmd_add_sample(args):
    db = SignatureDB(args.db)
    fe = FeatureExtractor()
    analysis, features = fe.extract(args.path)
    added = db.add_sample(args.path, args.label, features, analysis)
    if added:
        print(f"Sample added: {args.path} (label={args.label})")
    else:
        print("Sample already exists (duplicate MD5). Skipped.")


def cmd_train(args):
    db = SignatureDB(args.db)
    df = db.to_dataframe()
    if df.empty:
        print('No samples in DB. Add some with add-sample.')
        return
    y = df['label']
    X = df.drop(columns=[c for c in ['label', 'md5', 'path'] if c in df.columns])
    model = PackedDetectorModel()
    res = model.train(X, y, model_out=args.model_out)
    print('Training complete')
    print(res['report'])
    if res['roc_auc']:
        print('ROC AUC:', res['roc_auc'])


def cmd_predict(args):
    model = PackedDetectorModel.load(args.model)
    fe = FeatureExtractor()
    _, features = fe.extract(args.path)
    df = pd.DataFrame([features]).fillna(0)
    res = model.predict(df)
    print('Prediction:', res['preds'][0])
    if res['probs']:
        print('Probability:', res['probs'][0])


def cmd_export(args):
    db = SignatureDB(args.db)
    out = db.export_signatures(args.out, top_n=args.top_n)
    print('Exported signatures to', out)


def cmd_list(args):
    db = SignatureDB(args.db)
    df = db.to_dataframe()
    if df.empty:
        print('No samples')
    else:
        print(df[['path', 'md5', 'label']].to_string(index=False))


def build_cli():
    p = argparse.ArgumentParser(description='Antivirus SDK CLI')
    sp = p.add_subparsers()

    p_add = sp.add_parser('add-sample', help='Add a labeled PE sample to DB')
    p_add.add_argument('--db', default='signatures.db')
    p_add.add_argument('--path', required=True)
    p_add.add_argument('--label', type=int, choices=[0,1], required=True, help='1=malicious-packed, 0=benign/nonpacked')
    p_add.set_defaults(func=cmd_add_sample)

    p_train = sp.add_parser('train', help='Train packed-vs-nonpacked model from DB')
    p_train.add_argument('--db', default='signatures.db')
    p_train.add_argument('--model-out', default='packed_detector.joblib')
    p_train.set_defaults(func=cmd_train)

    p_pred = sp.add_parser('predict', help='Predict a PE sample with a trained model')
    p_pred.add_argument('--model', required=True)
    p_pred.add_argument('--path', required=True)
    p_pred.set_defaults(func=cmd_predict)

    p_export = sp.add_parser('export-signatures', help='Export simple signature aggregations')
    p_export.add_argument('--db', default='signatures.db')
    p_export.add_argument('--out', required=True)
    p_export.add_argument('--top-n', type=int, default=200)
    p_export.set_defaults(func=cmd_export)

    p_list = sp.add_parser('list', help='List samples in DB')
    p_list.add_argument('--db', default='signatures.db')
    p_list.set_defaults(func=cmd_list)

    return p


def main():
    p = build_cli()
    args = p.parse_args()
    if not hasattr(args, 'func'):
        p.print_help()
        return
    args.func(args)

if __name__ == '__main__':
    main()
